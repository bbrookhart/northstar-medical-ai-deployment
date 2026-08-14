from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Protocol, cast
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from polaris.domain import ConsentDecision
from polaris.errors import NotFoundError
from polaris.services.patients import (
    FhirGatewayUnavailable,
    PatientSecurityContext,
    patient_security_context,
)

_FHIR_JSON = "application/fhir+json"
_MAX_RESPONSE_BYTES = 1_048_576
_LOCAL_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class FhirHttpTransportError(RuntimeError):
    """A deliberately detail-free transport failure at the lab FHIR boundary."""


class FhirHttpNotFoundError(FhirHttpTransportError):
    pass


class FhirHttpTransport(Protocol):
    def get_json(
        self,
        resource_path: str,
        query: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]: ...


class UrllibFhirHttpTransport:
    """Small bounded FHIR client for the local interoperability lab.

    This adapter intentionally has no production token plumbing. A production connector must
    add a workload identity and downstream authorization without accepting caller-supplied URLs.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 3.0,
        allow_insecure_localhost: bool = False,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> None:
        self._base_url = validated_fhir_base_url(
            base_url,
            allow_insecure_localhost=allow_insecure_localhost,
        )
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValueError("FHIR timeout must be greater than zero and no more than 30 seconds")
        if max_response_bytes < 1 or max_response_bytes > _MAX_RESPONSE_BYTES:
            raise ValueError("FHIR response limit must be between 1 byte and 1 MiB")
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes

    def get_json(
        self,
        resource_path: str,
        query: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        if not resource_path or resource_path.startswith(("/", "\\")) or ".." in resource_path:
            raise ValueError("FHIR resource path is invalid")
        url = f"{self._base_url}/{resource_path}"
        if query:
            url = f"{url}?{urlencode(query)}"
        request = Request(  # noqa: S310 - base URL schemes are validated at construction.
            url,
            headers={"Accept": _FHIR_JSON, "User-Agent": "northstar-polaris-lab/0.1"},
            method="GET",
        )
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:  # noqa: S310
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > self._max_response_bytes:
                    raise FhirHttpTransportError("FHIR response exceeded the configured limit")
                raw = response.read(self._max_response_bytes + 1)
        except HTTPError as exc:
            if exc.code == 404:
                raise FhirHttpNotFoundError from exc
            raise FhirHttpTransportError from exc
        except (OSError, TimeoutError, ValueError) as exc:
            raise FhirHttpTransportError from exc
        if len(raw) > self._max_response_bytes:
            raise FhirHttpTransportError("FHIR response exceeded the configured limit")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FhirHttpTransportError from exc
        if not isinstance(payload, dict):
            raise FhirHttpTransportError("FHIR response was not a JSON object")
        return cast(Mapping[str, Any], payload)


class HttpFhirPatientGateway:
    """FHIR R4 Patient/Consent adapter that preserves the pre-authorization read boundary."""

    def __init__(self, transport: FhirHttpTransport) -> None:
        self._transport = transport

    def security_context(self, patient_id: str) -> PatientSecurityContext:
        safe_id = _fhir_id(patient_id)
        patient = self._get(
            f"Patient/{quote(safe_id, safe='')}",
            {"_elements": "id,meta,managingOrganization"},
            patient_not_found=True,
        )
        consent_bundle = self._get(
            "Consent",
            {
                "patient": f"Patient/{safe_id}",
                "status": "active",
                "_count": "2",
            },
        )
        return patient_security_context(
            patient,
            expected_id=safe_id,
            consent_decision=_consent_decision(consent_bundle, patient_id=safe_id),
        )

    def read_patient(self, patient_id: str) -> Mapping[str, Any]:
        safe_id = _fhir_id(patient_id)
        return self._get(
            f"Patient/{quote(safe_id, safe='')}",
            patient_not_found=True,
        )

    def _get(
        self,
        resource_path: str,
        query: Mapping[str, str] | None = None,
        *,
        patient_not_found: bool = False,
    ) -> Mapping[str, Any]:
        try:
            return self._transport.get_json(resource_path, query)
        except FhirHttpNotFoundError as exc:
            if patient_not_found:
                raise NotFoundError("PATIENT_NOT_AVAILABLE") from exc
            raise FhirGatewayUnavailable from exc
        except FhirHttpTransportError as exc:
            raise FhirGatewayUnavailable from exc


def validated_fhir_base_url(base_url: str, *, allow_insecure_localhost: bool) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("FHIR base URL is invalid")
    if parsed.scheme != "https" and not (
        allow_insecure_localhost and parsed.hostname.lower() in _LOCAL_HOSTS
    ):
        raise ValueError("FHIR base URL must use HTTPS except for an explicitly enabled localhost")
    normalized_path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, normalized_path, "", ""))


def _fhir_id(patient_id: str) -> str:
    if not patient_id or len(patient_id) > 64:
        raise ValueError("FHIR patient ID is invalid")
    if any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-."
        for character in patient_id
    ):
        raise ValueError("FHIR patient ID is invalid")
    return patient_id


def _consent_decision(bundle: Mapping[str, Any], *, patient_id: str) -> ConsentDecision:
    if bundle.get("resourceType") != "Bundle":
        raise ValueError("FHIR Consent search did not return a Bundle")
    entries = bundle.get("entry", [])
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise ValueError("FHIR Consent Bundle entries are invalid")
    decisions: list[ConsentDecision] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValueError("FHIR Consent Bundle entry is invalid")
        resource = entry.get("resource")
        if not isinstance(resource, Mapping) or resource.get("resourceType") != "Consent":
            raise ValueError("FHIR Consent Bundle contains a non-Consent resource")
        patient = resource.get("patient")
        provision = resource.get("provision")
        if (
            resource.get("status") != "active"
            or not isinstance(patient, Mapping)
            or patient.get("reference") != f"Patient/{patient_id}"
            or not isinstance(provision, Mapping)
        ):
            raise ValueError("FHIR Consent security context is invalid")
        provision_type = provision.get("type")
        if provision_type == "permit":
            decisions.append(ConsentDecision.PERMIT)
        elif provision_type == "deny":
            decisions.append(ConsentDecision.DENY)
        else:
            raise ValueError("FHIR Consent provision decision is invalid")
    if not decisions:
        return ConsentDecision.UNKNOWN
    if len(decisions) != 1:
        raise ValueError("FHIR Consent security context is ambiguous")
    return decisions[0]
