from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict, ValidationError

from polaris.domain import AuthorizationOperation, Identifier, SafeText

# Capabilities that must not exist in the v1 runtime at all (REQ-AI-006). This is enforced at
# registry construction rather than documented, so adding one is a test failure, not a review miss.
PROHIBITED_TOOL_TOKENS: frozenset[str] = frozenset(
    {
        "shell",
        "bash",
        "exec",
        "eval",
        "python",
        "code",
        "browser",
        "fetch",
        "http",
        "url",
        "file",
        "filesystem",
        "read_file",
        "write_file",
        "sql",
        "query",
        "database",
        "db",
        "email",
        "smtp",
        "send",
        "network",
        "socket",
        "memory",
        "remember",
    }
)


class ToolKind(StrEnum):
    READ = "READ"
    WRITE = "WRITE"


class PolicySearchArguments(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    question: SafeText


class PatientSummaryArguments(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    patient_id: Identifier


class ProposeFollowUpArguments(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    patient_id: Identifier
    facility_id: Identifier
    due_date: date
    summary: SafeText


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """One statically approved capability with a narrow schema and its own authorization."""

    name: str
    version: str
    kind: ToolKind
    description: str
    arguments: type[BaseModel]
    operation: AuthorizationOperation


class ToolRegistryError(ValueError):
    pass


class UnknownToolError(ToolRegistryError):
    pass


class ToolArgumentError(ToolRegistryError):
    pass


_DEFINITIONS: tuple[ToolDefinition, ...] = (
    ToolDefinition(
        name="policy.search",
        version="1",
        kind=ToolKind.READ,
        description="Search approved policy sources the caller is authorized to see.",
        arguments=PolicySearchArguments,
        operation=AuthorizationOperation.POLICY_QUERY,
    ),
    ToolDefinition(
        name="patient.summary",
        version="1",
        kind=ToolKind.READ,
        description="Read the minimum authorized administrative summary for one patient.",
        arguments=PatientSummaryArguments,
        operation=AuthorizationOperation.PATIENT_READ,
    ),
    ToolDefinition(
        name="action.propose",
        version="1",
        kind=ToolKind.WRITE,
        description=(
            "Propose one non-clinical administrative follow-up task for independent human approval."
        ),
        arguments=ProposeFollowUpArguments,
        operation=AuthorizationOperation.ACTION_PROPOSE,
    ),
)


class ToolRegistry:
    """The complete, static tool inventory.

    There is no registration API. Tools are a release-time decision reviewed with the rest of the
    code, not something an operator, a prompt, or a model can extend at runtime — which is why
    `available()` returns names only and every invocation is authorized independently.
    """

    def __init__(self, definitions: tuple[ToolDefinition, ...] = _DEFINITIONS) -> None:
        seen: set[str] = set()
        for definition in definitions:
            if definition.name in seen:
                raise ToolRegistryError("Tool names must be unique")
            seen.add(definition.name)
            tokens = set(definition.name.replace(".", "_").split("_"))
            if tokens & PROHIBITED_TOOL_TOKENS:
                raise ToolRegistryError(
                    f"Tool '{definition.name}' names a capability prohibited in v1"
                )
        self._definitions: Mapping[str, ToolDefinition] = MappingProxyType(
            {definition.name: definition for definition in definitions}
        )

    def available(self, *, include_write: bool) -> tuple[str, ...]:
        return tuple(
            sorted(
                name
                for name, definition in self._definitions.items()
                if include_write or definition.kind is ToolKind.READ
            )
        )

    def definitions(self) -> tuple[ToolDefinition, ...]:
        return tuple(self._definitions[name] for name in sorted(self._definitions))

    def resolve(self, name: object) -> ToolDefinition:
        if not isinstance(name, str) or name not in self._definitions:
            raise UnknownToolError("Requested tool is not in the approved registry")
        return self._definitions[name]

    def parse_arguments(self, definition: ToolDefinition, arguments: object) -> BaseModel:
        """Coerce model-supplied arguments through the tool's schema, rejecting anything extra."""

        if not isinstance(arguments, Mapping):
            raise ToolArgumentError("Tool arguments must be an object")
        try:
            return definition.arguments.model_validate(dict(arguments))
        except ValidationError as exc:
            raise ToolArgumentError("Tool arguments failed schema validation") from exc
