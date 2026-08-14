from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from polaris.agent.budget import AgentBudget
from polaris.agent.model import SYSTEM_CONTRACT, DeterministicModelAdapter
from polaris.agent.tools import PROHIBITED_TOOL_TOKENS, ToolRegistry
from polaris.domain import AgentCapability
from polaris.services.corpus import CorpusIngestionService, seed_corpus_sources
from polaris.services.retrieval_eval import (
    EVALUATION_CORPUS_ID,
    EVALUATION_CORPUS_VERSION,
    QUALITY_PASS_RATE,
    SECURITY_PASS_RATE,
    golden_cases,
)
from polaris.services.secure_retrieval import SecureRetrievalIndex

AIBOM_VERSION = "1.0"


def build_aibom(root: Path, *, corpus_id: str, corpus_version: str) -> dict[str, Any]:
    """Describe the AI-specific components a dependency SBOM cannot express.

    A CycloneDX component list says which libraries are installed. It does not say which model
    answers, which corpus version it may draw on, which tools it can reach, what bounds constrain
    it, or which evaluation thresholds gate it — and those are the things that change behavior. This
    document is generated from the running definitions rather than maintained by hand, so it cannot
    drift from what the code actually permits.
    """

    ingestion = CorpusIngestionService()
    manifest, chunks, promotions = ingestion.build(
        seed_corpus_sources(),
        corpus_id=corpus_id,
        version=corpus_version,
    )
    index = SecureRetrievalIndex(manifest, chunks)
    registry = ToolRegistry()
    budget = AgentBudget()
    adapter = DeterministicModelAdapter()

    return {
        "aibomVersion": AIBOM_VERSION,
        "application": {
            "name": "northstar-polaris",
            "revision_source": "uv.lock",
            "lock_sha256": hashlib.sha256((root / "uv.lock").read_bytes()).hexdigest(),
        },
        "models": [
            {
                "component": "orchestration model adapter",
                "model_id": adapter.model_id,
                "kind": "deterministic",
                "hosted": False,
                "training_data": "none — this is a fixed policy over supplied context, not a model",
                "system_contract_sha256": hashlib.sha256(SYSTEM_CONTRACT.encode()).hexdigest(),
                "provider_approved": False,
                "notes": (
                    "No hosted provider is connected. The hosted adapter refuses every call until "
                    "REQ-AI-002 criteria and BLK-004 due diligence close."
                ),
            }
        ],
        "corpora": [
            {
                "corpus_id": manifest.corpus_id,
                "version": manifest.version,
                "manifest_sha256": manifest.manifest_checksum,
                "admitted_documents": list(manifest.document_ids),
                "chunk_count": manifest.chunk_count,
                "rejected_count": manifest.rejected_count,
                "rejections": [
                    {
                        "document_id": promotion.document_id,
                        "reasons": [reason.value for reason in promotion.reasons],
                    }
                    for promotion in promotions
                    if not promotion.admitted
                ],
                "confidential_partition": sorted(
                    {
                        chunk.document_id
                        for chunk in chunks
                        if chunk.classification == "CONFIDENTIAL"
                    }
                ),
            },
            {
                "corpus_id": EVALUATION_CORPUS_ID,
                "version": EVALUATION_CORPUS_VERSION,
                "purpose": "evaluation only; never serves user queries",
            },
        ],
        "tools": [
            {
                "name": definition.name,
                "version": definition.version,
                "kind": definition.kind.value,
                "operation": definition.operation.value,
                "arguments_schema_sha256": _schema_digest(definition.arguments),
            }
            for definition in registry.definitions()
        ],
        "prohibited_tool_tokens": sorted(PROHIBITED_TOOL_TOKENS),
        "bounds": {
            "max_steps": budget.max_steps,
            "max_tool_calls": budget.max_tool_calls,
            "max_write_proposals": budget.max_write_proposals,
            "max_context_characters": budget.max_context_characters,
            "max_answer_characters": budget.max_answer_characters,
            "deadline_seconds": budget.deadline_seconds,
            "cross_session_memory": False,
            "concurrency_control": None,
            "cost_control": None,
        },
        "kill_switches": [capability.value for capability in AgentCapability],
        "evaluations": [
            {
                "name": "retrieval golden set",
                "case_count": len(golden_cases()),
                "security_threshold": SECURITY_PASS_RATE,
                "quality_threshold": QUALITY_PASS_RATE,
                "report": "evidence/reports/M05-retrieval-evaluation.json",
                "index_version": index.version,
            }
        ],
        "not_included": [
            "hosted model provider, contract, or data-flow review (BLK-004, REQ-AI-002)",
            "embedding model or vector store — retrieval is deterministic keyword matching",
            "fine-tuning, training, or evaluation datasets containing real data",
            "red-team campaign results against a real provider (M09)",
        ],
    }


def _schema_digest(model: type) -> str:
    schema = json.dumps(model.model_json_schema(), sort_keys=True, separators=(",", ":"))  # type: ignore[attr-defined]
    return hashlib.sha256(schema.encode()).hexdigest()


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"
