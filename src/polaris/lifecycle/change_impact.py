from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ChangeKind(StrEnum):
    """The change categories `REQ-GOV-003` says must trigger review."""

    MODEL = "MODEL"
    PROMPT = "PROMPT"
    CORPUS = "CORPUS"
    TOOL = "TOOL"
    AUTONOMY = "AUTONOMY"
    DEPENDENCY = "DEPENDENCY"
    EVALUATION = "EVALUATION"


class ImpactLevel(StrEnum):
    MATERIAL = "MATERIAL"
    NOTABLE = "NOTABLE"
    NONE = "NONE"


@dataclass(frozen=True, slots=True)
class Change:
    kind: ChangeKind
    impact: ImpactLevel
    summary: str
    required_actions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ChangeImpactReport:
    baseline_lock: str
    candidate_lock: str
    changes: tuple[Change, ...]

    @property
    def material(self) -> tuple[Change, ...]:
        return tuple(change for change in self.changes if change.impact is ImpactLevel.MATERIAL)

    @property
    def requires_review(self) -> bool:
        return any(change.impact is not ImpactLevel.NONE for change in self.changes)

    @property
    def required_actions(self) -> tuple[str, ...]:
        actions: list[str] = []
        for change in self.changes:
            for action in change.required_actions:
                if action not in actions:
                    actions.append(action)
        return tuple(actions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_lock": self.baseline_lock,
            "candidate_lock": self.candidate_lock,
            "requires_review": self.requires_review,
            "material_changes": len(self.material),
            "changes": [
                {
                    "kind": change.kind.value,
                    "impact": change.impact.value,
                    "summary": change.summary,
                    "required_actions": list(change.required_actions),
                }
                for change in self.changes
            ],
            "required_actions": list(self.required_actions),
        }


_RERUN_EVALUATION = "Re-run the retrieval evaluation and record the result"
_RERUN_CAMPAIGN = "Re-run the adversarial campaign and record the result"
_REVIEW_VENDOR = "Complete provider due diligence and data-flow review (REQ-AI-002, BLK-004)"
_REVIEW_SAFETY = "Obtain clinical-safety review of the changed behavior"
_REGENERATE_BOM = "Regenerate and review the SBOM and AIBOM"
_REVIEW_HUMAN_FACTORS = "Repeat the affected human-factors tasks (NS-ASR-005)"


def analyze_change(baseline: dict[str, Any], candidate: dict[str, Any]) -> ChangeImpactReport:
    """Decide what a change to the AI bill of materials obliges before release.

    The AIBOM is the right input because it already describes the things that change behavior — the
    model, the system contract, the serving corpus, the tool surface, and the bounds. Diffing it
    means a change cannot be reviewed as "just a config tweak" when it alters what the system does.
    """

    changes: list[Change] = []
    changes.extend(_model_changes(baseline, candidate))
    changes.extend(_corpus_changes(baseline, candidate))
    changes.extend(_tool_changes(baseline, candidate))
    changes.extend(_autonomy_changes(baseline, candidate))
    changes.extend(_evaluation_changes(baseline, candidate))
    changes.extend(_dependency_changes(baseline, candidate))
    return ChangeImpactReport(
        baseline_lock=str(baseline.get("application", {}).get("lock_sha256", "")),
        candidate_lock=str(candidate.get("application", {}).get("lock_sha256", "")),
        changes=tuple(changes),
    )


def _model_changes(baseline: dict[str, Any], candidate: dict[str, Any]) -> list[Change]:
    before = baseline.get("models", [{}])[0]
    after = candidate.get("models", [{}])[0]
    changes: list[Change] = []
    if before.get("model_id") != after.get("model_id"):
        changes.append(
            Change(
                kind=ChangeKind.MODEL,
                impact=ImpactLevel.MATERIAL,
                summary=f"model changed from {before.get('model_id')} to {after.get('model_id')}",
                required_actions=(_RERUN_CAMPAIGN, _RERUN_EVALUATION, _REVIEW_SAFETY),
            )
        )
    if not before.get("hosted") and after.get("hosted"):
        changes.append(
            Change(
                kind=ChangeKind.MODEL,
                impact=ImpactLevel.MATERIAL,
                summary="a hosted provider was introduced",
                required_actions=(_REVIEW_VENDOR, _RERUN_CAMPAIGN, _REVIEW_SAFETY),
            )
        )
    if before.get("system_contract_sha256") != after.get("system_contract_sha256"):
        changes.append(
            Change(
                kind=ChangeKind.PROMPT,
                impact=ImpactLevel.MATERIAL,
                summary="the system contract changed",
                required_actions=(_RERUN_CAMPAIGN, _RERUN_EVALUATION),
            )
        )
    return changes


def _corpus_changes(baseline: dict[str, Any], candidate: dict[str, Any]) -> list[Change]:
    before = baseline.get("corpora", [{}])[0]
    after = candidate.get("corpora", [{}])[0]
    changes: list[Change] = []
    if before.get("manifest_sha256") != after.get("manifest_sha256"):
        admitted_before = set(before.get("admitted_documents", []))
        admitted_after = set(after.get("admitted_documents", []))
        added = sorted(admitted_after - admitted_before)
        removed = sorted(admitted_before - admitted_after)
        detail = f"added={added} removed={removed}" if added or removed else "content or labels"
        changes.append(
            Change(
                kind=ChangeKind.CORPUS,
                impact=ImpactLevel.MATERIAL,
                summary=f"serving corpus manifest changed ({detail})",
                required_actions=(_RERUN_EVALUATION, _REGENERATE_BOM),
            )
        )
    before_confidential = set(before.get("confidential_partition", []))
    after_confidential = set(after.get("confidential_partition", []))
    if before_confidential != after_confidential:
        changes.append(
            Change(
                kind=ChangeKind.CORPUS,
                impact=ImpactLevel.MATERIAL,
                summary="the confidential partition changed",
                required_actions=(_RERUN_EVALUATION, _RERUN_CAMPAIGN),
            )
        )
    return changes


def _tool_changes(baseline: dict[str, Any], candidate: dict[str, Any]) -> list[Change]:
    before = {tool["name"]: tool for tool in baseline.get("tools", [])}
    after = {tool["name"]: tool for tool in candidate.get("tools", [])}
    changes: list[Change] = []
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    if added:
        write_added = [name for name in added if after[name].get("kind") == "WRITE"]
        changes.append(
            Change(
                kind=ChangeKind.TOOL,
                impact=ImpactLevel.MATERIAL,
                summary=f"tools added: {added}",
                required_actions=(
                    (_RERUN_CAMPAIGN, _REVIEW_SAFETY, _REVIEW_HUMAN_FACTORS)
                    if write_added
                    else (_RERUN_CAMPAIGN,)
                ),
            )
        )
    if removed:
        changes.append(
            Change(
                kind=ChangeKind.TOOL,
                impact=ImpactLevel.NOTABLE,
                summary=f"tools removed: {removed}",
                required_actions=(_RERUN_CAMPAIGN,),
            )
        )
    for name in sorted(set(before) & set(after)):
        if before[name].get("arguments_schema_sha256") != after[name].get(
            "arguments_schema_sha256"
        ):
            changes.append(
                Change(
                    kind=ChangeKind.TOOL,
                    impact=ImpactLevel.MATERIAL,
                    summary=f"argument schema changed for {name}",
                    required_actions=(_RERUN_CAMPAIGN,),
                )
            )
    return changes


def _autonomy_changes(baseline: dict[str, Any], candidate: dict[str, Any]) -> list[Change]:
    before = baseline.get("bounds", {})
    after = candidate.get("bounds", {})
    changes: list[Change] = []
    if not before.get("cross_session_memory") and after.get("cross_session_memory"):
        changes.append(
            Change(
                kind=ChangeKind.AUTONOMY,
                impact=ImpactLevel.MATERIAL,
                summary="cross-session memory was enabled",
                required_actions=(_RERUN_CAMPAIGN, _REVIEW_SAFETY, _REVIEW_HUMAN_FACTORS),
            )
        )
    for bound in ("max_steps", "max_tool_calls", "max_write_proposals", "max_answer_characters"):
        previous, current = before.get(bound), after.get(bound)
        if isinstance(previous, int) and isinstance(current, int) and current > previous:
            changes.append(
                Change(
                    kind=ChangeKind.AUTONOMY,
                    impact=ImpactLevel.MATERIAL,
                    summary=f"{bound} was raised from {previous} to {current}",
                    required_actions=(_RERUN_CAMPAIGN,),
                )
            )
    before_switches = set(baseline.get("kill_switches", []))
    after_switches = set(candidate.get("kill_switches", []))
    if removed_switches := sorted(before_switches - after_switches):
        changes.append(
            Change(
                kind=ChangeKind.AUTONOMY,
                impact=ImpactLevel.MATERIAL,
                summary=f"kill switches removed: {removed_switches}",
                required_actions=(_RERUN_CAMPAIGN, _REVIEW_SAFETY),
            )
        )
    return changes


def _evaluation_changes(baseline: dict[str, Any], candidate: dict[str, Any]) -> list[Change]:
    before = baseline.get("evaluations", [{}])[0]
    after = candidate.get("evaluations", [{}])[0]
    changes: list[Change] = []
    for threshold in ("security_threshold", "quality_threshold"):
        previous, current = before.get(threshold), after.get(threshold)
        lowered = (
            isinstance(previous, (int, float))
            and isinstance(current, (int, float))
            and current < previous
        )
        if lowered:
            # Lowering a threshold is how a failing evaluation gets made to pass.
            changes.append(
                Change(
                    kind=ChangeKind.EVALUATION,
                    impact=ImpactLevel.MATERIAL,
                    summary=f"{threshold} was lowered from {previous} to {current}",
                    required_actions=(
                        "Justify the lowered threshold in a residual-risk decision",
                        _RERUN_EVALUATION,
                    ),
                )
            )
    if before.get("case_count", 0) > after.get("case_count", 0):
        changes.append(
            Change(
                kind=ChangeKind.EVALUATION,
                impact=ImpactLevel.MATERIAL,
                summary="evaluation cases were removed",
                required_actions=("Justify removed cases in a residual-risk decision",),
            )
        )
    return changes


def _dependency_changes(baseline: dict[str, Any], candidate: dict[str, Any]) -> list[Change]:
    before = baseline.get("application", {}).get("lock_sha256")
    after = candidate.get("application", {}).get("lock_sha256")
    if before == after:
        return []
    return [
        Change(
            kind=ChangeKind.DEPENDENCY,
            impact=ImpactLevel.NOTABLE,
            summary="the dependency lockfile changed",
            required_actions=(_REGENERATE_BOM,),
        )
    ]
