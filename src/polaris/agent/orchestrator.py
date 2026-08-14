from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from types import MappingProxyType
from uuid import uuid4

from polaris.agent.budget import AgentBudget, BudgetExceeded, BudgetLedger
from polaris.agent.killswitch import AgentKillSwitch, CapabilityDisabled
from polaris.agent.model import (
    SYSTEM_CONTRACT,
    ModelAdapter,
    ModelIntent,
    ModelRequest,
    ModelUnavailable,
)
from polaris.agent.tools import (
    PatientSummaryArguments,
    PolicySearchArguments,
    ProposeFollowUpArguments,
    ToolArgumentError,
    ToolDefinition,
    ToolKind,
    ToolRegistry,
    UnknownToolError,
)
from polaris.agent.validators import validate_answer, validate_proposal_summary
from polaris.domain import (
    AgentCapability,
    AgentIntentKind,
    AgentRefusalReason,
    AgentRunResult,
    AgentRunState,
    AgentStep,
    Citation,
    FollowUpAction,
    Principal,
    PurposeOfUse,
    RetrievedChunk,
)
from polaris.errors import PolarisError
from polaris.services.actions import ActionService
from polaris.services.audit import AuditLedger, utc_now
from polaris.services.patients import PatientService
from polaris.services.secure_retrieval import CorpusRegistry, render_data_only_context

# The only legal transitions. Anything else is a programming error, not a runtime branch.
_TRANSITIONS: MappingProxyType[AgentRunState, frozenset[AgentRunState]] = MappingProxyType(
    {
        AgentRunState.RECEIVED: frozenset({AgentRunState.AUTHORIZED, AgentRunState.REFUSED}),
        AgentRunState.AUTHORIZED: frozenset({AgentRunState.RETRIEVING, AgentRunState.REFUSED}),
        AgentRunState.RETRIEVING: frozenset(
            {AgentRunState.MODEL_TURN, AgentRunState.REFUSED, AgentRunState.HALTED}
        ),
        AgentRunState.MODEL_TURN: frozenset(
            {
                AgentRunState.TOOL_CALL,
                AgentRunState.VALIDATING,
                AgentRunState.REFUSED,
                AgentRunState.HALTED,
                AgentRunState.FAILED,
            }
        ),
        AgentRunState.TOOL_CALL: frozenset(
            {
                AgentRunState.MODEL_TURN,
                AgentRunState.VALIDATING,
                AgentRunState.REFUSED,
                AgentRunState.HALTED,
                AgentRunState.FAILED,
            }
        ),
        AgentRunState.VALIDATING: frozenset(
            {AgentRunState.COMPLETED, AgentRunState.REFUSED, AgentRunState.HALTED}
        ),
        AgentRunState.COMPLETED: frozenset(),
        AgentRunState.REFUSED: frozenset(),
        AgentRunState.HALTED: frozenset(),
        AgentRunState.FAILED: frozenset(),
    }
)


class IllegalAgentTransition(RuntimeError):
    pass


class _RunContext:
    """Per-run scratch state. It is constructed inside `run` and discarded when `run` returns.

    Cross-session memory is disabled in v1 (`REQ-AI-004`), and the way to be sure is to have nowhere
    to put it: the orchestrator itself holds no mutable per-conversation attributes.
    """

    def __init__(self, run_id: str, state: AgentRunState = AgentRunState.RECEIVED) -> None:
        self.run_id = run_id
        self.state = state
        self.steps: list[AgentStep] = []
        self.retrieved: tuple[RetrievedChunk, ...] = ()
        self.citations: tuple[Citation, ...] = ()
        self.corpus_version = ""
        self.record(state, "run received")

    def record(self, state: AgentRunState, detail: str) -> None:
        self.steps.append(AgentStep(ordinal=len(self.steps), state=state, detail=detail))

    def transition(self, target: AgentRunState, detail: str) -> None:
        if target not in _TRANSITIONS[self.state]:
            raise IllegalAgentTransition(f"{self.state.value} -> {target.value}")
        self.state = target
        self.record(target, detail)


class AgentOrchestrator:
    """A bounded, explicitly staged loop around an untrusted model.

    The model chooses *what to ask for*. It never decides whether the request is allowed: every tool
    call re-derives authorization from the calling principal through the same services the HTTP API
    uses, and every answer is validated against the chunks the retriever actually returned. A model
    that is entirely compromised can therefore waste a run, but it cannot broaden retrieval, get a
    credential, bypass approval, execute anything, or exceed a bound.
    """

    def __init__(
        self,
        *,
        model: ModelAdapter,
        corpus: CorpusRegistry,
        patients: PatientService,
        actions: ActionService,
        audit: AuditLedger,
        kill_switch: AgentKillSwitch,
        registry: ToolRegistry | None = None,
        budget: AgentBudget | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._model = model
        self._corpus = corpus
        self._patients = patients
        self._actions = actions
        self._audit = audit
        self._kill_switch = kill_switch
        self._registry = registry or ToolRegistry()
        self._budget = budget or AgentBudget()
        self._clock = clock

    @property
    def model_id(self) -> str:
        return self._model.model_id

    def run(
        self,
        *,
        principal: Principal,
        purpose: PurposeOfUse,
        question: str,
        correlation_id: str,
    ) -> AgentRunResult:
        run_id = f"RUN-{uuid4().hex}"
        context = _RunContext(run_id)
        ledger = BudgetLedger(self._budget, clock=self._clock)

        try:
            return self._run(
                context,
                ledger,
                principal=principal,
                purpose=purpose,
                question=question,
                correlation_id=correlation_id,
            )
        except CapabilityDisabled as disabled:
            return self._refuse(
                context,
                AgentRefusalReason.CAPABILITY_DISABLED,
                principal=principal,
                correlation_id=correlation_id,
                detail=disabled.capability.value,
            )
        except BudgetExceeded as exceeded:
            return self._halt(
                context,
                principal=principal,
                correlation_id=correlation_id,
                detail=exceeded.bound,
                tool_calls=ledger.tool_calls,
            )
        except ModelUnavailable:
            return self._refuse(
                context,
                AgentRefusalReason.MODEL_UNAVAILABLE,
                principal=principal,
                correlation_id=correlation_id,
                detail="model adapter unavailable",
                state=AgentRunState.FAILED,
            )

    def _run(
        self,
        context: _RunContext,
        ledger: BudgetLedger,
        *,
        principal: Principal,
        purpose: PurposeOfUse,
        question: str,
        correlation_id: str,
    ) -> AgentRunResult:
        self._kill_switch.assert_enabled(AgentCapability.MODEL)
        context.transition(AgentRunState.AUTHORIZED, "model capability enabled")

        self._kill_switch.assert_enabled(AgentCapability.READ)
        context.transition(AgentRunState.RETRIEVING, "authorized retrieval")
        ledger.consume_step()
        retrieval = self._corpus.active_index().search(principal=principal, question=question)
        context.retrieved = retrieval.chunks
        context.corpus_version = retrieval.corpus_version
        rendered = render_data_only_context(retrieval.chunks)
        ledger.check_context(rendered)

        write_enabled = self._kill_switch.is_enabled(AgentCapability.WRITE)
        context.transition(
            AgentRunState.MODEL_TURN,
            f"{len(retrieval.chunks)} chunks from corpus {retrieval.corpus_version}",
        )

        while True:
            ledger.consume_step()
            intent = self._generate(
                question=question,
                context_text=rendered,
                write_enabled=write_enabled,
                remaining_steps=ledger.remaining_steps,
            )

            if intent.kind is AgentIntentKind.CALL_TOOL:
                outcome = self._handle_tool_call(
                    context,
                    ledger,
                    intent,
                    principal=principal,
                    purpose=purpose,
                    question=question,
                    correlation_id=correlation_id,
                )
                if outcome is not None:
                    return outcome
                continue

            context.transition(AgentRunState.VALIDATING, f"model intent {intent.kind.value}")
            if intent.kind is AgentIntentKind.ABSTAIN:
                return self._complete(
                    context,
                    principal=principal,
                    correlation_id=correlation_id,
                    answer=intent.answer,
                    citations=(),
                    tool_calls=ledger.tool_calls,
                )

            validation = validate_answer(
                intent,
                retrieved=context.retrieved,
                max_characters=self._budget.max_answer_characters,
            )
            if not validation.accepted and validation.reason is not None:
                return self._refuse(
                    context,
                    validation.reason,
                    principal=principal,
                    correlation_id=correlation_id,
                    detail=validation.detail,
                    tool_calls=ledger.tool_calls,
                )
            ledger.check_answer(intent.answer)
            return self._complete(
                context,
                principal=principal,
                correlation_id=correlation_id,
                answer=intent.answer,
                citations=_citations(context.retrieved, intent.cited_chunk_ids),
                tool_calls=ledger.tool_calls,
            )

    def _generate(
        self,
        *,
        question: str,
        context_text: str,
        write_enabled: bool,
        remaining_steps: int,
    ) -> ModelIntent:
        request = ModelRequest(
            system_contract=SYSTEM_CONTRACT,
            question=question,
            context=context_text,
            available_tools=self._registry.available(include_write=write_enabled),
            remaining_steps=remaining_steps,
        )
        return self._model.generate(request)

    def _handle_tool_call(
        self,
        context: _RunContext,
        ledger: BudgetLedger,
        intent: ModelIntent,
        *,
        principal: Principal,
        purpose: PurposeOfUse,
        question: str,
        correlation_id: str,
    ) -> AgentRunResult | None:
        try:
            definition = self._registry.resolve(intent.tool_name)
        except UnknownToolError:
            return self._refuse(
                context,
                AgentRefusalReason.UNKNOWN_TOOL,
                principal=principal,
                correlation_id=correlation_id,
                detail=str(intent.tool_name)[:64],
                tool_calls=ledger.tool_calls,
                from_state=AgentRunState.MODEL_TURN,
            )

        if definition.kind is ToolKind.WRITE:
            try:
                self._kill_switch.assert_enabled(AgentCapability.WRITE)
            except CapabilityDisabled:
                return self._refuse(
                    context,
                    AgentRefusalReason.CAPABILITY_DISABLED,
                    principal=principal,
                    correlation_id=correlation_id,
                    detail=AgentCapability.WRITE.value,
                    tool_calls=ledger.tool_calls,
                    from_state=AgentRunState.MODEL_TURN,
                )

        context.transition(AgentRunState.TOOL_CALL, f"{definition.name} v{definition.version}")
        ledger.consume_tool_call(write=definition.kind is ToolKind.WRITE)

        try:
            arguments = self._registry.parse_arguments(definition, intent.tool_arguments)
        except ToolArgumentError:
            return self._refuse(
                context,
                AgentRefusalReason.INVALID_TOOL_ARGUMENTS,
                principal=principal,
                correlation_id=correlation_id,
                detail=definition.name,
                tool_calls=ledger.tool_calls,
                from_state=AgentRunState.TOOL_CALL,
            )

        try:
            return self._invoke(
                context,
                ledger,
                definition,
                arguments,
                principal=principal,
                purpose=purpose,
                question=question,
                correlation_id=correlation_id,
            )
        except PolarisError as error:
            # Authorization, consent, and policy denials arrive here. The model asked; the
            # deterministic services said no, and the run ends without a fabricated success.
            return self._refuse(
                context,
                AgentRefusalReason.UNAUTHORIZED,
                principal=principal,
                correlation_id=correlation_id,
                detail=error.code,
                tool_calls=ledger.tool_calls,
                from_state=AgentRunState.TOOL_CALL,
            )

    def _invoke(
        self,
        context: _RunContext,
        ledger: BudgetLedger,
        definition: ToolDefinition,
        arguments: object,
        *,
        principal: Principal,
        purpose: PurposeOfUse,
        question: str,
        correlation_id: str,
    ) -> AgentRunResult | None:
        if isinstance(arguments, PolicySearchArguments):
            retrieval = self._corpus.active_index().search(
                principal=principal,
                question=arguments.question,
            )
            context.retrieved = retrieval.chunks
            context.transition(AgentRunState.MODEL_TURN, f"{len(retrieval.chunks)} chunks")
            return None

        if isinstance(arguments, PatientSummaryArguments):
            summary = self._patients.authorized_summary(
                principal=principal,
                purpose=purpose,
                patient_id=arguments.patient_id,
                correlation_id=correlation_id,
            )
            context.transition(AgentRunState.MODEL_TURN, f"summary {summary.patient_id}")
            return None

        if isinstance(arguments, ProposeFollowUpArguments):
            drafted = _drafted_summary(arguments.summary, question)
            validation = validate_proposal_summary(drafted)
            if not validation.accepted and validation.reason is not None:
                return self._refuse(
                    context,
                    validation.reason,
                    principal=principal,
                    correlation_id=correlation_id,
                    detail=validation.detail,
                    tool_calls=ledger.tool_calls,
                    from_state=AgentRunState.TOOL_CALL,
                )
            proposal = self._actions.propose(
                principal=principal,
                purpose=purpose,
                action=FollowUpAction(
                    patient_id=arguments.patient_id,
                    facility_id=arguments.facility_id,
                    due_date=arguments.due_date,
                    summary=drafted,
                ),
                correlation_id=correlation_id,
            )
            context.transition(AgentRunState.VALIDATING, f"proposal {proposal.proposal_id}")
            return self._complete(
                context,
                principal=principal,
                correlation_id=correlation_id,
                answer="",
                citations=(),
                tool_calls=ledger.tool_calls,
                proposal_id=proposal.proposal_id,
            )

        raise IllegalAgentTransition(f"unhandled tool {definition.name}")

    def _complete(
        self,
        context: _RunContext,
        *,
        principal: Principal,
        correlation_id: str,
        answer: str,
        citations: tuple[Citation, ...],
        tool_calls: int,
        proposal_id: str | None = None,
    ) -> AgentRunResult:
        context.transition(AgentRunState.COMPLETED, proposal_id or "answered")
        self._append(
            principal=principal,
            correlation_id=correlation_id,
            context=context,
            outcome="AGENT_RUN_COMPLETED",
            detail=proposal_id or "answer",
            tool_calls=tool_calls,
        )
        return AgentRunResult(
            run_id=context.run_id,
            state=AgentRunState.COMPLETED,
            answer=answer,
            citations=citations,
            proposal_id=proposal_id,
            steps=tuple(context.steps),
            tool_calls=tool_calls,
        )

    def _refuse(
        self,
        context: _RunContext,
        reason: AgentRefusalReason,
        *,
        principal: Principal,
        correlation_id: str,
        detail: str,
        tool_calls: int = 0,
        state: AgentRunState = AgentRunState.REFUSED,
        from_state: AgentRunState | None = None,
    ) -> AgentRunResult:
        if from_state is not None:
            context.state = from_state
        context.transition(state, f"{reason.value}: {detail}"[:200])
        self._append(
            principal=principal,
            correlation_id=correlation_id,
            context=context,
            outcome="AGENT_RUN_REFUSED" if state is AgentRunState.REFUSED else "AGENT_RUN_FAILED",
            detail=reason.value,
            tool_calls=tool_calls,
        )
        return AgentRunResult(
            run_id=context.run_id,
            state=state,
            refusal_reason=reason,
            steps=tuple(context.steps),
            tool_calls=tool_calls,
        )

    def _halt(
        self,
        context: _RunContext,
        *,
        principal: Principal,
        correlation_id: str,
        detail: str,
        tool_calls: int,
    ) -> AgentRunResult:
        if AgentRunState.HALTED not in _TRANSITIONS[context.state]:
            context.state = AgentRunState.MODEL_TURN
        context.transition(AgentRunState.HALTED, f"budget {detail}")
        self._append(
            principal=principal,
            correlation_id=correlation_id,
            context=context,
            outcome="AGENT_RUN_HALTED",
            detail=detail,
            tool_calls=tool_calls,
        )
        return AgentRunResult(
            run_id=context.run_id,
            state=AgentRunState.HALTED,
            refusal_reason=AgentRefusalReason.BUDGET_EXCEEDED,
            steps=tuple(context.steps),
            tool_calls=tool_calls,
        )

    def _append(
        self,
        *,
        principal: Principal,
        correlation_id: str,
        context: _RunContext,
        outcome: str,
        detail: str,
        tool_calls: int,
    ) -> None:
        self._audit.append(
            actor=principal.subject,
            event_type="agent.run",
            outcome=outcome,
            correlation_id=correlation_id,
            metadata={
                "run_id": context.run_id,
                "model_id": self._model.model_id,
                "corpus_version": context.corpus_version,
                "detail": detail,
                "steps": str(len(context.steps)),
                "tool_calls": str(tool_calls),
            },
        )


def _citations(
    retrieved: tuple[RetrievedChunk, ...],
    cited_chunk_ids: tuple[str, ...],
) -> tuple[Citation, ...]:
    """Build citations from the retriever's records, never from the model's text."""

    by_id = {chunk.chunk_id: chunk for chunk in retrieved}
    citations: list[Citation] = []
    seen: set[str] = set()
    for chunk_id in cited_chunk_ids:
        chunk = by_id.get(chunk_id)
        if chunk is None or chunk.document_id in seen:
            continue
        seen.add(chunk.document_id)
        citations.append(
            Citation(
                document_id=chunk.document_id,
                title=chunk.document_title,
                version=chunk.document_version,
                excerpt=chunk.text[:300],
            )
        )
    return tuple(citations)


def _drafted_summary(summary: str, question: str) -> str:
    text = summary.strip() or f"Administrative follow-up requested: {question.strip()}"
    return text[:500]
