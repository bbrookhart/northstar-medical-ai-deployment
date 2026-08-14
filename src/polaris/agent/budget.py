from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from polaris.services.audit import utc_now


class BudgetExceeded(RuntimeError):
    """A bound was reached. The run halts; it does not degrade into an unbounded one."""

    def __init__(self, bound: str) -> None:
        super().__init__("Agent resource budget exceeded")
        self.bound = bound


@dataclass(frozen=True, slots=True)
class AgentBudget:
    """Hard caps for one run. Every field is a stop condition, not a target.

    Defaults are bounded engineering values for a local simulation, not measured or approved
    production limits. Cost is absent because no metered provider is connected; adding one requires
    a cost bound here before it is enabled.
    """

    max_steps: int = 8
    max_tool_calls: int = 4
    max_write_proposals: int = 1
    max_context_characters: int = 8_000
    max_answer_characters: int = 2_000
    deadline_seconds: float = 10.0

    def __post_init__(self) -> None:
        values = (
            self.max_steps,
            self.max_tool_calls,
            self.max_write_proposals,
            self.max_context_characters,
            self.max_answer_characters,
        )
        if any(value < 1 for value in values):
            raise ValueError("Every agent budget bound must be at least one")
        if self.max_steps > 100 or self.max_tool_calls > 20 or self.max_write_proposals > 1:
            raise ValueError("Agent budget bounds exceed the approved v1 ceiling")
        if not 0 < self.deadline_seconds <= 120:
            raise ValueError("Agent deadline must be positive and at most 120 seconds")


class BudgetLedger:
    """Tracks consumption for exactly one run and refuses to be reused."""

    def __init__(
        self,
        budget: AgentBudget,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._budget = budget
        self._clock = clock
        self._started_at = clock()
        self._steps = 0
        self._tool_calls = 0
        self._write_proposals = 0

    @property
    def budget(self) -> AgentBudget:
        return self._budget

    @property
    def steps(self) -> int:
        return self._steps

    @property
    def tool_calls(self) -> int:
        return self._tool_calls

    @property
    def remaining_steps(self) -> int:
        return max(0, self._budget.max_steps - self._steps)

    def consume_step(self) -> None:
        self._check_deadline()
        if self._steps >= self._budget.max_steps:
            raise BudgetExceeded("max_steps")
        self._steps += 1

    def consume_tool_call(self, *, write: bool) -> None:
        self._check_deadline()
        if self._tool_calls >= self._budget.max_tool_calls:
            raise BudgetExceeded("max_tool_calls")
        if write and self._write_proposals >= self._budget.max_write_proposals:
            raise BudgetExceeded("max_write_proposals")
        self._tool_calls += 1
        if write:
            self._write_proposals += 1

    def check_context(self, context: str) -> None:
        if len(context) > self._budget.max_context_characters:
            raise BudgetExceeded("max_context_characters")

    def check_answer(self, answer: str) -> None:
        if len(answer) > self._budget.max_answer_characters:
            raise BudgetExceeded("max_answer_characters")

    def _check_deadline(self) -> None:
        if self._clock() - self._started_at > timedelta(seconds=self._budget.deadline_seconds):
            raise BudgetExceeded("deadline_seconds")
