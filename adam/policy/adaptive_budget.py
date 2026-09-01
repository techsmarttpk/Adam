"""Adaptive Budget and Effectiveness-Driven Policy Rate Limiter.

Dynamically expands mutation budgets for high-yield deception actions,
while aggressively throttling or suppressing repeated no-yield or backfiring actions.
"""

from __future__ import annotations
import dataclasses
from typing import Dict, List, Optional


@dataclasses.dataclass
class ActionBudgetState:
    action: str
    base_budget: int
    current_budget: int
    executions: int = 0
    yield_history: List[float] = dataclasses.field(default_factory=list)
    backfires: int = 0
    throttled: bool = False


class AdaptiveBudgetManager:
    """Dynamically scales action budgets based on measured efficacy and safety."""

    def __init__(
        self,
        global_max_mutations: int = 15,
        default_per_action_budget: int = 2,
    ) -> None:
        self.global_max_mutations = global_max_mutations
        self.default_per_action_budget = default_per_action_budget
        self.total_mutations_executed = 0
        self.action_states: Dict[str, ActionBudgetState] = {}

    def get_or_create_action_state(self, action: str) -> ActionBudgetState:
        if action not in self.action_states:
            self.action_states[action] = ActionBudgetState(
                action=action,
                base_budget=self.default_per_action_budget,
                current_budget=self.default_per_action_budget,
            )
        return self.action_states[action]

    def can_execute(self, action: str) -> Tuple[bool, str]:
        """Checks whether the action can execute under adaptive budget limits."""
        if self.total_mutations_executed >= self.global_max_mutations:
            return (False, f"Global mutation budget ({self.global_max_mutations}) exhausted.")

        state = self.get_or_create_action_state(action)
        if state.throttled:
            return (False, f"Action {action} is currently throttled due to repeated backfires or zero yield.")

        if state.executions >= state.current_budget:
            return (False, f"Action {action} reached its current budget ({state.current_budget}).")

        return (True, "Budget permitted.")

    def record_execution(self, action: str) -> None:
        self.total_mutations_executed += 1
        state = self.get_or_create_action_state(action)
        state.executions += 1

    def update_yield_feedback(self, action: str, yield_score: float, backfired: bool = False) -> None:
        """Adapts budget based on measured downstream yield and backfire indicators."""
        state = self.get_or_create_action_state(action)
        state.yield_history.append(yield_score)

        if backfired:
            state.backfires += 1
            if state.backfires >= 2:
                state.throttled = True

        # If consistently high yield (>60.0), reward with bonus budget (+1) up to limit
        if yield_score >= 60.0 and state.current_budget < (state.base_budget + 2):
            state.current_budget += 1

        # If zero yield on 2 consecutive executions, throttle
        if len(state.yield_history) >= 2 and sum(state.yield_history[-2:]) == 0.0:
            state.throttled = True
