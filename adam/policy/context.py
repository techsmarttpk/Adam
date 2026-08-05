"""
SessionContext — the per-session state passed explicitly into
PolicyEngine.evaluate(). One instance per analysis session, owned by the
orchestrator (Dev A / Pranav) and handed to you; you never construct it from
hidden global state (ADR-004).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from adam.contracts.interfaces import SessionContextProtocol
from adam.contracts.policy_decision import PolicyDecision
from adam.policy.budget import BudgetTracker


@dataclass
class SessionContext(SessionContextProtocol):
    session_id: str
    budget: BudgetTracker = field(default_factory=BudgetTracker)
    decisions: list[PolicyDecision] = field(default_factory=list)
    dry_run: bool = False

    def budget_remaining(self, rule_id: str, max_per_session: int) -> int:
        return self.budget.remaining(rule_id, max_per_session)

    def cooldown_active(self, rule_id: str, cooldown_seconds: float) -> bool:
        return self.budget.cooldown_active(rule_id, cooldown_seconds)

    def record_decision(self, decision: PolicyDecision) -> None:
        self.decisions.append(decision)
        if decision.verdict.value == "EXECUTE":
            self.budget.record_fire(decision.rule_id)
