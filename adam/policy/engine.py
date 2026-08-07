"""
PolicyEngine — the decision layer (ARCHITECTURE.md §5.5).

Construction does I/O (loading + compiling YAML from disk). evaluate() does
not — it is a pure function of (event, session context), which is what
ADR-004 requires and what makes results reproducible for the paper.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from adam.contracts.interfaces import IPolicyEngine, SessionContextProtocol
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.enums import Verdict
from adam.policy.compiler import CompiledRule, compile_ruleset
from adam.policy.loader import RuleLoader


class PolicyEngine(IPolicyEngine):
    def __init__(
        self,
        ruleset_path: str,
        *,
        global_confidence_gate: float = 0.60,
        dry_run: bool = False,
        loader: RuleLoader | None = None,
    ) -> None:
        self._loader = loader or RuleLoader()
        raw_rules = self._loader.load(ruleset_path)
        self._rules: list[CompiledRule] = compile_ruleset(raw_rules)
        self._global_confidence_gate = global_confidence_gate
        self._dry_run = dry_run

    def evaluate(
        self, event: SemanticEvent, context: SessionContextProtocol
    ) -> list[PolicyDecision]:
        decisions: list[PolicyDecision] = []

        for rule in self._rules:
            start = time.perf_counter()

            if not rule.condition(event, context):
                continue  # rule simply doesn't match; not a suppression

            verdict, rationale = self._gate(rule, event, context)
            evaluation_ms = (time.perf_counter() - start) * 1000

            decision = PolicyDecision(
                decision_id=f"dec_{uuid.uuid4().hex[:12]}",
                session_id=event.session_id,
                correlation_id=event.correlation_id,
                triggered_by=event.semantic_id,
                rule_id=rule.rule_id,
                rule_version=rule.version,
                action=rule.action if verdict in (Verdict.EXECUTE, Verdict.DRY_RUN) else None,
                verdict=verdict,
                priority=rule.priority,
                parameters=rule.parameters,
                rationale=rationale,
                evaluation_ms=evaluation_ms,
            )
            context.record_decision(decision)
            decisions.append(decision)

        return decisions

    def _gate(
        self, rule: CompiledRule, event: SemanticEvent, context: SessionContextProtocol
    ) -> tuple[Verdict, str]:
        """Apply confidence gate, budget, and cooldown in that order."""
        if event.confidence < self._global_confidence_gate:
            return (
                Verdict.SUPPRESSED_CONFIDENCE,
                f"Confidence {event.confidence:.2f} below global gate "
                f"{self._global_confidence_gate:.2f}",
            )

        remaining = context.budget_remaining(rule.rule_id, rule.budget.max_per_session)
        if remaining <= 0:
            return (
                Verdict.SUPPRESSED_BUDGET,
                f"Rule '{rule.rule_id}' budget exhausted "
                f"(max {rule.budget.max_per_session} per session)",
            )

        if context.cooldown_active(rule.rule_id, rule.budget.cooldown_seconds):
            return (
                Verdict.SUPPRESSED_COOLDOWN,
                f"Rule '{rule.rule_id}' still within its "
                f"{rule.budget.cooldown_seconds}s cooldown",
            )

        if self._dry_run:
            return (
                Verdict.DRY_RUN,
                f"Rule '{rule.rule_id}' matched at confidence {event.confidence:.2f}; "
                f"dry_run=true so no mutation will be executed",
            )

        return (
            Verdict.EXECUTE,
            f"Intent '{event.intent}' at confidence {event.confidence:.2f} "
            f"(gate {self._global_confidence_gate:.2f}); "
            f"budget {rule.budget.max_per_session - remaining + 1}/{rule.budget.max_per_session} used; "
            f"no cooldown active",
        )
