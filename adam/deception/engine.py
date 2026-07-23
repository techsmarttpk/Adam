"""
DeceptionEngine (ARCHITECTURE.md §5.6).

Owns: looking up the right primitive for a decision and executing it.
Must not: read policy YAML, re-decide whether a mutation is warranted (the
decision has already been made by Policy), or call VBoxManage directly.

Wiring note: in the real system this class subscribes to `PolicyDecision`
on the event bus (adam.common.bus — Dev A's module) and publishes
`MutationResult` back onto it (ADR-003). That wiring belongs in
adam/api/deps.py (the composition root) or adam/orchestrator/, not here —
this class only needs a bus-agnostic execute() method to stay unit-testable.
"""

from __future__ import annotations

from adam.contracts.enums import MutationStatus, Verdict
from adam.contracts.interfaces import IDeceptionEngine
from adam.contracts.mutation import MutationResult
from adam.contracts.policy_decision import PolicyDecision
from adam.deception.catalogue import get_primitive_class
from adam.deception.primitives.base import GuestMutationChannel


class DeceptionEngine(IDeceptionEngine):
    def __init__(self, channel: GuestMutationChannel) -> None:
        self._channel = channel

    def execute(self, decision: PolicyDecision) -> MutationResult:  # pragma: no cover
        raise NotImplementedError("Use execute_async — all guest ops are async (C5)")

    async def execute_async(self, decision: PolicyDecision) -> MutationResult:
        if decision.action is None or decision.verdict == Verdict.DRY_RUN:
            # DRY_RUN or a suppressed verdict slipped through — nothing to do.
            return MutationResult(
                mutation_id=f"skip_{decision.decision_id}",
                session_id=decision.session_id,
                correlation_id=decision.correlation_id,
                decision_id=decision.decision_id,
                primitive="none",
                status=MutationStatus.SKIPPED,
                revertible=False,
            )

        primitive_cls = get_primitive_class(decision.action)
        primitive = primitive_cls(self._channel)
        return await primitive.apply_async(
            session_id=decision.session_id,
            correlation_id=decision.correlation_id,
            decision_id=decision.decision_id,
            parameters=decision.parameters,
        )
