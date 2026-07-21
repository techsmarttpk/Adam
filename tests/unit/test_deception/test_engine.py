"""
Proves DeceptionEngine.execute_async() turns a PolicyDecision into a
MutationResult using a fake GuestMutationChannel — no VM, no Pranav's
sandbox module needed. This is what "Deception is testable without a VM"
means in practice.
"""

from __future__ import annotations

import pytest

from adam.contracts.enums import MutationStatus, Verdict
from adam.contracts.policy_decision import PolicyDecision
from adam.deception.engine import DeceptionEngine


class FakeGuestChannel:
    def __init__(self) -> None:
        self.applied: list[tuple[str, str, str, str | None]] = []

    async def apply_mutation(self, kind: str, target: str, operation: str, value: str | None) -> None:
        self.applied.append((kind, target, operation, value))


def _decision() -> PolicyDecision:
    return PolicyDecision(
        decision_id="dec_test0001",
        session_id="sess_test_0001",
        correlation_id="corr_test0001",
        triggered_by="sem_test0001",
        rule_id="RULE-014",
        rule_version="1.0.3",
        action="SPAWN_FAKE_DC_ARTIFACTS",
        verdict=Verdict.EXECUTE,
        priority=80,
        parameters={
            "domain_name": "CORP.LOCAL",
            "dc_hostname": "DC01",
            "netbios": "CORP",
            "populate_sysvol": True,
        },
        rationale="test fixture",
    )


@pytest.mark.asyncio
async def test_execute_applies_all_changes_and_scores_plausibility():
    channel = FakeGuestChannel()
    engine = DeceptionEngine(channel)

    result = await engine.execute_async(_decision())

    assert result.status == MutationStatus.APPLIED
    assert result.primitive.startswith("FakeDomainControllerDeception")
    assert 0.0 <= result.plausibility_score <= 1.0
    assert len(channel.applied) == len(result.changes) == 3  # registry + dns + sysvol


@pytest.mark.asyncio
async def test_execute_marks_failed_on_channel_error():
    class ExplodingChannel(FakeGuestChannel):
        async def apply_mutation(self, *args, **kwargs) -> None:  # noqa: D401
            raise RuntimeError("guest agent unreachable")

    engine = DeceptionEngine(ExplodingChannel())

    result = await engine.execute_async(_decision())

    assert result.status == MutationStatus.FAILED
    assert result.error is not None
