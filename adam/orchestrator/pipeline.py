"""
adam/orchestrator/pipeline.py

The integration point named in the task brief's execution-flow diagram:

    Raw Events -> Fusion -> Semantic Events -> Policy Engine -> Adaptive
    Deception -> (Sandbox Mutation)

Coordinates three already-real, already-tested components -- Dev B's
`adam.fusion.engine.EventFusionEngine`, Dev C's `adam.policy.engine.
PolicyEngine`, and Dev C's `adam.deception.engine.DeceptionEngine` -- via
the frozen `adam.contracts` boundary, using `adam.fusion.adapter` at the one
seam (Fusion's internal models vs. the contracts models) that needed a
translator. Duplicates none of their logic; this module is glue only.

Runs in **batch mode**: it processes the complete set of `RawEvent`s a
session captured, once, after telemetry export -- not interleaved with a
still-running detonation. `SandboxController.detonate()` is a single
blocking call today (see docs/ADAM_Full_Repository_Audit.md), so true
live, mutation-during-execution operation (ARCHITECTURE.md section 3.3's
closed loop) is a larger, separate restructuring of `detonate()` this pass
does not attempt. Batch mode is still a real, disclosed step toward that
diagram: every real session now produces real `SemanticEvent`s,
`PolicyDecision`s, and `MutationResult`s from its own captured telemetry,
which no code anywhere did before this change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from adam.contracts.enums import Verdict
from adam.contracts.mutation import MutationResult
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.raw_event import RawEvent as ContractRawEvent
from adam.contracts.semantic_event import SemanticEvent as ContractSemanticEvent
from adam.deception.engine import DeceptionEngine
from adam.deception.primitives.base import GuestMutationChannel
from adam.fusion.adapter import fusion_semantic_to_contract, raw_event_to_fusion
from adam.fusion.engine import EventFusionEngine
from adam.policy.context import SessionContext
from adam.policy.engine import PolicyEngine

__all__ = ["PipelineResult", "run_fusion_policy_deception"]


@dataclass(slots=True)
class PipelineResult:
    """Everything one batch run of the Fusion -> Policy -> Deception chain produced."""

    semantic_events: list[ContractSemanticEvent] = field(default_factory=list)
    decisions: list[PolicyDecision] = field(default_factory=list)
    mutations: list[MutationResult] = field(default_factory=list)
    fusion_runtime_ms: float = 0.0
    correlated_groups: int = 0


def _detector_name_for(category: str) -> str:
    """Best-effort label: Dev B's SemanticEvent carries `category`, not which detector produced it."""
    return f"{category.replace(' ', '')}Detector"


async def run_fusion_policy_deception(
    raw_events: Sequence[ContractRawEvent],
    *,
    session_id: str,
    ruleset_path: str,
    channel: GuestMutationChannel,
    global_confidence_gate: float = 0.60,
    dry_run: bool = False,
) -> PipelineResult:
    """
    Runs one session's captured `RawEvent`s through Fusion, then Policy,
    then (for every `EXECUTE` decision) Deception. Never raises for
    "nothing interesting happened" -- an empty `raw_events` or a run that
    triggers no detector produces a `PipelineResult` with empty lists, the
    same "zero findings is a valid result" posture the rest of ADAM uses
    (ARCHITECTURE.md section 14.2).

    `channel`: a real `GuestMutationChannel` (see
    `adam.sandbox.guest.mutation_channel.RecordingGuestMutationChannel`)
    or a test double -- this function does not care which, matching
    `DeceptionEngine`'s own bus-agnostic design.
    """
    fusion_events = [raw_event_to_fusion(evt) for evt in raw_events]

    fusion_engine = EventFusionEngine()
    fusion_result = fusion_engine.process(fusion_events)

    semantic_events = [
        fusion_semantic_to_contract(
            detection, session_id=session_id, detector_name=_detector_name_for(detection.category)
        )
        for detection in fusion_result.detections
    ]

    context = SessionContext(session_id=session_id, dry_run=dry_run)
    policy_engine = PolicyEngine(ruleset_path, global_confidence_gate=global_confidence_gate, dry_run=dry_run)

    decisions: list[PolicyDecision] = []
    for semantic_event in semantic_events:
        decisions.extend(policy_engine.evaluate(semantic_event, context))

    deception_engine = DeceptionEngine(channel)
    mutations: list[MutationResult] = []
    for decision in decisions:
        if decision.verdict == Verdict.EXECUTE and decision.action is not None:
            mutations.append(await deception_engine.execute_async(decision))

    return PipelineResult(
        semantic_events=semantic_events,
        decisions=decisions,
        mutations=mutations,
        fusion_runtime_ms=fusion_result.runtime_ms,
        correlated_groups=fusion_result.correlated_groups,
    )
