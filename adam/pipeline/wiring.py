"""
adam/pipeline/wiring.py

Shared EventBus -> Fusion/Policy/Deception wiring, used by BOTH composition
roots so the live detonation path and the replay/API path subscribe the same
handlers and execute the same engines:

  - adam/api/deps.py (replay CLI + FastAPI server) -- the original inline
    handlers lived here (init_dependencies, "Handlers for Bus wiring") and
    were extracted verbatim into this module.
  - adam/orchestrator/runner.py (live `adam run` detonation path) -- calls
    wire_engines() on the session's EventBus before SessionOrchestrator
    starts publishing, so a live session's raw telemetry is processed by
    Fusion/Policy/Deception as it flows instead of being dropped by an
    empty bus.

The three subscriber names are fixed and identical in both paths:
fusion_raw (RawEvent -> EventFusionEngine), policy_semantic (SemanticEvent
-> PolicyEngine), deception_decision (PolicyDecision -> DeceptionEngine).

The only parameterized, caller-specific piece is how a session's dry-run
(deception-enablement) state is resolved, because the two roots differ
there:
  - deps.py resolves it from the persisted AnalysisSession (DB lookup),
    preserving the pre-extraction behavior exactly (including the
    "no session record -> deception enabled" fallback).
  - runner.py (live) has no DB; it passes no resolver, which defaults to
    dry_run=True (deception does not execute) for every session. This is
    the SAFE default: the first end-to-end live runs are observation-only
    until a real mutation channel exists, at which point a live resolver
    can be wired to restore per-session enablement.

The Deception engine's mutation channel is chosen by each caller (deps.py
and runner.py both use FakeGuestChannel for now); the real guest mutation
channel is a separate follow-up and is not this module's concern.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable

from adam.common.bus import EventBus, Subscription
from adam.contracts.envelope import Envelope
from adam.contracts.enums import MutationStatus, Verdict
from adam.contracts.mutation import MutationResult
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent, Actor, AttckRef
from adam.deception.engine import DeceptionEngine
from adam.fusion.engine import EventFusionEngine
from adam.fusion.models import RawEvent as FusionRawEvent
from adam.policy.context import SessionContext
from adam.policy.engine import PolicyEngine
from adam.fusion.mapping import map_detection_to_intent

logger = logging.getLogger(__name__)


@dataclass
class EngineHandles:
    """
    Handle to one wire_engines() call: the three live subscriptions (their
    delivered/dropped counters are the proof that events were actually
    processed) and the session-context cache the handlers own.
    """

    subscriptions: list[Subscription] = field(default_factory=list)
    session_contexts: dict[str, SessionContext] = field(default_factory=dict)
    decisions_total: int = 0
    decisions_executed: int = 0
    mutations_applied: int = 0

    def delivered(self, name: str) -> int:
        for subscription in self.subscriptions:
            if subscription.name == name:
                return subscription.delivered
        return 0


async def _default_dry_run(_session_id: str) -> bool:
    return True


def wire_engines(
    bus: EventBus,
    *,
    fusion: EventFusionEngine,
    policy: PolicyEngine,
    deception: DeceptionEngine,
    session_contexts: dict[str, SessionContext] | None = None,
    resolve_dry_run: Callable[[str], Awaitable[bool | None]] | None = None,
) -> EngineHandles:
    """
    Subscribe fusion_raw / policy_semantic / deception_decision onto `bus`.

    Handlers replicate (byte-for-byte behaviour) the handlers that used to
    be defined inline in adam/api/deps.py:init_dependencies(). The single
    behavioural parameter is `resolve_dry_run(session_id) -> bool | None`:
    consulted at most once per session, on the first SemanticEvent for that
    session, to decide dry_run for the session's PolicyEngine context and
    whether DeceptionEngine.execute_async() may run. `None` (or omitting
    the resolver) means "no information" -> dry_run=True, i.e. deception
    does NOT execute -- the safe observation-only default for the live
    path, chosen deliberately so a live session validates the reactive
    loop without attempting mutations until a real mutation channel and a
    live dry-run resolver exist.
    """
    if session_contexts is None:
        session_contexts = {}

    handles = EngineHandles(session_contexts=session_contexts)

    async def _dry_run_for(session_id: str) -> bool:
        if resolve_dry_run is None:
            return await _default_dry_run(session_id)
        result = await resolve_dry_run(session_id)
        return True if result is None else result

    async def handle_raw_event(env: Envelope[RawEvent]) -> None:
        try:
            ts = env.payload.occurred_at
        except Exception:
            ts = datetime.now(timezone.utc)

        fusion_ev = FusionRawEvent(
            timestamp=ts,
            source="bus",
            event_type=env.payload.category.value if hasattr(env.payload.category, "value") else str(env.payload.category),
            process_id=env.payload.process.pid if env.payload.process else env.payload.attributes.get("pid"),
            parent_process_id=env.payload.process.ppid if env.payload.process else env.payload.attributes.get("ppid"),
            process_name=env.payload.process.image if env.payload.process else env.payload.attributes.get("process_name"),
            command_line=env.payload.process.command_line if env.payload.process else env.payload.attributes.get("command_line"),
            payload=env.payload.attributes,
        )

        result = fusion.process([fusion_ev])

        for idx, detection in enumerate(result.detections, start=1):
            intent, tactic, technique = map_detection_to_intent(detection)
            first_ev = detection.evidence[0] if detection.evidence else None
            pid = first_ev.process_id if (first_ev and first_ev.process_id) else 1000
            pname = first_ev.process_name if (first_ev and first_ev.process_name) else "unknown.exe"

            dts = detection.timestamp
            if dts.tzinfo is None:
                dts = dts.replace(tzinfo=timezone.utc)

            features = {"file_count": len(detection.evidence), "has_target": True}
            if first_ev:
                if first_ev.payload and "TargetFilename" in first_ev.payload:
                    features["target_object"] = first_ev.payload["TargetFilename"]
                elif first_ev.payload and "TargetObject" in first_ev.payload:
                    features["target_object"] = first_ev.payload["TargetObject"]
                elif first_ev.payload and "DestinationIp" in first_ev.payload:
                    features["network_endpoint"] = f"{first_ev.payload.get('DestinationIp')}:{first_ev.payload.get('DestinationPort', '')}"
                elif first_ev.payload and "QueryName" in first_ev.payload:
                    features["network_endpoint"] = first_ev.payload["QueryName"]

            if intent == "RECON_DOMAIN_CONTROLLER":
                features["ldap_attempts"] = 3
                features["all_failed"] = True
            elif intent == "PERSIST_RUN_KEY":
                features["distinct_registry_keys"] = 6

            se = SemanticEvent(
                semantic_id=f"sem_{uuid.uuid4().hex[:8]}_{idx:03d}",
                session_id=env.session_id,
                correlation_id=env.correlation_id,
                intent=intent,
                confidence=max(detection.confidence, 0.8),
                severity=detection.severity,
                window_start=dts,
                window_end=dts,
                actor=Actor(pid=pid, image=f"C:\\Windows\\System32\\{pname}", guid=f"{{guid-{uuid.uuid4().hex[:8]}}}"),
                evidence=[e.process_name for e in detection.evidence if e.process_name],
                attck=AttckRef(tactic=tactic, technique=technique),
                detector=f"{detection.category}Detector@1.0",
                features=features,
            )

            s_env = Envelope[SemanticEvent](
                message_id=str(uuid.uuid4()),
                message_type="SemanticEvent",
                session_id=env.session_id,
                correlation_id=env.correlation_id,
                emitted_at=datetime.now(timezone.utc),
                emitter="LiveFusionBridge",
                payload=se,
            )
            await bus.publish(s_env)

    async def handle_semantic_event(env: Envelope[SemanticEvent]) -> None:
        session_id = env.session_id
        if session_id not in session_contexts:
            session_contexts[session_id] = SessionContext(
                session_id=session_id, dry_run=await _dry_run_for(session_id)
            )

        decisions = policy.evaluate(env.payload, session_contexts[session_id])
        for decision in decisions:
            handles.decisions_total += 1
            if decision.verdict == Verdict.EXECUTE:
                handles.decisions_executed += 1
            d_env = Envelope[PolicyDecision](
                message_id=str(uuid.uuid4()),
                message_type="PolicyDecision",
                session_id=session_id,
                correlation_id=env.correlation_id,
                emitted_at=datetime.now(timezone.utc),
                emitter="PolicyEngine",
                payload=decision,
            )
            await bus.publish(d_env)
        # Cooperative yield after processing each semantic event so consumer tasks
        # (especially deception_decision) can drain their queues without latency starvation.
        await asyncio.sleep(0)

    async def handle_policy_decision(env: Envelope[PolicyDecision]) -> None:
        decision = env.payload

        if decision.verdict == Verdict.EXECUTE:
            try:
                # Retrieve deception enablement from the cached context to
                # avoid a DB round-trip; fall back to the resolver (or the
                # no-info default: enabled) if no context exists yet.
                context = session_contexts.get(env.session_id)
                if context is not None:
                    deception_enabled = not context.dry_run
                else:
                    deception_enabled = not await _dry_run_for(env.session_id)

                if not deception_enabled:
                    logger.info(
                        "[DeceptionEngine] decision=%s action=%s SKIPPED: dry_run is active or deception disabled",
                        decision.decision_id, decision.action,
                    )
                    return

                mutation = await deception.execute_async(decision)
                if mutation.status == MutationStatus.APPLIED:
                    handles.mutations_applied += 1
                    logger.info(
                        "[DeceptionEngine] decision=%s action=%s mutation=%s APPLIED successfully (latency=%.2fms)",
                        decision.decision_id, decision.action, mutation.mutation_id, mutation.latency_ms,
                    )
                elif mutation.status == MutationStatus.FAILED:
                    logger.warning(
                        "[DeceptionEngine] decision=%s action=%s mutation=%s FAILED: %s",
                        decision.decision_id, decision.action, mutation.mutation_id, mutation.error,
                    )
                elif mutation.status == MutationStatus.SKIPPED:
                    logger.info(
                        "[DeceptionEngine] decision=%s action=%s mutation=%s SKIPPED",
                        decision.decision_id, decision.action, mutation.mutation_id,
                    )
                else:
                    logger.info(
                        "[DeceptionEngine] decision=%s action=%s mutation=%s status=%s",
                        decision.decision_id, decision.action, mutation.mutation_id, mutation.status,
                    )
                m_env = Envelope[MutationResult](
                    message_id=str(uuid.uuid4()),
                    message_type="MutationResult",
                    session_id=env.session_id,
                    correlation_id=env.correlation_id,
                    emitted_at=datetime.now(timezone.utc),
                    emitter="DeceptionEngine",
                    payload=mutation,
                )
                await bus.publish(m_env)
            except Exception as e:
                logger.error(f"Deception failed unexpectedly for decision=%s: {e}", decision.decision_id, exc_info=True)

    subscriptions = [
        bus.subscribe(PolicyDecision, handle_policy_decision, name="deception_decision", queue_size=100000),
        bus.subscribe(RawEvent, handle_raw_event, name="fusion_raw", queue_size=10000),
        bus.subscribe(SemanticEvent, handle_semantic_event, name="policy_semantic", queue_size=50000),
    ]
    return handles
