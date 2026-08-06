"""
tests/integration/test_live_pipeline_integration.py

End-to-end proof for the execution flow the integration brief asked for:

    Raw Events -> Fusion -> Semantic Events -> Policy Engine ->
    Adaptive Deception -> (Sandbox Mutation)

Unlike tests/integration/test_replay_pipeline.py (which starts from
hand-authored SemanticEvent fixtures), this test starts from real
adam.contracts.raw_event.RawEvent objects -- the same shape
adam/collectors/*.py produce from a live Sysmon/ProcMon capture -- and
drives them through the REAL adam.fusion.engine.EventFusionEngine (Dev B),
the REAL adam.policy.engine.PolicyEngine (Dev C), and the REAL
adam.deception.engine.DeceptionEngine (Dev C) via
adam.orchestrator.pipeline.run_fusion_policy_deception -- the same function
adam.orchestrator.session.SessionOrchestrator now calls after every real
capture. No component here is mocked except the final guest-mutation
channel, which uses the real (recording, not-yet-live) implementation --
see adam/sandbox/guest/mutation_channel.py's module docstring for why that
one boundary is honestly a recording, not a live guest effect, today.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from adam.contracts.enums import Category, Source, Verdict
from adam.contracts.raw_event import ProcessInfo, RawEvent
from adam.orchestrator.pipeline import run_fusion_policy_deception
from adam.sandbox.guest.mutation_channel import RecordingGuestMutationChannel


def _process_event(
    *, event_id: str, pid: int, image: str, command_line: str = "", ppid: int = 1000
) -> RawEvent:
    return RawEvent(
        event_id=event_id,
        session_id="sess_pipeline_test",
        source=Source.SYSMON,
        source_event_id=1,
        category=Category.PROCESS,
        occurred_at=datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc),
        observed_at=datetime(2026, 8, 5, 12, 0, 1, tzinfo=timezone.utc),
        process=ProcessInfo(
            pid=pid,
            ppid=ppid,
            image=image,
            command_line=command_line,
            integrity_level="Medium",
            user="WIN10\\analyst",
            guid=f"{{{event_id}}}",
        ),
        attributes={},
    )


class TestLiveRawEventsThroughTheRealPipeline:
    @pytest.mark.asyncio
    async def test_recon_command_burst_produces_a_real_decision_and_mutation(self) -> None:
        """
        Three distinct system-discovery commands sharing one process_id
        (adam.fusion.correlate.EventCorrelator groups by process_id --
        this mirrors, e.g., one script invoking several recon commands in
        sequence under one logical process grouping) is exactly
        adam.fusion.detectors.recon.ReconDetector's own MIN_COMMANDS=3
        trigger condition.
        """
        raw_events = [
            _process_event(event_id="raw_1", pid=7000, image=r"C:\Windows\System32\whoami.exe"),
            _process_event(event_id="raw_2", pid=7000, image=r"C:\Windows\System32\hostname.exe"),
            _process_event(event_id="raw_3", pid=7000, image=r"C:\Windows\System32\ipconfig.exe"),
        ]

        channel = RecordingGuestMutationChannel(session_id="sess_pipeline_test")
        result = await run_fusion_policy_deception(
            raw_events,
            session_id="sess_pipeline_test",
            ruleset_path="rules/default",
            channel=channel,
        )

        assert len(result.semantic_events) == 1
        semantic_event = result.semantic_events[0]
        assert semantic_event.intent == "RECON_SYSTEM_UPTIME"
        assert semantic_event.evidence == ["raw_1", "raw_2", "raw_3"]

        assert len(result.decisions) == 1
        decision = result.decisions[0]
        assert decision.rule_id == "RULE-025"
        assert decision.verdict == Verdict.EXECUTE
        assert decision.action == "SPAWN_DECOY_PROCESSES"

        assert len(result.mutations) == 1
        assert result.mutations[0].primitive.startswith("SpawnDecoyProcesses")

        # The mutation reached the real DeceptionEngine -> real primitive ->
        # real channel, and every Change it produced was recorded --
        # end to end, nothing mocked except the final guest effect itself.
        assert len(channel.recorded) >= 1

    @pytest.mark.asyncio
    async def test_registry_run_key_write_produces_a_real_semantic_event(self) -> None:
        """
        Dev B's PersistenceDetector fires on a `reg.exe add ...\\Run ...`
        process-create (a real, correct detection). The corresponding rule,
        RULE-021, additionally requires `when.custom:
        predicates.distinct_registry_keys_over` (features.distinct_
        registry_keys > 5, rules/default/persistence.yaml) -- a signal only
        a real Fusion correlation window (multiple related registry writes
        grouped together) could honestly compute, not something this
        adapter fabricates from one process-create event. So the real,
        correct behavior here is: a real SemanticEvent, zero decisions --
        Policy's confidence/predicate gating working exactly as designed
        (ARCHITECTURE.md section 5.5), not a bug in the pipeline.
        """
        raw_events = [
            _process_event(
                event_id="raw_reg_1",
                pid=8000,
                image=r"C:\Windows\System32\reg.exe",
                command_line=r'reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /d evil.exe',
            ),
        ]

        channel = RecordingGuestMutationChannel(session_id="sess_pipeline_test")
        result = await run_fusion_policy_deception(
            raw_events,
            session_id="sess_pipeline_test",
            ruleset_path="rules/default",
            channel=channel,
        )

        assert len(result.semantic_events) == 1
        assert result.semantic_events[0].intent == "PERSIST_RUN_KEY"
        assert result.semantic_events[0].evidence == ["raw_reg_1"]

        # RULE-021's predicate is not satisfiable from a single event's
        # features -- see docstring above.
        assert result.decisions == []
        assert result.mutations == []

    @pytest.mark.asyncio
    async def test_benign_events_produce_no_findings_and_no_crash(self) -> None:
        """Mirrors sess_2026_08_05_a7f82ef0's real content (see
        docs/ADAM_DevC_Bypass_Feasibility.md) -- ordinary background
        process activity must flow through cleanly with zero detections,
        not raise."""
        raw_events = [
            _process_event(event_id="raw_bg_1", pid=1234, image=r"C:\Windows\System32\svchost.exe"),
            _process_event(event_id="raw_bg_2", pid=5678, image=r"C:\Windows\System32\VBoxService.exe"),
        ]

        channel = RecordingGuestMutationChannel(session_id="sess_pipeline_test")
        result = await run_fusion_policy_deception(
            raw_events, session_id="sess_pipeline_test", ruleset_path="rules/default", channel=channel
        )

        assert result.semantic_events == []
        assert result.decisions == []
        assert result.mutations == []
        assert channel.recorded == []

    @pytest.mark.asyncio
    async def test_empty_session_does_not_raise(self) -> None:
        channel = RecordingGuestMutationChannel(session_id="sess_pipeline_test")
        result = await run_fusion_policy_deception(
            [], session_id="sess_pipeline_test", ruleset_path="rules/default", channel=channel
        )
        assert result.semantic_events == []
        assert result.decisions == []
        assert result.mutations == []
