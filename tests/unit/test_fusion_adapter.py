"""
tests/unit/test_fusion_adapter.py

Covers adam/fusion/adapter.py -- the boundary translator between the frozen
adam.contracts models and Dev B's internal adam.fusion.models, built as part
of the live Fusion -> Policy -> Deception pipeline integration
(adam/orchestrator/pipeline.py). See that module's docstring and
docs/ADAM_Full_Repository_Audit.md for why this adapter exists at all.
"""

from __future__ import annotations

from datetime import datetime, timezone

from adam.contracts.enums import Category, Source
from adam.contracts.raw_event import ProcessInfo, RawEvent
from adam.fusion.adapter import CATEGORY_TO_INTENT, fusion_semantic_to_contract, raw_event_to_fusion
from adam.fusion.models import RawEvent as FusionRawEvent
from adam.fusion.models import SemanticEvent as FusionSemanticEvent


def _raw_event(**overrides: object) -> RawEvent:
    defaults: dict[str, object] = dict(
        event_id="raw_abc123",
        session_id="sess_test",
        source=Source.SYSMON,
        source_event_id=1,
        category=Category.PROCESS,
        occurred_at=datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc),
        observed_at=datetime(2026, 8, 5, 12, 0, 1, tzinfo=timezone.utc),
        process=ProcessInfo(
            pid=4812,
            ppid=2204,
            image=r"C:\Windows\System32\whoami.exe",
            command_line="whoami.exe",
            integrity_level="Medium",
            user="WIN10\\analyst",
            guid="{a1b2c3d4-0000-0000-0000-000000000001}",
        ),
        attributes={"RuleName": "-"},
    )
    defaults.update(overrides)
    return RawEvent(**defaults)  # type: ignore[arg-type]


class TestRawEventToFusion:
    def test_maps_core_fields(self) -> None:
        event = _raw_event()
        fusion_event = raw_event_to_fusion(event)

        assert fusion_event.timestamp == event.occurred_at
        assert fusion_event.source == "SYSMON"
        assert fusion_event.event_type == "PROCESS"
        assert fusion_event.process_id == 4812
        assert fusion_event.parent_process_id == 2204
        assert fusion_event.process_name == r"C:\Windows\System32\whoami.exe"
        assert fusion_event.command_line == "whoami.exe"

    def test_stashes_original_event_id_for_evidence_traceability(self) -> None:
        event = _raw_event(event_id="raw_specific_id")
        fusion_event = raw_event_to_fusion(event)
        assert fusion_event.payload["_adam_event_id"] == "raw_specific_id"

    def test_attributes_flow_into_payload(self) -> None:
        event = _raw_event(attributes={"TargetObject": r"HKLM\SOFTWARE\Run", "Details": "x"})
        fusion_event = raw_event_to_fusion(event)
        assert fusion_event.payload["TargetObject"] == r"HKLM\SOFTWARE\Run"

    def test_handles_missing_process(self) -> None:
        event = _raw_event(process=None)
        fusion_event = raw_event_to_fusion(event)
        assert fusion_event.process_id is None
        assert fusion_event.process_name is None


class TestFusionSemanticToContract:
    def _fusion_semantic_event(self, *, category: str = "Reconnaissance") -> FusionSemanticEvent:
        evidence = [
            FusionRawEvent(
                timestamp=datetime(2026, 8, 5, 12, 0, 0),
                source="sysmon",
                event_type="PROCESS",
                process_id=4812,
                process_name="whoami.exe",
                payload={"_adam_event_id": "raw_abc123"},
            )
        ]
        return FusionSemanticEvent(
            timestamp=datetime(2026, 8, 5, 12, 0, 0),
            category=category,
            technique_id="T1082",
            severity="LOW",
            confidence=0.80,
            description="Multiple system discovery commands detected.",
            evidence=evidence,
        )

    def test_maps_known_category_to_taxonomy_intent(self) -> None:
        sem = self._fusion_semantic_event(category="Reconnaissance")
        contract_event = fusion_semantic_to_contract(sem, session_id="sess_test")
        assert contract_event.intent == CATEGORY_TO_INTENT["Reconnaissance"]
        assert contract_event.intent == "RECON_SYSTEM_UPTIME"

    def test_unknown_category_gets_a_deterministic_fallback_not_a_crash(self) -> None:
        sem = self._fusion_semantic_event(category="Something Novel")
        contract_event = fusion_semantic_to_contract(sem, session_id="sess_test")
        assert contract_event.intent == "SOMETHING_NOVEL"

    def test_recovers_real_evidence_id_from_payload(self) -> None:
        sem = self._fusion_semantic_event()
        contract_event = fusion_semantic_to_contract(sem, session_id="sess_test")
        assert contract_event.evidence == ["raw_abc123"]

    def test_confidence_and_session_id_pass_through(self) -> None:
        sem = self._fusion_semantic_event()
        contract_event = fusion_semantic_to_contract(sem, session_id="sess_XYZ")
        assert contract_event.confidence == 0.80
        assert contract_event.session_id == "sess_XYZ"

    def test_attck_populated_from_category_and_technique_id(self) -> None:
        sem = self._fusion_semantic_event()
        contract_event = fusion_semantic_to_contract(sem, session_id="sess_test")
        assert contract_event.attck is not None
        assert contract_event.attck.technique == "T1082"

    def test_actor_guid_is_synthetic_and_labelled_as_such(self) -> None:
        sem = self._fusion_semantic_event()
        contract_event = fusion_semantic_to_contract(sem, session_id="sess_test")
        assert contract_event.actor.guid.startswith("synthetic-")

    def test_no_evidence_still_produces_valid_semantic_event(self) -> None:
        sem = FusionSemanticEvent(
            timestamp=datetime(2026, 8, 5, 12, 0, 0),
            category="Impact",
            technique_id="T1486",
            severity="HIGH",
            confidence=0.9,
            description="no evidence case",
            evidence=[],
        )
        contract_event = fusion_semantic_to_contract(sem, session_id="sess_test")
        assert contract_event.evidence == []
        assert contract_event.actor.pid == 0
        assert contract_event.actor.image == "unknown"
