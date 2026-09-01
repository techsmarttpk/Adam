import pytest
import os
import json
import asyncio
from datetime import datetime, timezone
from adam.contracts.enums import EventCategory, EventSource, PolicyVerdict, MutationStatus
from adam.contracts.raw_event import RawEvent, ProcessContext
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.mutation import MutationResult, MutationChange
from adam.deception.explainer import explain_mutation
from adam.api.routers.mutation_tests import (
    MANIFEST_PATH, EXE_PATH, _generate_test_raw_events, _ACTIVE_TEST_SESSIONS
)

def test_manifest_schema_and_commands():
    assert os.path.exists(MANIFEST_PATH), "manifest.json must exist"
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert "commands" in manifest
    assert len(manifest["commands"]) >= 15

    severities = set()
    for cmd in manifest["commands"]:
        assert "id" in cmd
        assert "name" in cmd
        assert "severity" in cmd
        assert "expected_intent" in cmd
        assert "expected_policy_action" in cmd
        severities.add(cmd["severity"])

    assert "CRITICAL" in severities
    assert "HIGH" in severities
    assert "MEDIUM" in severities
    assert "LOW" in severities
    assert "OBSERVE" in severities

def test_compiled_executable_exists_and_runs():
    assert os.path.exists(EXE_PATH), f"adam_mutation_test.exe must be present at {EXE_PATH}"
    assert os.path.getsize(EXE_PATH) > 0

def test_test_mode_isolation():
    # Ordinary session ID should not be in active test sessions
    ordinary_session_id = "sess_regular_prod_001"
    assert ordinary_session_id not in _ACTIVE_TEST_SESSIONS

    # Only explicitly injected test sessions are registered
    test_session_id = "sess_test_12345"
    _ACTIVE_TEST_SESSIONS[test_session_id] = {
        "session_id": test_session_id,
        "mutation_test_mode": True
    }
    assert _ACTIVE_TEST_SESSIONS[test_session_id]["mutation_test_mode"] is True

    # Teardown
    del _ACTIVE_TEST_SESSIONS[test_session_id]

def test_mutation_explainer_structured_representation():
    now = datetime.now(timezone.utc)
    mut = MutationResult(
        mutation_id="mut_dc_001",
        session_id="sess_test",
        correlation_id="corr_test",
        decision_id="dec_dc_001",
        primitive="SPAWN_FAKE_DC_ARTIFACTS",
        status=MutationStatus.APPLIED,
        applied_at=now,
        latency_ms=124.5,
        changes=[
            MutationChange(kind="REGISTRY", target="HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Domain", operation="SET", value="CORP.LOCAL"),
            MutationChange(kind="NETWORK", target="dns:DC01.CORP.LOCAL", operation="RESPOND", value="10.0.0.10"),
            MutationChange(kind="FILE", target="C:\\Windows\\SYSVOL\\sysvol\\CORP.LOCAL\\", operation="CREATE")
        ],
        plausibility_score=0.92,
        plausibility_notes="Fake DC structured"
    )

    explanation = explain_mutation(mut)
    assert explanation["title"] == "Generated Domain Environment"
    assert explanation["status"] == "APPLIED"
    assert "CORP.LOCAL" in explanation["artifacts"]["Domain"]
    assert "DC01.CORP.LOCAL" in explanation["artifacts"]["Domain Controller"]
    assert "10.0.0.10" in explanation["artifacts"]["Address"]

def test_generate_test_raw_events():
    now = datetime.now(timezone.utc)
    cmd_info = {
        "id": "high_recon_dc",
        "name": "Domain Controller Discovery",
        "severity": "HIGH",
        "expected_intent": "RECON_DOMAIN_CONTROLLER",
        "expected_policy_action": "SPAWN_FAKE_DC_ARTIFACTS"
    }

    events = _generate_test_raw_events("sess_test_99", cmd_info, now)
    assert len(events) >= 1
    assert events[0].session_id == "sess_test_99"
    assert "nltest" in (events[0].process.command_line or "").lower()
