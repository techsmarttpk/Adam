import pytest
import json
from datetime import datetime, timezone
import aiosqlite

from adam.contracts.session import AnalysisSession, SampleRef, SessionConfig, SessionMetrics
from adam.contracts.enums import Arm, SessionStatus, Verdict, MutationStatus, ChangeKind, NetworkMode
from adam.contracts.semantic_event import SemanticEvent, Actor, AttckRef
from adam.contracts.mutation import MutationResult, Change
from adam.db.repositories.sqlite import SQLiteSessionRepository, SQLiteEventRepository, SQLiteDecisionRepository, SQLiteMutationRepository
from adam.reporting.generator import ReportGenerator

@pytest.fixture
async def db_conn():
    conn = await aiosqlite.connect(":memory:")
    # Initialize schema
    await conn.execute("CREATE TABLE sessions (session_id TEXT PRIMARY KEY, experiment_id TEXT, sample_sha256 TEXT, arm TEXT, status TEXT, started_at TEXT, ended_at TEXT, payload TEXT)")
    await conn.execute("CREATE TABLE raw_events (event_id TEXT PRIMARY KEY, session_id TEXT, source TEXT, occurred_at TEXT, payload TEXT)")
    await conn.execute("CREATE TABLE semantic_events (semantic_id TEXT PRIMARY KEY, session_id TEXT, correlation_id TEXT, intent TEXT, confidence REAL, window_start TEXT, caused_by_mutation TEXT, payload TEXT)")
    await conn.execute("CREATE TABLE policy_decisions (decision_id TEXT PRIMARY KEY, session_id TEXT, correlation_id TEXT, triggered_by TEXT, rule_id TEXT, verdict TEXT, decided_at TEXT, payload TEXT)")
    await conn.execute("CREATE TABLE mutations (mutation_id TEXT PRIMARY KEY, session_id TEXT, correlation_id TEXT, decision_id TEXT, status TEXT, applied_at TEXT, payload TEXT)")
    await conn.commit()
    yield conn
    await conn.close()

@pytest.fixture
def repos(db_conn):
    return {
        "session": SQLiteSessionRepository(db_conn),
        "event": SQLiteEventRepository(db_conn),
        "decision": SQLiteDecisionRepository(db_conn),
        "mutation": SQLiteMutationRepository(db_conn),
    }

@pytest.fixture
def generator(repos):
    return ReportGenerator(
        session_repo=repos["session"],
        event_repo=repos["event"],
        decision_repo=repos["decision"],
        mutation_repo=repos["mutation"],
        plausibility_warn_below=0.5
    )

def _make_session(sid, eid, arm):
    return AnalysisSession(
        session_id=sid,
        experiment_id=eid,
        arm=arm,
        sample=SampleRef(sha256="a"*64, md5="b"*32, size_bytes=100, filename="test.exe", file_type="binary"),
        config=SessionConfig(deception_enabled=True, policy_ruleset="default", vm_profile="win10", timeout_seconds=300, network_mode=NetworkMode.SIMULATED),
        status=SessionStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        metrics=SessionMetrics()
    )

def _make_semantic_event(sid, intent, mutation_id=None, network=None, tactic="TA0001", technique="T1001"):
    actor = Actor(pid=100, image="test.exe", guid="{guid}")
    attck = AttckRef(tactic=tactic, technique=technique)
    features = {}
    if network:
        features["network_endpoint"] = network
        
    return SemanticEvent(
        semantic_id=f"sem_{intent}_{sid}",
        session_id=sid,
        correlation_id="corr",
        intent=intent,
        confidence=0.8,
        severity="HIGH",
        window_start=datetime.now(timezone.utc),
        window_end=datetime.now(timezone.utc),
        actor=actor,
        attck=attck,
        detector="TestDetector",
        features=features,
        caused_by_mutation=mutation_id
    )

@pytest.mark.asyncio
async def test_single_session_report(generator, repos):
    # Create session
    await repos["session"].create(_make_session("sess1", "exp1", Arm.TREATMENT))
    
    # Add mutation with plausibility < 0.5 to trigger detection risk
    mut = MutationResult(
        mutation_id="mut1",
        session_id="sess1",
        correlation_id="corr",
        decision_id="dec1",
        primitive="FakeRegistryKey",
        status=MutationStatus.APPLIED,
        plausibility_score=0.2, # LOW PLAUSIBILITY
        changes=[Change(kind=ChangeKind.REGISTRY, target="HKLM/Run", operation="SET", value="bad.exe")]
    )
    await repos["mutation"].create(mut)
    
    # Add semantic event
    ev = _make_semantic_event("sess1", "PERSIST_RUN_KEY")
    await repos["event"].create_semantic(ev)
    
    # Generate report
    report_json = await generator.generate("sess1", format="json")
    report = json.loads(report_json)
    
    assert report["session_id"] == "sess1"
    assert report["experiment_id"] == "exp1"
    assert "TA0001 / T1001" in report["attck_coverage"]

    
    # Detection risk should contain mut1
    assert len(report["detection_risk"]) == 1
    assert report["detection_risk"][0]["mutation_id"] == "mut1"
    # IOCs should be extracted (both mutation and semantic event)
    assert len(report["iocs"]) == 2
    assert any(i["target"] == "HKLM/Run" for i in report["iocs"])
    assert any(i["source"] == "semantic_event" for i in report["iocs"])

    
@pytest.mark.asyncio
async def test_yield_comparison_math(generator, repos):
    # Set up experiment with control and treatment
    await repos["session"].create(_make_session("ctrl", "exp_yield", Arm.CONTROL))
    await repos["session"].create(_make_session("trt", "exp_yield", Arm.TREATMENT))
    
    # Treatment events:
    # 2 post-mutation events, 1 new intent, 1 new network
    t_ev1 = _make_semantic_event("trt", "INTENT_A", mutation_id="mut_x", network="1.1.1.1")
    t_ev2 = _make_semantic_event("trt", "INTENT_B", mutation_id="mut_x", network="2.2.2.2")
    await repos["event"].create_semantic(t_ev1)
    await repos["event"].create_semantic(t_ev2)
    
    # Control events:
    # 1 post-mutation event (simulating a false positive or baseline behavior), 1 intent, 1 network
    c_ev1 = _make_semantic_event("ctrl", "INTENT_A", mutation_id="mut_y", network="1.1.1.1")
    await repos["event"].create_semantic(c_ev1)
    
    report_json = await generator.generate_comparison("exp_yield")
    report = json.loads(report_json)
    
    assert report["experiment_id"] == "exp_yield"
    # Delta events: Treatment (2) - Control (1) = 1
    assert report["delta_semantic_events"] == 1
    
    # Distinct Intents Yield: INTENT_B should be new
    assert "INTENT_B" in report["distinct_intents_yield"]
    assert "INTENT_A" not in report["distinct_intents_yield"]
    
    # Distinct Networks Yield: 2.2.2.2 should be new
    assert "2.2.2.2" in report["distinct_networks_yield"]
    assert "1.1.1.1" not in report["distinct_networks_yield"]
