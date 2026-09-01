import pytest
import asyncio
from datetime import datetime, timezone
from typing import Any
from adam.contracts.enums import EventSource, EventCategory, DeceptionArm, SessionStatus, NetworkMode
from adam.contracts.session import AnalysisSession, SampleMetadata, SessionConfig, SessionMetrics
from adam.contracts.raw_event import RawEvent, ProcessContext
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult
from adam.common.bus import EventBus
from adam.common.config import load_settings
from adam.db.connection import DbConnection
from adam.db.writer import DbWriter
from adam.db.repositories.sessions import SessionRepository
from adam.db.repositories.events import EventRepository
from adam.db.repositories.decisions import DecisionRepository
from adam.db.repositories.mutations import MutationRepository
from adam.fusion.engine import FusionEngine
from adam.policy.engine import PolicyEngine
from adam.deception.engine import DeceptionEngine
from adam.orchestrator.session import SessionRunner

class MockSandboxController:
    def __init__(self) -> None:
        self.session_id = None
        self.mutations = []

    def set_session_id(self, session_id: str) -> None:
        self.session_id = session_id

    async def prepare(self) -> None:
        pass

    async def detonate(self, sample_path: str) -> None:
        pass

    async def apply_mutation(self, decision) -> Any:
        from adam.contracts.mutation import MutationResult, MutationChange
        from adam.contracts.enums import MutationStatus
        from adam.common.timeutil import now_utc
        
        change = MutationChange(kind="REGISTRY", target="HKLM\\fake", operation="SET", value="mock")
        res = MutationResult(
            mutation_id=f"mut_{decision.decision_id[4:]}",
            session_id=decision.session_id,
            correlation_id=decision.correlation_id,
            decision_id=decision.decision_id,
            primitive=decision.action,
            status=MutationStatus.APPLIED,
            applied_at=now_utc(),
            latency_ms=10.0,
            changes=[change],
            plausibility_score=0.9,
            plausibility_notes="mock applied",
            revertible=True,
            causal_window_ms=30000,
            error=None
        )
        self.mutations.append(res)
        return res

    async def collect_artifacts(self) -> None:
        pass

    async def teardown(self) -> None:
        pass

@pytest.mark.asyncio
async def test_replay_pipeline():
    settings = load_settings()
    settings.db.path = "artifacts/test_adam.sqlite"
    
    bus = EventBus()
    db_conn = DbConnection(settings.db)
    db_writer = DbWriter(db_conn, settings.db)
    
    session_repo = SessionRepository(db_conn, db_writer)
    event_repo = EventRepository(db_conn, db_writer)
    decision_repo = DecisionRepository(db_conn, db_writer)
    mutation_repo = MutationRepository(db_conn, db_writer)
    
    mock_sandbox = MockSandboxController()
    fusion = FusionEngine(settings.fusion, bus)
    policy = PolicyEngine(settings.policy, bus)
    deception = DeceptionEngine(mock_sandbox, bus)
    
    await db_conn.connect()
    await db_writer.start()
    await bus.start()
    
    session_id = "sess_test_123"
    sample = SampleMetadata(
        sha256="test_sha256", md5="test_md5", filename="malware.exe", size_bytes=100, file_type="PE"
    )
    config = SessionConfig(
        deception_enabled=True,
        policy_ruleset=settings.policy.ruleset_path,
        vm_profile="test",
        timeout_seconds=2,
        network_mode=NetworkMode.SIMULATED
    )
    session = AnalysisSession(
        session_id=session_id,
        experiment_id="exp_test",
        arm=DeceptionArm.TREATMENT,
        sample=sample,
        config=config,
        status=SessionStatus.PENDING,
        started_at=datetime.now(timezone.utc),
        metrics=SessionMetrics()
    )
    
    runner = SessionRunner(
        session=session,
        bus=bus,
        sandbox=mock_sandbox,
        fusion=fusion,
        policy=policy,
        deception=deception,
        session_repo=session_repo,
        event_repo=event_repo,
        decision_repo=decision_repo,
        mutation_repo=mutation_repo
    )
    
    subs = []
    subs.append(bus.subscribe(RawEvent, runner._handle_raw_event, name="test-raw"))
    subs.append(bus.subscribe(SemanticEvent, runner._handle_semantic_event, name="test-sem"))
    subs.append(bus.subscribe(PolicyDecision, runner._handle_decision, name="test-dec"))
    subs.append(bus.subscribe(MutationResult, runner._handle_mutation, name="test-mut"))
    
    raw_event = RawEvent(
        event_id="raw_event_test_01",
        session_id=session_id,
        source=EventSource.SYSMON,
        source_event_id=13,
        category=EventCategory.REGISTRY,
        occurred_at=datetime.now(timezone.utc),
        observed_at=datetime.now(timezone.utc),
        process=ProcessContext(pid=1234, image="malware.exe"),
        attributes={"target_object": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Domain", "details": "QueryValue"}
    )
    
    await bus.publish(raw_event)
    await bus.drain(timeout=2.0)
    
    assert runner.raw_count == 1
    assert runner.sem_count == 1
    assert runner.dec_count == 1
    assert runner.mut_count == 1
    
    for s in subs:
        s.task.cancel()
    await bus.stop()
    await db_writer.stop()
    await db_conn.disconnect()
