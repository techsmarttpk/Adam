import pytest
import aiosqlite
from datetime import datetime, timezone

from adam.contracts.session import AnalysisSession, SampleRef, SessionConfig, SessionMetrics
from adam.contracts.enums import Arm, NetworkMode, SessionStatus, Source, Category, Verdict, ChangeKind, MutationStatus
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent, Actor
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult, Change
from adam.contracts.interfaces import ArtifactRef

from adam.db.schema import SCHEMA_SQL
from adam.db.repositories.sqlite import (
    SQLiteSessionRepository,
    SQLiteEventRepository,
    SQLiteDecisionRepository,
    SQLiteMutationRepository,
    SQLiteArtifactRepository
)

@pytest.fixture
async def db():
    async with aiosqlite.connect(":memory:") as conn:
        await conn.executescript(SCHEMA_SQL)
        yield conn

@pytest.fixture
def sample_session():
    return AnalysisSession(
        session_id="sess_123",
        experiment_id="exp_1",
        arm=Arm.CONTROL,
        sample=SampleRef(
            sha256="a"*64,
            md5="b"*32,
            filename="test.exe",
            size_bytes=1024,
            file_type="PE"
        ),
        config=SessionConfig(
            deception_enabled=False,
            policy_ruleset="default",
            vm_profile="win10",
            timeout_seconds=300,
            network_mode=NetworkMode.HOST_ONLY
        ),
        status=SessionStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        ended_at=datetime.now(timezone.utc),
        metrics=SessionMetrics()
    )

@pytest.mark.asyncio
async def test_session_repository(db, sample_session):
    repo = SQLiteSessionRepository(db)
    
    # Create
    await repo.create(sample_session)
    
    # Read
    loaded = await repo.get_by_id("sess_123")
    assert loaded is not None
    assert loaded.session_id == "sess_123"
    assert loaded.status == SessionStatus.COMPLETED
    
    # Update
    sample_session.status = SessionStatus.FAILED
    await repo.update(sample_session)
    loaded_updated = await repo.get_by_id("sess_123")
    assert loaded_updated.status == SessionStatus.FAILED
    
    # List all
    all_sessions = await repo.list_all()
    assert len(all_sessions) == 1

@pytest.mark.asyncio
async def test_event_repository_raw(db, sample_session):
    session_repo = SQLiteSessionRepository(db)
    await session_repo.create(sample_session)
    
    repo = SQLiteEventRepository(db)
    event = RawEvent(
        event_id="evt_1",
        session_id="sess_123",
        source=Source.SYSMON,
        source_event_id=1,
        category=Category.PROCESS,
        occurred_at=datetime.now(timezone.utc),
        observed_at=datetime.now(timezone.utc),
    )
    
    await repo.create_raw(event)
    loaded = await repo.get_raw_by_session("sess_123")
    assert len(loaded) == 1
    assert loaded[0].event_id == "evt_1"

@pytest.mark.asyncio
async def test_event_repository_semantic(db, sample_session):
    session_repo = SQLiteSessionRepository(db)
    await session_repo.create(sample_session)
    
    repo = SQLiteEventRepository(db)
    event = SemanticEvent(
        semantic_id="sem_1",
        session_id="sess_123",
        correlation_id="corr_1",
        intent="TEST",
        confidence=0.9,
        severity="HIGH",
        window_start=datetime.now(timezone.utc),
        window_end=datetime.now(timezone.utc),
        actor=Actor(pid=123, image="test.exe", guid="xyz"),
        detector="TestDetector"
    )
    
    await repo.create_semantic(event)
    loaded = await repo.get_semantic_by_session("sess_123")
    assert len(loaded) == 1
    assert loaded[0].semantic_id == "sem_1"

@pytest.mark.asyncio
async def test_decision_repository(db, sample_session):
    session_repo = SQLiteSessionRepository(db)
    await session_repo.create(sample_session)
    
    repo = SQLiteDecisionRepository(db)
    decision = PolicyDecision(
        decision_id="dec_1",
        session_id="sess_123",
        correlation_id="corr_1",
        triggered_by="sem_1",
        rule_id="RULE-1",
        rule_version="1.0",
        verdict=Verdict.EXECUTE,
        rationale="test"
    )
    
    await repo.create(decision)
    loaded = await repo.get_by_session("sess_123")
    assert len(loaded) == 1
    assert loaded[0].decision_id == "dec_1"

@pytest.mark.asyncio
async def test_mutation_repository(db, sample_session):
    session_repo = SQLiteSessionRepository(db)
    await session_repo.create(sample_session)
    
    repo = SQLiteMutationRepository(db)
    mutation = MutationResult(
        mutation_id="mut_1",
        session_id="sess_123",
        correlation_id="corr_1",
        decision_id="dec_1",
        primitive="FakePrimitive",
        status=MutationStatus.APPLIED,
        changes=[Change(kind=ChangeKind.REGISTRY, target="HKCU", operation="SET", value="1")]
    )
    
    await repo.create(mutation)
    loaded = await repo.get_by_session("sess_123")
    assert len(loaded) == 1
    assert loaded[0].mutation_id == "mut_1"

@pytest.mark.asyncio
async def test_artifact_repository(db, sample_session):
    session_repo = SQLiteSessionRepository(db)
    await session_repo.create(sample_session)
    
    repo = SQLiteArtifactRepository(db)
    artifact = ArtifactRef(
        kind="pcap",
        path="/tmp/test.pcap",
        size_bytes=100
    )
    
    await repo.create("sess_123", artifact)
    loaded = await repo.get_by_session("sess_123")
    assert len(loaded) == 1
    assert loaded[0].kind == "pcap"
    assert loaded[0].path == "/tmp/test.pcap"
