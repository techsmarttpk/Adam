import asyncio
import pytest
import aiosqlite
from datetime import datetime, timezone

from adam.common.bus import EventBus
from adam.contracts.envelope import Envelope
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent, Actor
from adam.contracts.enums import Source, Category

from adam.db.schema import SCHEMA_SQL
from adam.db.writer import DBWriter

@pytest.fixture
async def db():
    async with aiosqlite.connect(":memory:") as conn:
        await conn.executescript(SCHEMA_SQL)
        yield conn

@pytest.fixture
def raw_envelope():
    return Envelope(
        envelope_version="1.0",
        message_id="msg1",
        message_type="RawEvent",
        session_id="sess_1",
        correlation_id="corr_1",
        emitted_at=datetime.now(timezone.utc),
        emitter="test",
        payload=RawEvent(
            event_id="evt_1",
            session_id="sess_1",
            source=Source.SYSMON,
            source_event_id=1,
            category=Category.PROCESS,
            occurred_at=datetime.now(timezone.utc),
            observed_at=datetime.now(timezone.utc)
        )
    )

@pytest.fixture
def semantic_envelope():
    return Envelope(
        envelope_version="1.0",
        message_id="msg2",
        message_type="SemanticEvent",
        session_id="sess_1",
        correlation_id="corr_1",
        emitted_at=datetime.now(timezone.utc),
        emitter="test",
        payload=SemanticEvent(
            semantic_id="sem_1",
            session_id="sess_1",
            correlation_id="corr_1",
            intent="TEST",
            confidence=0.9,
            severity="HIGH",
            window_start=datetime.now(timezone.utc),
            window_end=datetime.now(timezone.utc),
            actor=Actor(pid=123, image="test", guid="test"),
            detector="test"
        )
    )

@pytest.mark.asyncio
async def test_writer_backpressure_shedding(db, raw_envelope, semantic_envelope):
    bus = EventBus()
    # Tiny queue to test shedding
    writer = DBWriter(db, bus, max_queue_size=2, batch_size=2, flush_interval_s=1.0)
    
    # We do not start the writer task so we can control the queue filling
    # Manually enqueue to bypass the bus delay
    writer._enqueue(raw_envelope)
    writer._enqueue(raw_envelope)
    
    assert len(writer.queue) == 2
    assert writer.dropped_raw_events == 0
    
    # Enqueue a SemanticEvent when the queue is full.
    # It should shed one of the RawEvents.
    writer._enqueue(semantic_envelope)
    
    assert len(writer.queue) == 2
    assert writer.dropped_raw_events == 1
    # Check that the last element is the SemanticEvent
    assert isinstance(writer.queue[-1].payload, SemanticEvent)
    
    # Enqueue another RawEvent, since it's lower priority and queue is full,
    # it should shed the old RawEvent and add the new one, OR drop the incoming.
    # Our implementation sheds the leftmost RawEvent.
    writer._enqueue(raw_envelope)
    assert len(writer.queue) == 2
    assert writer.dropped_raw_events == 2
    
    # Enqueue a SemanticEvent again. The queue now has 1 Raw and 1 Semantic.
    # It should shed the last RawEvent.
    writer._enqueue(semantic_envelope)
    assert len(writer.queue) == 2
    assert writer.dropped_raw_events == 3
    
    # Queue is now 2 SemanticEvents (high priority).
    # Enqueue a RawEvent. It should be dropped immediately.
    writer._enqueue(raw_envelope)
    assert len(writer.queue) == 2
    assert writer.dropped_raw_events == 4
    for env in writer.queue:
        assert isinstance(env.payload, SemanticEvent)

@pytest.mark.asyncio
async def test_writer_batching_and_flush(db, semantic_envelope):
    bus = EventBus()
    writer = DBWriter(db, bus, max_queue_size=10, batch_size=5, flush_interval_s=0.1)
    writer.start()
    await bus.start()
    
    # Create the session first to satisfy foreign key
    await db.execute(
        "INSERT INTO sessions (session_id, experiment_id, sample_sha256, arm, status, started_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("sess_1", "exp", "sha", "CONTROL", "COMPLETED", datetime.now(timezone.utc).isoformat(), "{}")
    )
    
    # Publish a semantic event through the bus
    await bus.publish(semantic_envelope)
    
    # Wait for the flush interval
    await asyncio.sleep(0.3)
    
    # Check database
    events = await writer.event_repo.get_semantic_by_session("sess_1")
    assert len(events) == 1
    
    await writer.stop()

