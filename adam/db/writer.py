"""
adam/db/writer.py

Asynchronous Database Writer (ARCHITECTURE.md section 5.7).
Subscribes to the EventBus and writes records to SQLite in batches.
"""
import asyncio
import logging
from collections import deque
from typing import Any

import aiosqlite

from adam.common.bus import EventBus
from adam.contracts.envelope import Envelope
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult
from adam.db.repositories.sqlite import (
    SQLiteSessionRepository,
    SQLiteEventRepository,
    SQLiteDecisionRepository,
    SQLiteMutationRepository
)

logger = logging.getLogger(__name__)

class DBWriter:
    def __init__(
        self,
        db: aiosqlite.Connection,
        bus: EventBus,
        max_queue_size: int = 10000,
        batch_size: int = 100,
        flush_interval_s: float = 1.0
    ):
        self.db = db
        self.bus = bus
        self.max_queue_size = max_queue_size
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        
        self.queue: deque[Envelope[Any]] = deque()
        self.item_added = asyncio.Event()
        self.task: asyncio.Task[None] | None = None
        self.dropped_raw_events = 0
        
        self.session_repo = SQLiteSessionRepository(db)
        self.event_repo = SQLiteEventRepository(db)
        self.decision_repo = SQLiteDecisionRepository(db)
        self.mutation_repo = SQLiteMutationRepository(db)

    def _enqueue(self, envelope: Envelope[Any]) -> None:
        if len(self.queue) >= self.max_queue_size:
            # Shedding: try to shed a low-value RawEvent from the left of the queue
            shed = False
            for i in range(len(self.queue)):
                if isinstance(self.queue[i].payload, RawEvent):
                    del self.queue[i]
                    self.dropped_raw_events += 1
                    logger.warning(
                        "QueueOverflow: Shed low-value RawEvent to make room in DBWriter queue. Total dropped: %d",
                        self.dropped_raw_events
                    )
                    shed = True
                    break
            
            if not shed:
                # If we couldn't shed a RawEvent, and this incoming event is a RawEvent, drop it.
                if isinstance(envelope.payload, RawEvent):
                    self.dropped_raw_events += 1
                    logger.warning(
                        "QueueOverflow: DBWriter queue full of high-priority events, dropping incoming RawEvent. Total dropped: %d",
                        self.dropped_raw_events
                    )
                    return
                else:
                    logger.warning("DBWriter queue overflowed with high-value events; expanding queue temporarily.")
        
        self.queue.append(envelope)
        self.item_added.set()

    async def _handler(self, envelope: Envelope[Any]) -> None:
        self._enqueue(envelope)

    def start(self) -> None:
        """Subscribe to the bus and start the writer task."""
        self.bus.subscribe(RawEvent, self._handler, name="db_writer_raw")
        self.bus.subscribe(SemanticEvent, self._handler, name="db_writer_semantic")
        self.bus.subscribe(PolicyDecision, self._handler, name="db_writer_decision")
        self.bus.subscribe(MutationResult, self._handler, name="db_writer_mutation")
        
        try:
            from adam.orchestrator.session import SessionLifecycle
            self.bus.subscribe(SessionLifecycle, self._handler, name="db_writer_session")
        except ImportError:
            pass
            
        self.task = asyncio.create_task(self._write_loop(), name="adam.db.writer")

    async def _write_loop(self) -> None:
        while True:
            try:
                await asyncio.wait_for(self.item_added.wait(), timeout=self.flush_interval_s)
            except asyncio.TimeoutError:
                pass # Flush interval reached, flush what we have
            except asyncio.CancelledError:
                break
                
            self.item_added.clear()
            await self.flush()

    async def flush(self) -> None:
        if not self.queue:
            return
            
        batch = []
        while self.queue and len(batch) < self.batch_size:
            batch.append(self.queue.popleft())
            
        if not batch:
            return
            
        try:
            for env in batch:
                payload = env.payload
                if isinstance(payload, RawEvent):
                    await self.event_repo.create_raw(payload)
                elif isinstance(payload, SemanticEvent):
                    await self.event_repo.create_semantic(payload)
                elif isinstance(payload, PolicyDecision):
                    await self.decision_repo.create(payload)
                elif isinstance(payload, MutationResult):
                    await self.mutation_repo.create(payload)
                elif type(payload).__name__ == "SessionLifecycle":
                    # For SessionLifecycle, we might want to log it or update a session
                    # But if the orchestrator is already creating/updating the session directly
                    # via SessionRepo, we could do nothing. We'll simply ignore it for DB insertion.
                    pass
            await self.db.commit()
        except Exception:
            await self.db.rollback()
            logger.exception("DBWriter failed to commit batch, rolling back.")

    async def stop(self) -> None:
        """Stop the writer task and flush remaining items."""
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
            self.task = None
            
        while self.queue:
            await self.flush()
