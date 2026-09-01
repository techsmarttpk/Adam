import json
from typing import List, Optional
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent, ActorContext, AttckContext
from adam.db.connection import DbConnection
from adam.db.writer import DbWriter
from adam.common.timeutil import parse_iso, to_iso

class EventRepository:
    def __init__(self, db_conn: DbConnection, db_writer: DbWriter) -> None:
        self.db_conn = db_conn
        self.db_writer = db_writer

    def save_raw_event(self, event: RawEvent) -> None:
        self.db_writer.enqueue(
            """
            INSERT INTO raw_event_metadata (
                event_id, session_id, source, source_event_id, category, occurred_at, observed_at, pid, image
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.session_id,
                event.source.value,
                event.source_event_id,
                event.category.value,
                to_iso(event.occurred_at),
                to_iso(event.observed_at),
                event.process.pid if event.process else None,
                event.process.image if event.process else None
            )
        )

    def save_semantic_event(self, event: SemanticEvent) -> None:
        self.db_writer.enqueue(
            """
            INSERT INTO semantic_events (
                semantic_id, session_id, correlation_id, intent, confidence, severity,
                window_start, window_end, actor_pid, actor_image, actor_guid,
                evidence, attck_tactic, attck_technique, detector, features, caused_by_mutation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.semantic_id,
                event.session_id,
                event.correlation_id,
                event.intent,
                event.confidence,
                event.severity,
                to_iso(event.window_start),
                to_iso(event.window_end),
                event.actor.pid if event.actor else None,
                event.actor.image if event.actor else None,
                event.actor.guid if event.actor else None,
                json.dumps(event.evidence),
                event.attck.tactic if event.attck else None,
                event.attck.technique if event.attck else None,
                event.detector,
                json.dumps(event.features),
                event.caused_by_mutation
            )
        )

    async def get_semantic_events(self, session_id: str) -> List[SemanticEvent]:
        conn = await self.db_conn.connect()
        async with conn.execute(
            """
            SELECT 
                semantic_id, session_id, correlation_id, intent, confidence, severity,
                window_start, window_end, actor_pid, actor_image, actor_guid,
                evidence, attck_tactic, attck_technique, detector, features, caused_by_mutation
            FROM semantic_events
            WHERE session_id = ?
            ORDER BY window_start DESC
            """,
            (session_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            events = []
            for r in rows:
                actor = None
                if r[8] is not None:
                    actor = ActorContext(pid=r[8], image=r[9], guid=r[10])
                attck = None
                if r[12] is not None:
                    attck = AttckContext(tactic=r[12], technique=r[13])
                
                events.append(SemanticEvent(
                    semantic_id=r[0],
                    session_id=r[1],
                    correlation_id=r[2],
                    intent=r[3],
                    confidence=r[4],
                    severity=r[5],
                    window_start=parse_iso(r[6]),
                    window_end=parse_iso(r[7]),
                    actor=actor,
                    evidence=json.loads(r[11]),
                    attck=attck,
                    detector=r[14],
                    features=json.loads(r[15]),
                    caused_by_mutation=r[16]
                ))
            return events

    async def get_raw_events(self, session_id: str, limit: Optional[int] = None) -> List[RawEvent]:
        conn = await self.db_conn.connect()
        query = """
            SELECT 
                event_id, session_id, source, source_event_id, category, occurred_at, observed_at, pid, image
            FROM raw_event_metadata
            WHERE session_id = ?
            ORDER BY occurred_at DESC
        """
        params = [session_id]
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        async with conn.execute(query, tuple(params)) as cursor:
            rows = await cursor.fetchall()
            events = []
            for r in rows:
                from adam.contracts.enums import EventSource, EventCategory
                from adam.contracts.raw_event import ProcessContext
                
                proc = None
                if r[7] is not None or r[8] is not None:
                    proc = ProcessContext(pid=r[7] or 0, image=r[8])
                    
                events.append(RawEvent(
                    event_id=r[0],
                    session_id=r[1],
                    source=EventSource(r[2]),
                    source_event_id=r[3],
                    category=EventCategory(r[4]),
                    occurred_at=parse_iso(r[5]),
                    observed_at=parse_iso(r[6]),
                    process=proc,
                    attributes={}
                ))
            return events
