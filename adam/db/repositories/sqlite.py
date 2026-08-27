"""
adam/db/repositories/sqlite.py

SQLite-backed repositories for the Database Layer.
"""
from typing import List, Optional

import aiosqlite

from adam.contracts.session import AnalysisSession
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult
from adam.contracts.interfaces import ArtifactRef
from adam.db.interfaces import (
    ISessionRepository,
    IEventRepository,
    IDecisionRepository,
    IMutationRepository,
    IArtifactRepository,
)


class SQLiteSessionRepository(ISessionRepository):
    def __init__(self, db: aiosqlite.Connection):
        self.db = db

    async def create(self, session: AnalysisSession) -> None:
        await self.db.execute(
            "INSERT INTO sessions (session_id, experiment_id, sample_sha256, arm, status, started_at, ended_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session.session_id,
                session.experiment_id,
                session.sample.sha256,
                session.arm.value if hasattr(session.arm, "value") else str(session.arm),
                session.status.value if hasattr(session.status, "value") else str(session.status),
                session.started_at.isoformat(),
                session.ended_at.isoformat() if session.ended_at else None,
                session.model_dump_json()
            )
        )

    async def get_by_id(self, session_id: str) -> Optional[AnalysisSession]:
        async with self.db.execute("SELECT payload FROM sessions WHERE session_id = ?", (session_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return AnalysisSession.model_validate_json(row[0])
            return None

    async def update(self, session: AnalysisSession) -> None:
        await self.db.execute(
            "UPDATE sessions SET status = ?, ended_at = ?, payload = ? WHERE session_id = ?",
            (
                session.status.value if hasattr(session.status, "value") else str(session.status),
                session.ended_at.isoformat() if session.ended_at else None,
                session.model_dump_json(),
                session.session_id
            )
        )

    async def list_all(self) -> List[AnalysisSession]:
        sessions = []
        async with self.db.execute("SELECT payload FROM sessions") as cursor:
            async for row in cursor:
                sessions.append(AnalysisSession.model_validate_json(row[0]))
        return sessions


class SQLiteEventRepository(IEventRepository):
    def __init__(self, db: aiosqlite.Connection):
        self.db = db

    async def create_raw(self, event: RawEvent) -> None:
        await self.db.execute(
            "INSERT INTO raw_events (event_id, session_id, source, occurred_at, payload) VALUES (?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.session_id,
                event.source.value if hasattr(event.source, "value") else str(event.source),
                event.occurred_at.isoformat(),
                event.model_dump_json()
            )
        )

    async def get_raw_by_session(self, session_id: str) -> List[RawEvent]:
        events = []
        async with self.db.execute("SELECT payload FROM raw_events WHERE session_id = ? ORDER BY occurred_at ASC", (session_id,)) as cursor:
            async for row in cursor:
                events.append(RawEvent.model_validate_json(row[0]))
        return events

    async def create_semantic(self, event: SemanticEvent) -> None:
        await self.db.execute(
            "INSERT OR IGNORE INTO semantic_events (semantic_id, session_id, correlation_id, intent, confidence, window_start, caused_by_mutation, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.semantic_id,
                event.session_id,
                event.correlation_id,
                event.intent,
                event.confidence,
                event.window_start.isoformat(),
                event.caused_by_mutation,
                event.model_dump_json()
            )
        )

    async def get_semantic_by_session(self, session_id: str) -> List[SemanticEvent]:
        events = []
        async with self.db.execute("SELECT payload FROM semantic_events WHERE session_id = ? ORDER BY window_start ASC", (session_id,)) as cursor:
            async for row in cursor:
                events.append(SemanticEvent.model_validate_json(row[0]))
        return events


class SQLiteDecisionRepository(IDecisionRepository):
    def __init__(self, db: aiosqlite.Connection):
        self.db = db

    async def create(self, decision: PolicyDecision) -> None:
        await self.db.execute(
            "INSERT OR IGNORE INTO policy_decisions (decision_id, session_id, correlation_id, triggered_by, rule_id, verdict, decided_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                decision.decision_id,
                decision.session_id,
                decision.correlation_id,
                decision.triggered_by,
                decision.rule_id,
                decision.verdict.value if hasattr(decision.verdict, "value") else str(decision.verdict),
                decision.decided_at.isoformat(),
                decision.model_dump_json()
            )
        )

    async def get_by_session(self, session_id: str) -> List[PolicyDecision]:
        decisions = []
        async with self.db.execute("SELECT payload FROM policy_decisions WHERE session_id = ? ORDER BY decided_at ASC", (session_id,)) as cursor:
            async for row in cursor:
                decisions.append(PolicyDecision.model_validate_json(row[0]))
        return decisions


class SQLiteMutationRepository(IMutationRepository):
    def __init__(self, db: aiosqlite.Connection):
        self.db = db

    async def create(self, mutation: MutationResult) -> None:
        await self.db.execute(
            "INSERT OR IGNORE INTO mutations (mutation_id, session_id, correlation_id, decision_id, status, applied_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                mutation.mutation_id,
                mutation.session_id,
                mutation.correlation_id,
                mutation.decision_id,
                mutation.status.value if hasattr(mutation.status, "value") else str(mutation.status),
                mutation.applied_at.isoformat(),
                mutation.model_dump_json()
            )
        )

    async def get_by_session(self, session_id: str) -> List[MutationResult]:
        mutations = []
        async with self.db.execute("SELECT payload FROM mutations WHERE session_id = ? ORDER BY applied_at ASC", (session_id,)) as cursor:
            async for row in cursor:
                mutations.append(MutationResult.model_validate_json(row[0]))
        return mutations


class SQLiteArtifactRepository(IArtifactRepository):
    def __init__(self, db: aiosqlite.Connection):
        self.db = db

    async def create(self, session_id: str, artifact: ArtifactRef) -> None:
        await self.db.execute(
            "INSERT INTO artifacts (session_id, kind, path, size_bytes) VALUES (?, ?, ?, ?)",
            (
                session_id,
                artifact.kind,
                artifact.path,
                artifact.size_bytes
            )
        )

    async def get_by_session(self, session_id: str) -> List[ArtifactRef]:
        artifacts = []
        async with self.db.execute("SELECT kind, path, size_bytes FROM artifacts WHERE session_id = ? ORDER BY id ASC", (session_id,)) as cursor:
            async for row in cursor:
                artifacts.append(ArtifactRef(kind=row[0], path=row[1], size_bytes=row[2]))
        return artifacts
