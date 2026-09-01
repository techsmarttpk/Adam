import json
from datetime import datetime
from typing import Optional
from adam.contracts.session import AnalysisSession, SampleMetadata, SessionConfig, SessionMetrics
from adam.contracts.enums import SessionStatus, DeceptionArm, NetworkMode
from adam.db.connection import DbConnection
from adam.db.writer import DbWriter
from adam.common.timeutil import parse_iso, to_iso

class SessionRepository:
    def __init__(self, db_conn: DbConnection, db_writer: DbWriter) -> None:
        self.db_conn = db_conn
        self.db_writer = db_writer

    async def save_immediate(self, session: AnalysisSession) -> None:
        conn = await self.db_conn.connect()
        await conn.execute(
            "INSERT OR IGNORE INTO experiments (experiment_id) VALUES (?)",
            (session.experiment_id,)
        )
        await conn.execute(
            """
            INSERT OR REPLACE INTO sessions (
                session_id, experiment_id, arm, sample_sha256, sample_md5,
                sample_filename, sample_size_bytes, sample_file_type,
                deception_enabled, policy_ruleset, vm_profile, timeout_seconds,
                network_mode, status, started_at, ended_at, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.session_id,
                session.experiment_id,
                session.arm.value,
                session.sample.sha256,
                session.sample.md5,
                session.sample.filename,
                session.sample.size_bytes,
                session.sample.file_type,
                1 if session.config.deception_enabled else 0,
                session.config.policy_ruleset,
                session.config.vm_profile,
                session.config.timeout_seconds,
                session.config.network_mode.value,
                session.status.value,
                to_iso(session.started_at),
                to_iso(session.ended_at) if session.ended_at else None,
                session.error
            )
        )
        await conn.execute(
            """
            INSERT OR REPLACE INTO session_metrics (
                session_id, raw_events, semantic_events, decisions_total,
                decisions_executed, mutations_applied, semantic_events_post_mutation
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.session_id,
                session.metrics.raw_events,
                session.metrics.semantic_events,
                session.metrics.decisions_total,
                session.metrics.decisions_executed,
                session.metrics.mutations_applied,
                session.metrics.semantic_events_post_mutation
            )
        )
        await conn.commit()

    def save(self, session: AnalysisSession) -> None:
        self.db_writer.enqueue(
            "INSERT OR IGNORE INTO experiments (experiment_id) VALUES (?)",
            (session.experiment_id,)
        )
        
        self.db_writer.enqueue(
            """
            INSERT OR REPLACE INTO sessions (
                session_id, experiment_id, arm, sample_sha256, sample_md5,
                sample_filename, sample_size_bytes, sample_file_type,
                deception_enabled, policy_ruleset, vm_profile, timeout_seconds,
                network_mode, status, started_at, ended_at, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.session_id,
                session.experiment_id,
                session.arm.value,
                session.sample.sha256,
                session.sample.md5,
                session.sample.filename,
                session.sample.size_bytes,
                session.sample.file_type,
                1 if session.config.deception_enabled else 0,
                session.config.policy_ruleset,
                session.config.vm_profile,
                session.config.timeout_seconds,
                session.config.network_mode.value,
                session.status.value,
                to_iso(session.started_at),
                to_iso(session.ended_at) if session.ended_at else None,
                session.error
            )
        )
        
        self.db_writer.enqueue(
            """
            INSERT OR REPLACE INTO session_metrics (
                session_id, raw_events, semantic_events, decisions_total,
                decisions_executed, mutations_applied, semantic_events_post_mutation
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.session_id,
                session.metrics.raw_events,
                session.metrics.semantic_events,
                session.metrics.decisions_total,
                session.metrics.decisions_executed,
                session.metrics.mutations_applied,
                session.metrics.semantic_events_post_mutation
            )
        )

    def update_status(self, session_id: str, status: SessionStatus,
                      ended_at: Optional[datetime] = None, error: Optional[str] = None) -> None:
        self.db_writer.enqueue(
            "UPDATE sessions SET status = ?, ended_at = ?, error = ? WHERE session_id = ?",
            (
                status.value,
                to_iso(ended_at) if ended_at else None,
                error,
                session_id
            )
        )

    def update_metrics(self, session_id: str, metrics: SessionMetrics) -> None:
        self.db_writer.enqueue(
            """
            UPDATE session_metrics SET
                raw_events = ?,
                semantic_events = ?,
                decisions_total = ?,
                decisions_executed = ?,
                mutations_applied = ?,
                semantic_events_post_mutation = ?
            WHERE session_id = ?
            """,
            (
                metrics.raw_events,
                metrics.semantic_events,
                metrics.decisions_total,
                metrics.decisions_executed,
                metrics.mutations_applied,
                metrics.semantic_events_post_mutation,
                session_id
            )
        )

    async def get(self, session_id: str) -> Optional[AnalysisSession]:
        conn = await self.db_conn.connect()
        async with conn.execute(
            """
            SELECT 
                s.session_id, s.experiment_id, s.arm, s.sample_sha256, s.sample_md5,
                s.sample_filename, s.sample_size_bytes, s.sample_file_type,
                s.deception_enabled, s.policy_ruleset, s.vm_profile, s.timeout_seconds,
                s.network_mode, s.status, s.started_at, s.ended_at, s.error,
                m.raw_events, m.semantic_events, m.decisions_total, m.decisions_executed,
                m.mutations_applied, m.semantic_events_post_mutation
            FROM sessions s
            LEFT JOIN session_metrics m ON s.session_id = m.session_id
            WHERE s.session_id = ?
            """,
            (session_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            
            sample = SampleMetadata(
                sha256=row[3],
                md5=row[4],
                filename=row[5],
                size_bytes=row[6],
                file_type=row[7]
            )
            config = SessionConfig(
                deception_enabled=bool(row[8]),
                policy_ruleset=row[9],
                vm_profile=row[10],
                timeout_seconds=row[11],
                network_mode=NetworkMode(row[12])
            )
            metrics = SessionMetrics(
                raw_events=row[17] or 0,
                semantic_events=row[18] or 0,
                decisions_total=row[19] or 0,
                decisions_executed=row[20] or 0,
                mutations_applied=row[21] or 0,
                semantic_events_post_mutation=row[22] or 0
            )
            
            return AnalysisSession(
                session_id=row[0],
                experiment_id=row[1],
                arm=DeceptionArm(row[2]),
                sample=sample,
                config=config,
                status=SessionStatus(row[13]),
                started_at=parse_iso(row[14]),
                ended_at=parse_iso(row[15]) if row[15] else None,
                metrics=metrics,
                error=row[16]
            )
