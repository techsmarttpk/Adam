import json
from typing import List
from adam.contracts.mutation import MutationResult, MutationChange
from adam.contracts.enums import MutationStatus
from adam.db.connection import DbConnection
from adam.db.writer import DbWriter
from adam.common.timeutil import parse_iso, to_iso

class MutationRepository:
    def __init__(self, db_conn: DbConnection, db_writer: DbWriter) -> None:
        self.db_conn = db_conn
        self.db_writer = db_writer

    def save(self, mutation: MutationResult) -> None:
        changes_dict = [c.model_dump() for c in mutation.changes]
        self.db_writer.enqueue(
            """
            INSERT INTO mutations (
                mutation_id, session_id, correlation_id, decision_id,
                primitive, status, applied_at, latency_ms, changes,
                plausibility_score, plausibility_notes, revertible,
                causal_window_ms, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                mutation.mutation_id,
                mutation.session_id,
                mutation.correlation_id,
                mutation.decision_id,
                mutation.primitive,
                mutation.status.value,
                to_iso(mutation.applied_at),
                mutation.latency_ms,
                json.dumps(changes_dict),
                mutation.plausibility_score,
                mutation.plausibility_notes,
                1 if mutation.revertible else 0,
                mutation.causal_window_ms,
                mutation.error
            )
        )

    async def get_mutations(self, session_id: str) -> List[MutationResult]:
        conn = await self.db_conn.connect()
        async with conn.execute(
            """
            SELECT 
                mutation_id, session_id, correlation_id, decision_id,
                primitive, status, applied_at, latency_ms, changes,
                plausibility_score, plausibility_notes, revertible,
                causal_window_ms, error
            FROM mutations
            WHERE session_id = ?
            ORDER BY applied_at ASC
            """,
            (session_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            mutations = []
            for r in rows:
                changes_list = json.loads(r[8])
                changes = [MutationChange(**c) for c in changes_list]
                
                mutations.append(MutationResult(
                    mutation_id=r[0],
                    session_id=r[1],
                    correlation_id=r[2],
                    decision_id=r[3],
                    primitive=r[4],
                    status=MutationStatus(r[5]),
                    applied_at=parse_iso(r[6]),
                    latency_ms=r[7],
                    changes=changes,
                    plausibility_score=r[9],
                    plausibility_notes=r[10],
                    revertible=bool(r[11]),
                    causal_window_ms=r[12],
                    error=r[13]
                ))
            return mutations
