import json
from typing import List
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.enums import PolicyVerdict
from adam.db.connection import DbConnection
from adam.db.writer import DbWriter
from adam.common.timeutil import parse_iso, to_iso

class DecisionRepository:
    def __init__(self, db_conn: DbConnection, db_writer: DbWriter) -> None:
        self.db_conn = db_conn
        self.db_writer = db_writer

    def save(self, decision: PolicyDecision) -> None:
        self.db_writer.enqueue(
            """
            INSERT INTO decisions (
                decision_id, session_id, correlation_id, triggered_by,
                rule_id, rule_version, action, verdict, priority,
                parameters, rationale, decided_at, evaluation_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                decision.decision_id,
                decision.session_id,
                decision.correlation_id,
                decision.triggered_by,
                decision.rule_id,
                decision.rule_version,
                decision.action,
                decision.verdict.value,
                decision.priority,
                json.dumps(decision.parameters),
                decision.rationale,
                to_iso(decision.decided_at),
                decision.evaluation_ms
            )
        )

    async def get_decisions(self, session_id: str) -> List[PolicyDecision]:
        conn = await self.db_conn.connect()
        async with conn.execute(
            """
            SELECT 
                decision_id, session_id, correlation_id, triggered_by,
                rule_id, rule_version, action, verdict, priority,
                parameters, rationale, decided_at, evaluation_ms
            FROM decisions
            WHERE session_id = ?
            ORDER BY decided_at ASC
            """,
            (session_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            decisions = []
            for r in rows:
                decisions.append(PolicyDecision(
                    decision_id=r[0],
                    session_id=r[1],
                    correlation_id=r[2],
                    triggered_by=r[3],
                    rule_id=r[4],
                    rule_version=r[5],
                    action=r[6],
                    verdict=PolicyVerdict(r[7]),
                    priority=r[8],
                    parameters=json.loads(r[9]),
                    rationale=r[10],
                    decided_at=parse_iso(r[11]),
                    evaluation_ms=r[12]
                ))
            return decisions
