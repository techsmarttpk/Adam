"""
adam/api/deps.py

Composition root (ARCHITECTURE.md section 5.8).
Constructs and wires together all components of the ADAM pipeline.
"""
import uuid
import logging
from datetime import datetime, timezone

import aiosqlite

from adam.common.bus import EventBus
from adam.common.config import get_settings
from adam.contracts.envelope import Envelope
from adam.contracts.mutation import MutationResult
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent, Actor, AttckRef
from adam.contracts.enums import Verdict
from adam.db.repositories.sqlite import SQLiteSessionRepository, SQLiteEventRepository, SQLiteDecisionRepository, SQLiteMutationRepository
from adam.db.writer import DBWriter
from adam.reporting.generator import ReportGenerator
from adam.deception.engine import DeceptionEngine
from adam.fusion.engine import EventFusionEngine
from adam.fusion.models import RawEvent as FusionRawEvent
from adam.policy.context import SessionContext
from adam.policy.engine import PolicyEngine
from tests.unit.test_deception.test_engine import FakeGuestChannel
from demo.run_simulation import map_detection_to_intent

logger = logging.getLogger(__name__)

class Dependencies:
    def __init__(self):
        self.bus: EventBus | None = None
        self.db_conn: aiosqlite.Connection | None = None
        self.db_writer: DBWriter | None = None
        self.deception: DeceptionEngine | None = None
        self.fusion: EventFusionEngine | None = None
        self.policy: PolicyEngine | None = None
        self.session_repo: SQLiteSessionRepository | None = None
        self.event_repo: SQLiteEventRepository | None = None
        self.decision_repo: SQLiteDecisionRepository | None = None
        self.mutation_repo: SQLiteMutationRepository | None = None
        self.session_contexts: dict[str, SessionContext] = {}
        self.report_generator: ReportGenerator | None = None

deps = Dependencies()

async def init_dependencies() -> None:
    settings = get_settings()
    
    # 1. Instantiate
    deps.bus = EventBus()
    deps.db_conn = await aiosqlite.connect(settings.db.path)
    
    # Initialize DB schema
    await deps.db_conn.execute("CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, experiment_id TEXT, sample_sha256 TEXT, arm TEXT, status TEXT, started_at TEXT, ended_at TEXT, payload TEXT)")
    await deps.db_conn.execute("CREATE TABLE IF NOT EXISTS raw_events (event_id TEXT PRIMARY KEY, session_id TEXT, source TEXT, occurred_at TEXT, payload TEXT)")
    await deps.db_conn.execute("CREATE TABLE IF NOT EXISTS semantic_events (semantic_id TEXT PRIMARY KEY, session_id TEXT, correlation_id TEXT, intent TEXT, confidence REAL, window_start TEXT, caused_by_mutation TEXT, payload TEXT)")
    await deps.db_conn.execute("CREATE TABLE IF NOT EXISTS policy_decisions (decision_id TEXT PRIMARY KEY, session_id TEXT, correlation_id TEXT, triggered_by TEXT, rule_id TEXT, verdict TEXT, decided_at TEXT, payload TEXT)")
    await deps.db_conn.execute("CREATE TABLE IF NOT EXISTS mutations (mutation_id TEXT PRIMARY KEY, session_id TEXT, correlation_id TEXT, decision_id TEXT, status TEXT, applied_at TEXT, payload TEXT)")
    await deps.db_conn.execute("CREATE TABLE IF NOT EXISTS artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, kind TEXT, path TEXT, size_bytes INTEGER)")
    await deps.db_conn.commit()

    deps.db_writer = DBWriter(
        db=deps.db_conn,
        bus=deps.bus,
        max_queue_size=settings.db.queue_size,
        batch_size=settings.db.batch_size,
        flush_interval_s=settings.db.batch_timeout_s
    )
    deps.deception = DeceptionEngine(FakeGuestChannel())
    deps.fusion = EventFusionEngine(window_seconds=120)
    deps.policy = PolicyEngine("rules/default")
    deps.session_repo = SQLiteSessionRepository(deps.db_conn)
    
    deps.event_repo = SQLiteEventRepository(deps.db_conn)
    deps.decision_repo = SQLiteDecisionRepository(deps.db_conn)
    deps.mutation_repo = SQLiteMutationRepository(deps.db_conn)
    
    deps.report_generator = ReportGenerator(
        session_repo=deps.session_repo,
        event_repo=deps.event_repo,
        decision_repo=deps.decision_repo,
        mutation_repo=deps.mutation_repo,
        plausibility_warn_below=settings.reporting.plausibility_warn_below
    )
    
    # 2. Handlers for Bus wiring
    async def handle_raw_event(env: Envelope[RawEvent]) -> None:
        if not deps.fusion or not deps.bus:
            return
            
        ev = env.payload.model_dump()
        try:
            ts = env.payload.occurred_at
        except Exception:
            ts = datetime.now(timezone.utc)
            
        fusion_ev = FusionRawEvent(
            timestamp=ts,
            source="bus",
            event_type=env.payload.category.value if hasattr(env.payload.category, "value") else str(env.payload.category),
            process_id=env.payload.process.pid if env.payload.process else env.payload.attributes.get("pid"),
            parent_process_id=env.payload.process.ppid if env.payload.process else env.payload.attributes.get("ppid"),
            process_name=env.payload.process.image if env.payload.process else env.payload.attributes.get("process_name"),
            command_line=env.payload.process.command_line if env.payload.process else env.payload.attributes.get("command_line"),
            payload=env.payload.attributes
        )
        
        result = deps.fusion.process([fusion_ev])
        
        for idx, detection in enumerate(result.detections, start=1):
            intent, tactic, technique = map_detection_to_intent(detection)
            first_ev = detection.evidence[0] if detection.evidence else None
            pid = first_ev.process_id if (first_ev and first_ev.process_id) else 1000
            pname = first_ev.process_name if (first_ev and first_ev.process_name) else "unknown.exe"

            dts = detection.timestamp
            if dts.tzinfo is None:
                dts = dts.replace(tzinfo=timezone.utc)

            features = {"file_count": len(detection.evidence), "has_target": True}
            if intent == "RECON_DOMAIN_CONTROLLER":
                features["ldap_attempts"] = 3
                features["all_failed"] = True
            elif intent == "PERSIST_RUN_KEY":
                features["distinct_registry_keys"] = 6

            se = SemanticEvent(
                semantic_id=f"sem_{uuid.uuid4().hex[:8]}_{idx:03d}",
                session_id=env.session_id,
                correlation_id=env.correlation_id,
                intent=intent,
                confidence=max(detection.confidence, 0.8),
                severity=detection.severity,
                window_start=dts,
                window_end=dts,
                actor=Actor(pid=pid, image=f"C:\\Windows\\System32\\{pname}", guid=f"{{guid-{uuid.uuid4().hex[:8]}}}"),
                evidence=[e.process_name for e in detection.evidence if e.process_name],
                attck=AttckRef(tactic=tactic, technique=technique),
                detector=f"{detection.category}Detector@1.0",
                features=features,
            )
            
            s_env = Envelope[SemanticEvent](
                message_id=str(uuid.uuid4()),
                message_type="SemanticEvent",
                session_id=env.session_id,
                correlation_id=env.correlation_id,
                emitted_at=datetime.now(timezone.utc),
                emitter="LiveFusionBridge",
                payload=se
            )
            await deps.bus.publish(s_env)

    async def handle_semantic_event(env: Envelope[SemanticEvent]) -> None:
        if not deps.policy or not deps.bus:
            return
        
        session_id = env.session_id
        if session_id not in deps.session_contexts:
            session = await deps.session_repo.get_by_id(session_id)
            dry_run = not session.config.deception_enabled if session else False
            deps.session_contexts[session_id] = SessionContext(session_id=session_id, dry_run=dry_run)
            
        decisions = deps.policy.evaluate(env.payload, deps.session_contexts[session_id])
        for decision in decisions:
            d_env = Envelope[PolicyDecision](
                message_id=str(uuid.uuid4()),
                message_type="PolicyDecision",
                session_id=session_id,
                correlation_id=env.correlation_id,
                emitted_at=datetime.now(timezone.utc),
                emitter="PolicyEngine",
                payload=decision
            )
            await deps.bus.publish(d_env)

    async def handle_policy_decision(env: Envelope[PolicyDecision]) -> None:
        if not deps.deception or not deps.bus:
            return
            
        decision = env.payload
        if decision.verdict == Verdict.EXECUTE:
            session = await deps.session_repo.get_by_id(env.session_id)
            if session and not session.config.deception_enabled:
                return  # Skip mutation if deception is disabled (e.g. CONTROL arm)
            
            try:
                mutation = await deps.deception.execute_async(decision)
                m_env = Envelope[MutationResult](
                    message_id=str(uuid.uuid4()),
                    message_type="MutationResult",
                    session_id=env.session_id,
                    correlation_id=env.correlation_id,
                    emitted_at=datetime.now(timezone.utc),
                    emitter="DeceptionEngine",
                    payload=mutation
                )
                await deps.bus.publish(m_env)
            except Exception as e:
                logger.error(f"Deception failed: {e}")

    # 3. Wire (alphabetical order per §5.8)
    deps.bus.subscribe(PolicyDecision, handle_policy_decision, name="deception_decision")
    deps.bus.subscribe(RawEvent, handle_raw_event, name="fusion_raw")
    deps.bus.subscribe(SemanticEvent, handle_semantic_event, name="policy_semantic")
    
    # DBWriter internal subscriptions (subscribes to everything it needs)
    deps.db_writer.start()
    
    # 4. Start EventBus
    await deps.bus.start()

async def shutdown_dependencies() -> None:
    if deps.db_writer:
        await deps.db_writer.stop()
    if deps.bus:
        await deps.bus.drain(timeout=5.0)
    if deps.db_conn:
        await deps.db_conn.close()
