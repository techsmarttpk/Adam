"""
adam/api/deps.py

Composition root (ARCHITECTURE.md section 5.8).
Constructs and wires together all components of the ADAM pipeline.
"""
import aiosqlite

from adam.common.bus import EventBus
from adam.common.config import get_settings
from adam.db.repositories.sqlite import SQLiteSessionRepository, SQLiteEventRepository, SQLiteDecisionRepository, SQLiteMutationRepository
from adam.db.writer import DBWriter
from adam.reporting.generator import ReportGenerator
from adam.deception.engine import DeceptionEngine
from adam.fusion.engine import EventFusionEngine
from adam.pipeline.wiring import EngineHandles, wire_engines
from adam.policy.context import SessionContext
from adam.policy.engine import PolicyEngine
from adam.sandbox.guest.channel import InMemoryGuestChannel

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
        self.engine_handles: EngineHandles | None = None
        self.report_generator: ReportGenerator | None = None

deps = Dependencies()

async def init_dependencies() -> None:
    settings = get_settings()
    
    # 1. Instantiate
    deps.bus = EventBus()
    deps.db_conn = await aiosqlite.connect(settings.db.path)
    await deps.db_conn.execute("PRAGMA journal_mode=WAL;")
    await deps.db_conn.execute("PRAGMA busy_timeout=5000;")
    
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
    deps.deception = DeceptionEngine(InMemoryGuestChannel())
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
    
    # 2. Wire Fusion/Policy/Deception onto the bus. Shared with the live
    #    detonation path via adam/pipeline/wiring.wire_engines() -- the
    #    handlers that used to live inline below are extracted there
    #    byte-for-byte. The only deps-specific piece is resolving a
    #    session's dry_run (deception enablement) from the persisted
    #    AnalysisSession; a missing session record resolves to None, which
    #    wire_engines treats as "no information" -> dry_run=True (deception
    #    does NOT execute), the safe default -- flip this back to an
    #    opt-in per-session decision only once a real mutation channel
    #    exists.
    async def _resolve_dry_run(session_id: str) -> bool | None:
        session = await deps.session_repo.get_by_id(session_id)
        if session is None:
            return None
        return not session.config.deception_enabled

    deps.engine_handles = wire_engines(
        deps.bus,
        fusion=deps.fusion,
        policy=deps.policy,
        deception=deps.deception,
        session_contexts=deps.session_contexts,
        resolve_dry_run=_resolve_dry_run,
    )

    # DBWriter internal subscriptions (subscribes to everything it needs)
    deps.db_writer.start()
    
    # 4. Start EventBus
    await deps.bus.start()

async def shutdown_dependencies() -> None:
    if deps.bus:
        await deps.bus.drain(timeout=5.0)
    if deps.db_writer:
        await deps.db_writer.stop()
    if deps.db_conn:
        await deps.db_conn.close()
