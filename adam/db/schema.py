"""
adam/db/schema.py

SQLite schema for Phase 1 persistence layer (ARCHITECTURE.md section 5.7).
"""

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    experiment_id TEXT NOT NULL,
    sample_sha256 TEXT NOT NULL,
    arm TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_events (
    event_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    source TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS semantic_events (
    semantic_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    confidence REAL NOT NULL,
    window_start TEXT NOT NULL,
    caused_by_mutation TEXT,
    payload TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    triggered_by TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS mutations (
    mutation_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    status TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_raw_events_session ON raw_events(session_id);
CREATE INDEX IF NOT EXISTS idx_semantic_events_session ON semantic_events(session_id);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_session ON policy_decisions(session_id);
CREATE INDEX IF NOT EXISTS idx_mutations_session ON mutations(session_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_id);
"""
