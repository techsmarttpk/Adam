CREATE TABLE IF NOT EXISTS experiments (
    experiment_id TEXT PRIMARY KEY,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    experiment_id TEXT,
    arm TEXT,
    sample_sha256 TEXT,
    sample_md5 TEXT,
    sample_filename TEXT,
    sample_size_bytes INTEGER,
    sample_file_type TEXT,
    deception_enabled INTEGER,
    policy_ruleset TEXT,
    vm_profile TEXT,
    timeout_seconds INTEGER,
    network_mode TEXT,
    status TEXT,
    started_at TIMESTAMP,
    ended_at TIMESTAMP,
    error TEXT,
    FOREIGN KEY (experiment_id) REFERENCES experiments(experiment_id)
);

CREATE TABLE IF NOT EXISTS raw_event_metadata (
    event_id TEXT PRIMARY KEY,
    session_id TEXT,
    source TEXT,
    source_event_id INTEGER,
    category TEXT,
    occurred_at TIMESTAMP,
    observed_at TIMESTAMP,
    pid INTEGER,
    image TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS semantic_events (
    semantic_id TEXT PRIMARY KEY,
    session_id TEXT,
    correlation_id TEXT,
    intent TEXT,
    confidence REAL,
    severity TEXT,
    window_start TIMESTAMP,
    window_end TIMESTAMP,
    actor_pid INTEGER,
    actor_image TEXT,
    actor_guid TEXT,
    evidence TEXT,
    attck_tactic TEXT,
    attck_technique TEXT,
    detector TEXT,
    features TEXT,
    caused_by_mutation TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    session_id TEXT,
    correlation_id TEXT,
    triggered_by TEXT,
    rule_id TEXT,
    rule_version TEXT,
    action TEXT,
    verdict TEXT,
    priority INTEGER,
    parameters TEXT,
    rationale TEXT,
    decided_at TIMESTAMP,
    evaluation_ms REAL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (triggered_by) REFERENCES semantic_events(semantic_id)
);

CREATE TABLE IF NOT EXISTS mutations (
    mutation_id TEXT PRIMARY KEY,
    session_id TEXT,
    correlation_id TEXT,
    decision_id TEXT,
    primitive TEXT,
    status TEXT,
    applied_at TIMESTAMP,
    latency_ms REAL,
    changes TEXT,
    plausibility_score REAL,
    plausibility_notes TEXT,
    revertible INTEGER,
    causal_window_ms INTEGER,
    error TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (decision_id) REFERENCES decisions(decision_id)
);

CREATE TABLE IF NOT EXISTS session_metrics (
    session_id TEXT PRIMARY KEY,
    raw_events INTEGER DEFAULT 0,
    semantic_events INTEGER DEFAULT 0,
    decisions_total INTEGER DEFAULT 0,
    decisions_executed INTEGER DEFAULT 0,
    mutations_applied INTEGER DEFAULT 0,
    semantic_events_post_mutation INTEGER DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_experiment ON sessions(experiment_id, arm);
CREATE INDEX IF NOT EXISTS idx_semantic_events_session ON semantic_events(session_id, window_start);
CREATE INDEX IF NOT EXISTS idx_semantic_events_mutation ON semantic_events(session_id, caused_by_mutation);
CREATE INDEX IF NOT EXISTS idx_decisions_session ON decisions(session_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_mutations_session ON mutations(session_id, decision_id);
CREATE INDEX IF NOT EXISTS idx_raw_events_session ON raw_event_metadata(session_id, occurred_at);
