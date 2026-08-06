import os
import sqlite3
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "artifacts", "adam.sqlite")

MOCK_SESSIONS = [
    {
        "session_id": "sess_2026_08_06_d5f9",
        "experiment_id": "exp_lockbit_variant_7",
        "arm": "TREATMENT",
        "status": "COMPLETED",
        "sample": {
            "filename": "invoice_urgent.exe",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "size_bytes": 284672,
            "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows"
        },
        "config": {
            "vm_profile": "win10-x64-office",
            "deception_enabled": True,
            "policy_ruleset": "rules/default@1.0.3",
            "timeout_seconds": 300,
            "network_mode": "SIMULATED"
        },
        "metrics": {
            "decisions_total": 12,
            "mutations_applied": 5,
            "semantic_events_post_mutation": 21,
            "semantic_events": 47
        },
        "started_at": "2026-08-06T14:30:02Z",
        "ended_at": "2026-08-06T14:35:07Z",
        "error": None
    },
    {
        "session_id": "sess_2026_08_06_c0b2",
        "experiment_id": "exp_lockbit_variant_7",
        "arm": "CONTROL",
        "status": "COMPLETED",
        "sample": {
            "filename": "invoice_urgent.exe",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "size_bytes": 284672,
            "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows"
        },
        "config": {
            "vm_profile": "win10-x64-office",
            "deception_enabled": False,
            "policy_ruleset": "rules/default@1.0.3",
            "timeout_seconds": 300,
            "network_mode": "SIMULATED"
        },
        "metrics": {
            "decisions_total": 0,
            "mutations_applied": 0,
            "semantic_events_post_mutation": 0,
            "semantic_events": 2
        },
        "started_at": "2026-08-06T14:10:00Z",
        "ended_at": "2026-08-06T14:15:05Z",
        "error": None
    },
    {
        "session_id": "sess_2026_08_06_f12a",
        "experiment_id": "exp_wannacry_v2",
        "arm": "TREATMENT",
        "status": "FAILED",
        "sample": {
            "filename": "wcry_sample.bin",
            "sha256": "24a7c8a6e873efc819ef0019e0029b3c4f923c8aefefccaa882c16aef71a2be1",
            "md5": "9b12a87c12f00a980bc2e0d3cb1e2204",
            "size_bytes": 524288,
            "file_type": "PE32 executable (DLL)"
        },
        "config": {
            "vm_profile": "win10-x64-office",
            "deception_enabled": True,
            "policy_ruleset": "rules/aggressive@2.0.1",
            "timeout_seconds": 300,
            "network_mode": "SIMULATED"
        },
        "metrics": {
            "decisions_total": 0,
            "mutations_applied": 0,
            "semantic_events_post_mutation": 0,
            "semantic_events": 0
        },
        "started_at": "2026-08-06T14:40:00Z",
        "ended_at": "2026-08-06T14:41:15Z",
        "error": "GuestToolMissingError: Sysmon service not running inside Windows guest."
    }
]

MOCK_DECISIONS = [
    {
        "decision_id": "dec_01J8X4K3B7",
        "session_id": "sess_2026_08_06_d5f9",
        "rule_id": "RULE-014",
        "rule_version": "1.0.3",
        "action": "SPAWN_FAKE_DC_ARTIFACTS",
        "verdict": "EXECUTE",
        "priority": 80,
        "triggered_by": "sem_01J8X4K3A1",
        "rationale": "Domain recon at confidence 0.87 (gate 0.75); budget 0/1 used; no cooldown active."
    },
    {
        "decision_id": "dec_01J8X4K3B9",
        "session_id": "sess_2026_08_06_d5f9",
        "rule_id": "RULE-014",
        "rule_version": "1.0.3",
        "action": "SPAWN_FAKE_DC_ARTIFACTS",
        "verdict": "SUPPRESSED_BUDGET",
        "priority": 80,
        "triggered_by": "sem_01J8X4K4C1",
        "rationale": "Domain recon limit breached; rule SPAWN_FAKE_DC_ARTIFACTS hit max count of 1."
    },
    {
        "decision_id": "dec_01J8X4K3C4",
        "session_id": "sess_2026_08_06_d5f9",
        "rule_id": "RULE-027",
        "rule_version": "1.1.0",
        "action": "INJECT_FAKE_SQL_CREDENTIALS",
        "verdict": "EXECUTE",
        "priority": 90,
        "triggered_by": "sem_01J8X4K5D2",
        "rationale": "lsass.exe access detected at confidence 0.95 (gate 0.80); budget 0/1 used."
    }
]

MOCK_MUTATIONS = [
    {
        "mutation_id": "mut_01J8X4K3C2",
        "session_id": "sess_2026_08_06_d5f9",
        "primitive": "FakeDomainControllerDeception@1.0",
        "status": "APPLIED",
        "changes": [
            {"kind": "REGISTRY", "operation": "SET", "target": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Domain", "value": "CORP.LOCAL"},
            {"kind": "FILE", "operation": "CREATE", "target": "C:\\Windows\\SYSVOL\\sysvol\\CORP.LOCAL\\", "value": ""},
            {"kind": "NETWORK", "operation": "RESPOND", "target": "dns:DC01.CORP.LOCAL", "value": "10.0.0.10"}
        ],
        "latency_ms": 197,
        "plausibility_score": 0.72,
        "plausibility_notes": "Registry key mtime is post-boot; a timestamp-aware sample could detect this.",
        "causal_window_ms": 30000
    },
    {
        "mutation_id": "mut_01J8X4K5F8",
        "session_id": "sess_2026_08_06_d5f9",
        "primitive": "LsassDecoyCredentialDeception@1.1",
        "status": "APPLIED",
        "changes": [
            {"kind": "PROCESS", "operation": "INJECT", "target": "lsass.exe memory space", "value": "User: CORP\\admin, Pass: DeceptionP@ss123"}
        ],
        "latency_ms": 45,
        "plausibility_score": 0.91,
        "plausibility_notes": "Decoy credentials injected successfully in local LSASS memory cache.",
        "causal_window_ms": 60000
    }
]

MOCK_YIELD = [
    {
        "session_id": "sess_2026_08_06_d5f9",
        "intent": "RECON_DOMAIN_CONTROLLER",
        "control_count": 0,
        "treatment_count": 3,
        "attributed": True,
        "correlation_id": "corr_01J8X4K2M9"
    },
    {
        "session_id": "sess_2026_08_06_d5f9",
        "intent": "ATTACK_ACTIVE_DIRECTORY_LDAP",
        "control_count": 0,
        "treatment_count": 12,
        "attributed": True,
        "correlation_id": "corr_01J8X4K2M9"
    },
    {
        "session_id": "sess_2026_08_06_d5f9",
        "intent": "ATTACK_SYSVOL_SHARE_ACCESS",
        "control_count": 0,
        "treatment_count": 6,
        "attributed": True,
        "correlation_id": "corr_01J8X4K2M9"
    },
    {
        "session_id": "sess_2026_08_06_d5f9",
        "intent": "RECON_LOCAL_USER_INFO",
        "control_count": 2,
        "treatment_count": 2,
        "attributed": False,
        "correlation_id": "corr_01J8X4K1A4"
    }
]

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Create tables
    cur.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        experiment_id TEXT,
        arm TEXT,
        status TEXT,
        sample_json TEXT,
        config_json TEXT,
        metrics_json TEXT,
        started_at TEXT,
        ended_at TEXT,
        error TEXT
    )
    ''')

    cur.execute('''
    CREATE TABLE IF NOT EXISTS decisions (
        decision_id TEXT PRIMARY KEY,
        session_id TEXT,
        rule_id TEXT,
        rule_version TEXT,
        action TEXT,
        verdict TEXT,
        priority INTEGER,
        triggered_by TEXT,
        rationale TEXT
    )
    ''')

    cur.execute('''
    CREATE TABLE IF NOT EXISTS mutations (
        mutation_id TEXT PRIMARY KEY,
        session_id TEXT,
        primitive TEXT,
        status TEXT,
        changes_json TEXT,
        latency_ms INTEGER,
        plausibility_score REAL,
        plausibility_notes TEXT,
        causal_window_ms INTEGER
    )
    ''')

    cur.execute('''
    CREATE TABLE IF NOT EXISTS yield_comparisons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        intent TEXT,
        control_count INTEGER,
        treatment_count INTEGER,
        attributed BOOLEAN,
        correlation_id TEXT
    )
    ''')

    # Seed data if tables are empty
    cur.execute("SELECT COUNT(*) FROM sessions")
    if cur.fetchone()[0] == 0:
        for s in MOCK_SESSIONS:
            cur.execute('''
                INSERT INTO sessions (session_id, experiment_id, arm, status, sample_json, config_json, metrics_json, started_at, ended_at, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                s["session_id"], s.get("experiment_id"), s.get("arm"), s.get("status"),
                json.dumps(s.get("sample")), json.dumps(s.get("config")), json.dumps(s.get("metrics")),
                s.get("started_at"), s.get("ended_at"), s.get("error")
            ))
        
        for d in MOCK_DECISIONS:
            cur.execute('''
                INSERT INTO decisions (decision_id, session_id, rule_id, rule_version, action, verdict, priority, triggered_by, rationale)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                d["decision_id"], d.get("session_id"), d.get("rule_id"), d.get("rule_version"),
                d.get("action"), d.get("verdict"), d.get("priority"), d.get("triggered_by"), d.get("rationale")
            ))
            
        for m in MOCK_MUTATIONS:
            cur.execute('''
                INSERT INTO mutations (mutation_id, session_id, primitive, status, changes_json, latency_ms, plausibility_score, plausibility_notes, causal_window_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                m["mutation_id"], m.get("session_id"), m.get("primitive"), m.get("status"),
                json.dumps(m.get("changes")), m.get("latency_ms"), m.get("plausibility_score"), m.get("plausibility_notes"), m.get("causal_window_ms")
            ))
            
        for y in MOCK_YIELD:
            cur.execute('''
                INSERT INTO yield_comparisons (session_id, intent, control_count, treatment_count, attributed, correlation_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                y.get("session_id"), y.get("intent"), y.get("control_count"), y.get("treatment_count"),
                y.get("attributed"), y.get("correlation_id")
            ))

    conn.commit()
    conn.close()
    print(f"Database initialized and seeded at {DB_PATH}")

if __name__ == "__main__":
    init_db()
