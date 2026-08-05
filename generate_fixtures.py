import json
from pathlib import Path

FIXTURES_DIR = Path("tests/fixtures/semantic_events")
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

base_event = {
  "semantic_id": "sem_01J8X4K3A1",
  "session_id": "sess_test_0001",
  "correlation_id": "corr_01J8X4K2M9",
  "confidence": 0.90,
  "severity": "MEDIUM",
  "window_start": "2026-07-21T14:32:11.401220Z",
  "window_end": "2026-07-21T14:32:13.902441Z",
  "actor": {
    "pid": 4812,
    "image": "C:\\Users\\analyst\\AppData\\Local\\Temp\\sample.exe",
    "guid": "{a1b2c3d4-0000-0000-0000-000000000001}"
  },
  "evidence": ["raw_01J8X4K2M9P3QR7T"],
  "attck": { "tactic": "TA0007", "technique": "T1018" },
  "detector": "DummyDetector",
  "features": {},
  "caused_by_mutation": None
}

intents = [
    ("RECON_INSTALLED_AV", "recon_av.json"),
    ("RECON_VIRTUALISATION", "recon_vm.json"),
    ("RECON_NETWORK_SHARES", "recon_shares.json"),
    ("CRED_BROWSER_STORE", "cred_browser.json"),
    ("CRED_WALLET_SEARCH", "cred_wallet.json"),
    ("PERSIST_RUN_KEY", "persist_run_key.json"),
    ("EVADE_SANDBOX_DETECTED", "evasion.json"),
]

for intent, filename in intents:
    event = base_event.copy()
    event["intent"] = intent
    if intent == "PERSIST_RUN_KEY":
        event["features"] = {"distinct_registry_keys": 6}
    else:
        event["features"] = {}
    
    (FIXTURES_DIR / filename).write_text(json.dumps(event, indent=2))
