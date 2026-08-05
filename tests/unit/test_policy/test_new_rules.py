import json
from pathlib import Path
from adam.contracts.enums import Verdict
from adam.contracts.semantic_event import SemanticEvent
from adam.policy.context import SessionContext
from adam.policy.engine import PolicyEngine

FIXTURES = Path(__file__).parents[2] / "fixtures" / "semantic_events"
RULES_DIR = Path(__file__).parents[3] / "rules" / "default"

def _load_event(name: str) -> SemanticEvent:
    data = json.loads((FIXTURES / name).read_text())
    return SemanticEvent.model_validate(data)

def test_new_rules_fire_correctly():
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    
    test_cases = [
        ("recon_av.json", "RULE-016", "SIMULATE_AV_PRESENCE"),
        ("recon_vm.json", "RULE-017", "HIDE_VM_ARTIFACTS"),
        ("recon_shares.json", "RULE-018", "MOUNT_FAKE_NETWORK_SHARE"),
        ("cred_browser.json", "RULE-019", "INJECT_FAKE_BROWSER_CREDS"),
        ("cred_wallet.json", "RULE-020", "PLANT_DECOY_WALLET"),
        ("persist_run_key.json", "RULE-021", "PLANT_DECOY_RUN_KEY"),
        ("evasion.json", "RULE-022", "LOG_ONLY"),
        ("c2_beacon.json", "RULE-023", "FABRICATE_C2_RESPONSE"),
        ("evade_sleep.json", "RULE-024", "ACCELERATE_SYSTEM_CLOCK"),
        ("recon_uptime.json", "RULE-025", "SPAWN_DECOY_PROCESSES"),
        ("recon_user_artifacts.json", "RULE-027", "PLANT_DECOY_DOCUMENTS"),
    ]
    
    for filename, rule_id, action in test_cases:
        event = _load_event(filename)
        context = SessionContext(session_id=event.session_id)
        decisions = engine.evaluate(event, context)
        
        fired = [d for d in decisions if d.rule_id == rule_id]
        assert len(fired) == 1, f"{rule_id} did not fire for {filename}"
        assert fired[0].verdict == Verdict.EXECUTE
        assert fired[0].action == action

def test_dry_run_mode_never_calls_apply():
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60, dry_run=True)
    event = _load_event("recon_av.json")
    context = SessionContext(session_id=event.session_id)
    decisions = engine.evaluate(event, context)
    
    fired = [d for d in decisions if d.rule_id == "RULE-016"]
    assert len(fired) == 1
    assert fired[0].verdict == Verdict.DRY_RUN
