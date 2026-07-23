import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest
import jsonschema

from adam.contracts.enums import Verdict, MutationStatus, ChangeKind
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.policy_decision import PolicyDecision
from adam.policy.context import SessionContext
from adam.policy.engine import PolicyEngine
from adam.deception.engine import DeceptionEngine
from adam.deception.catalogue import get_primitive_class, _CATALOGUE

FIXTURES_DIR = Path(__file__).parents[1] / "fixtures" / "semantic_events"
RULES_DIR = Path(__file__).parents[2] / "rules" / "default"
SCHEMA_PATH = Path(__file__).parents[2] / "rules" / "schema" / "rule.schema.json"


def _load_event(name: str) -> SemanticEvent:
    data = json.loads((FIXTURES_DIR / name).read_text())
    return SemanticEvent.model_validate(data)


# 1. Schema Validation Sweep
def test_schema_validation_sweep():
    with SCHEMA_PATH.open() as f:
        schema = json.load(f)

    for yaml_file in sorted(RULES_DIR.glob("*.yaml")):
        import yaml
        with yaml_file.open() as f:
            rules = yaml.safe_load(f) or []
            for i, rule in enumerate(rules):
                jsonschema.validate(instance=rule, schema=schema)


# 2. Determinism Check
def test_determinism_fresh_context():
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    fixtures = ["recon_domain_controller.json", "recon_av.json", "cred_browser.json", "persist_run_key.json", "evasion.json"]

    for fixture in fixtures:
        event = _load_event(fixture)
        first_run = engine.evaluate(event, SessionContext(session_id=event.session_id))
        
        for _ in range(19):
            subsequent = engine.evaluate(event, SessionContext(session_id=event.session_id))
            assert len(first_run) == len(subsequent)
            for d1, d2 in zip(first_run, subsequent):
                assert d1.rule_id == d2.rule_id
                assert d1.verdict == d2.verdict
                assert d1.action == d2.action
                assert d1.priority == d2.priority
                assert d1.parameters == d2.parameters
                assert d1.rationale == d2.rationale


def test_determinism_same_context_instance():
    # Calling evaluate 20 times on SAME context instance mutates budget state deterministically
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    event = _load_event("recon_av.json")
    context = SessionContext(session_id=event.session_id)

    run1 = engine.evaluate(event, context)
    assert run1[0].verdict == Verdict.EXECUTE

    for _ in range(19):
        subsequent = engine.evaluate(event, context)
        assert subsequent[0].verdict == Verdict.SUPPRESSED_BUDGET


# 3. Budget/Cooldown Isolation
def test_budget_isolation_two_rules():
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    context = SessionContext(session_id="sess_isolation")

    event_a = _load_event("recon_av.json")       # RULE-016 (max_per_session: 1)
    event_b = _load_event("recon_shares.json")   # RULE-018 (max_per_session: 1)

    # Fire A once
    d_a1 = [d for d in engine.evaluate(event_a, context) if d.rule_id == "RULE-016"][0]
    assert d_a1.verdict == Verdict.EXECUTE

    # Fire A twice (should suppress)
    d_a2 = [d for d in engine.evaluate(event_a, context) if d.rule_id == "RULE-016"][0]
    assert d_a2.verdict == Verdict.SUPPRESSED_BUDGET

    # Fire B once in between (should execute, not suppressed by A's budget)
    d_b1 = [d for d in engine.evaluate(event_b, context) if d.rule_id == "RULE-018"][0]
    assert d_b1.verdict == Verdict.EXECUTE

    # Fire B twice (should suppress)
    d_b2 = [d for d in engine.evaluate(event_b, context) if d.rule_id == "RULE-018"][0]
    assert d_b2.verdict == Verdict.SUPPRESSED_BUDGET


def test_cooldown_isolation_two_rules():
    from dataclasses import replace
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    engine._rules = [
        replace(r, budget=replace(r.budget, max_per_session=5))
        for r in engine._rules
    ]

    context = SessionContext(session_id="sess_cooldown")

    event_a = _load_event("recon_av.json")       # RULE-016 (cooldown: 30s)
    event_b = _load_event("recon_shares.json")   # RULE-018 (cooldown: 60s)

    with patch("time.monotonic") as mock_mono:
        mock_mono.return_value = 1000.0
        d_a1 = [d for d in engine.evaluate(event_a, context) if d.rule_id == "RULE-016"][0]
        assert d_a1.verdict == Verdict.EXECUTE

        mock_mono.return_value = 1010.0
        # Fire B for first time at +10s
        d_b1 = [d for d in engine.evaluate(event_b, context) if d.rule_id == "RULE-018"][0]
        assert d_b1.verdict == Verdict.EXECUTE

        # Fire A at +10s (within 30s cooldown -> suppressed)
        d_a2 = [d for d in engine.evaluate(event_a, context) if d.rule_id == "RULE-016"][0]
        assert d_a2.verdict == Verdict.SUPPRESSED_COOLDOWN


# 4. Suppressed Decisions Are Real Objects
def test_suppressed_confidence_object():
    event = _load_event("recon_av.json")
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.95)
    context = SessionContext(session_id=event.session_id)
    decisions = engine.evaluate(event, context)
    suppressed = [d for d in decisions if d.rule_id == "RULE-016"]
    assert len(suppressed) == 1
    d = suppressed[0]
    assert d is not None
    assert d.verdict == Verdict.SUPPRESSED_CONFIDENCE
    assert d.rationale is not None and len(d.rationale) > 0


def test_suppressed_budget_object():
    event = _load_event("recon_av.json")
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    context = SessionContext(session_id=event.session_id)
    engine.evaluate(event, context)
    decisions = engine.evaluate(event, context)
    suppressed = [d for d in decisions if d.rule_id == "RULE-016"]
    assert len(suppressed) == 1
    d = suppressed[0]
    assert d is not None
    assert d.verdict == Verdict.SUPPRESSED_BUDGET
    assert d.rationale is not None and len(d.rationale) > 0


def test_suppressed_cooldown_object():
    from dataclasses import replace
    event = _load_event("recon_av.json")
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    
    # modify rule budget in memory to allow max=2
    engine._rules = [
        replace(r, budget=replace(r.budget, max_per_session=2)) if r.rule_id == "RULE-016" else r
        for r in engine._rules
    ]

    context = SessionContext(session_id=event.session_id)

    with patch("time.monotonic") as mock_mono:
        mock_mono.return_value = 100.0
        engine.evaluate(event, context)

        mock_mono.return_value = 105.0
        decisions = engine.evaluate(event, context)
        suppressed = [d for d in decisions if d.rule_id == "RULE-016"]
        assert len(suppressed) == 1
        d = suppressed[0]
        assert d is not None
        assert d.verdict == Verdict.SUPPRESSED_COOLDOWN
        assert d.rationale is not None and len(d.rationale) > 0


# 5. dry_run Enforcement Engine-Wide
@pytest.mark.asyncio
async def test_dry_run_enforcement_all_primitives():
    actions = list(_CATALOGUE.keys())
    assert len(actions) > 0

    for action in actions:
        channel = AsyncMock()
        deception_engine = DeceptionEngine(channel)
        
        decision = PolicyDecision(
            decision_id="dec_dry_run_test",
            session_id="sess_dry",
            correlation_id="corr_dry",
            triggered_by="sem_dry",
            rule_id="RULE-TEST",
            rule_version="1.0",
            action=action,
            verdict=Verdict.DRY_RUN,
            priority=50,
            parameters={"domain_name": "CORP.LOCAL", "dc_hostname": "DC01"},
            rationale="dry_run test",
            evaluation_ms=1.0,
        )
        
        result = await deception_engine.execute_async(decision)
        assert result.status == MutationStatus.SKIPPED
        assert channel.apply_mutation.call_count == 0


# 6. Apply -> Revert Round-Trip, Every Primitive
@pytest.mark.asyncio
async def test_apply_revert_roundtrip_all_primitives():
    actions = {
        "SPAWN_FAKE_DC_ARTIFACTS": {"domain_name": "CORP.LOCAL", "dc_hostname": "DC01", "populate_sysvol": True},
        "PLANT_DECOY_RUN_KEY": {},
        "SIMULATE_AV_PRESENCE": {},
        "PLANT_DECOY_DOCUMENTS": {},
        "PLANT_DECOY_WALLET": {},
        "INJECT_FAKE_BROWSER_CREDS": {},
        "MOUNT_FAKE_NETWORK_SHARE": {},
        "HIDE_VM_ARTIFACTS": {},
    }

    inverse_ops = {
        "SET": ["DELETE"],
        "CREATE": ["DELETE", "TERMINATE"],
        "RESPOND": ["UNRESPOND", "DELETE"],
        "MOUNT": ["UNMOUNT", "DELETE"],
        "MASK": ["UNMASK"]
    }

    for action, params in actions.items():
        channel = AsyncMock()
        cls = get_primitive_class(action)
        primitive = cls(channel)

        mutation = await primitive.apply_async("sess", "corr", "dec", params)
        assert mutation.status == MutationStatus.APPLIED
        applied_calls = list(channel.apply_mutation.call_args_list)

        channel.reset_mock()
        reverted_mutation = await primitive.revert_async(mutation)
        assert reverted_mutation.status == MutationStatus.REVERTED
        revert_calls = list(channel.apply_mutation.call_args_list)

        assert len(revert_calls) == len(applied_calls)
        
        # Verify inverse operations
        for app_call, rev_call in zip(reversed(applied_calls), revert_calls):
            app_kind, app_target, app_op, app_val = app_call.args
            rev_kind, rev_target, rev_op, rev_val = rev_call.args
            assert rev_kind == app_kind
            assert rev_target == app_target
            assert rev_op in inverse_ops[app_op]


# 7. Plausibility Score Sanity
def test_plausibility_scores():
    scores = {}
    actions = {
        "SPAWN_FAKE_DC_ARTIFACTS": {"domain_name": "CORP.LOCAL", "dc_hostname": "DC01"},
        "PLANT_DECOY_RUN_KEY": {},
        "SIMULATE_AV_PRESENCE": {},
        "PLANT_DECOY_DOCUMENTS": {},
        "PLANT_DECOY_WALLET": {},
        "INJECT_FAKE_BROWSER_CREDS": {},
        "MOUNT_FAKE_NETWORK_SHARE": {},
        "HIDE_VM_ARTIFACTS": {},
    }

    channel = AsyncMock()
    for action, params in actions.items():
        cls = get_primitive_class(action)
        prim = cls(channel)
        score, notes = prim._plausibility(params)
        scores[action] = (score, notes)

    # Scores must not be all identical
    unique_scores = set(s[0] for s in scores.values())
    assert len(unique_scores) > 1


# 9. Adversarial Fixture Pass
def test_adversarial_boundary_confidence():
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.70)
    data = json.loads((FIXTURES_DIR / "recon_av.json").read_text())
    event = SemanticEvent.model_validate(data)
    event.confidence = 0.700000  # Exactly at threshold boundary
    context = SessionContext(session_id=event.session_id)
    decisions = engine.evaluate(event, context)
    fired = [d for d in decisions if d.rule_id == "RULE-016"]
    assert len(fired) == 1
    assert fired[0].verdict == Verdict.EXECUTE


def test_adversarial_unknown_intent():
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    data = json.loads((FIXTURES_DIR / "recon_av.json").read_text())
    event = SemanticEvent.model_validate(data)
    event.intent = "UNKNOWN_NONEXISTENT_INTENT_123"
    context = SessionContext(session_id=event.session_id)
    decisions = engine.evaluate(event, context)
    assert len(decisions) == 0  # Fails gracefully by returning no decisions


def test_adversarial_malformed_event():
    with pytest.raises(Exception):
        # Invalid missing required fields raises Pydantic ValidationError
        SemanticEvent.model_validate({"intent": "RECON_INSTALLED_AV"})
