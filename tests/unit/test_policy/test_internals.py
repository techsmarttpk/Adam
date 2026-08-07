import pytest
import json
from pathlib import Path
from adam.contracts.enums import Verdict
from adam.contracts.semantic_event import SemanticEvent
from adam.policy.context import SessionContext
from adam.policy.budget import BudgetTracker
from adam.policy.engine import PolicyEngine
from adam.policy.predicates.builtin import distinct_registry_keys_over

def test_budget_tracking_per_rule_id():
    tracker = BudgetTracker()
    tracker.record_fire("RULE-A")
    assert tracker.remaining("RULE-A", 1) == 0
    assert tracker.remaining("RULE-B", 1) == 1

def test_context_determinism():
    FIXTURES = Path(__file__).parents[2] / "fixtures" / "semantic_events"
    RULES_DIR = Path(__file__).parents[3] / "rules" / "default"
    
    data = json.loads((FIXTURES / "recon_domain_controller.json").read_text())
    event = SemanticEvent.model_validate(data)
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    
    context1 = SessionContext(session_id=event.session_id)
    decisions1 = engine.evaluate(event, context1)
    
    context2 = SessionContext(session_id=event.session_id)
    decisions2 = engine.evaluate(event, context2)
    
    # Prove determinism (ignoring UUID fields)
    assert [(d.rule_id, d.verdict, d.action) for d in decisions1] == [(d.rule_id, d.verdict, d.action) for d in decisions2]

def test_custom_predicate_isolation():
    FIXTURES = Path(__file__).parents[2] / "fixtures" / "semantic_events"
    data = json.loads((FIXTURES / "recon_domain_controller.json").read_text())
    event = SemanticEvent.model_validate(data)
    event.features["distinct_registry_keys"] = 6
    
    context = SessionContext(session_id="test")
    assert distinct_registry_keys_over(event, context) is True
    
    event.features["distinct_registry_keys"] = 3
    assert distinct_registry_keys_over(event, context) is False

def test_suppressed_decisions_persisted():
    FIXTURES = Path(__file__).parents[2] / "fixtures" / "semantic_events"
    RULES_DIR = Path(__file__).parents[3] / "rules" / "default"
    
    data = json.loads((FIXTURES / "recon_domain_controller.json").read_text())
    event = SemanticEvent.model_validate(data)
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    context = SessionContext(session_id=event.session_id)
    
    # First fire
    engine.evaluate(event, context)
    
    # Second fire - should be budget suppressed but still recorded
    decisions = engine.evaluate(event, context)
    suppressed = [d for d in decisions if d.rule_id == "RULE-014" and d.verdict == Verdict.SUPPRESSED_BUDGET]
    assert len(suppressed) == 1
    
    # The suppressed decision should be in context.decisions
    assert suppressed[0] in context.decisions
