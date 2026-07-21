"""
Proves the loader -> compiler -> PolicyEngine.evaluate() path works for
RULE-014, entirely offline (no VM, no bus) — this is exactly the replay-style
testing ARCHITECTURE.md §17 asks for.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from adam.contracts.enums import Verdict
from adam.contracts.semantic_event import SemanticEvent
from adam.policy.context import SessionContext
from adam.policy.engine import PolicyEngine

FIXTURES = Path(__file__).parents[2] / "fixtures" / "semantic_events"
RULES_DIR = Path(__file__).parents[3] / "rules" / "default"


def _load_event(name: str) -> SemanticEvent:
    data = json.loads((FIXTURES / name).read_text())
    return SemanticEvent.model_validate(data)


def test_rule_014_fires_at_high_confidence():
    event = _load_event("recon_domain_controller.json")
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    context = SessionContext(session_id=event.session_id)

    decisions = engine.evaluate(event, context)

    fired = [d for d in decisions if d.rule_id == "RULE-014"]
    assert len(fired) == 1
    assert fired[0].verdict == Verdict.EXECUTE
    assert fired[0].action == "SPAWN_FAKE_DC_ARTIFACTS"
    assert fired[0].parameters["domain_name"] == "CORP.LOCAL"


def test_budget_exhausted_on_second_fire():
    event = _load_event("recon_domain_controller.json")
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    context = SessionContext(session_id=event.session_id)

    engine.evaluate(event, context)  # first fire consumes the budget
    second = engine.evaluate(event, context)  # same event again

    fired_014 = [d for d in second if d.rule_id == "RULE-014"]
    assert len(fired_014) == 1
    assert fired_014[0].verdict == Verdict.SUPPRESSED_BUDGET


def test_low_confidence_is_suppressed_not_dropped():
    # 0.80 clears RULE-014's own `when.confidence_gte: 0.75`, so the rule
    # matches — but a stricter *global* gate (0.90) should still suppress
    # it, and that suppression must be persisted/emitted, not dropped.
    event = _load_event("recon_domain_controller.json")
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.90)
    context = SessionContext(session_id=event.session_id)

    decisions = engine.evaluate(event, context)

    fired_014 = [d for d in decisions if d.rule_id == "RULE-014"]
    assert len(fired_014) == 1
    assert fired_014[0].verdict == Verdict.SUPPRESSED_CONFIDENCE
    assert fired_014[0].action is None


def test_rule_015_fires_at_medium_confidence():
    event = _load_event("recon_domain_controller.json")
    # Change the confidence to 0.65 so that it matches RULE-015 (0.50 to 0.74)
    # and doesn't match RULE-014 (>=0.75)
    event.confidence = 0.65
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    context = SessionContext(session_id=event.session_id)

    decisions = engine.evaluate(event, context)

    fired_014 = [d for d in decisions if d.rule_id == "RULE-014"]
    fired_015 = [d for d in decisions if d.rule_id == "RULE-015"]

    assert len(fired_014) == 0
    assert len(fired_015) == 1
    assert fired_015[0].verdict == Verdict.EXECUTE
    assert fired_015[0].action == "SPAWN_FAKE_DC_ARTIFACTS"
    assert fired_015[0].parameters["populate_sysvol"] is False


def test_rule_cooldown_suppresses_fire():
    event = _load_event("recon_domain_controller.json")
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    
    # Modify the compiled rule in engine to allow 2 fires so budget doesn't block it
    for r in engine._rules:
        if r.rule_id == "RULE-014":
            from adam.policy.compiler import RuleBudget, CompiledRule
            new_budget = RuleBudget(max_per_session=2, cooldown_seconds=30.0)
            new_rule = CompiledRule(
                rule_id=r.rule_id,
                version=r.version,
                condition=r.condition,
                action=r.action,
                priority=r.priority,
                parameters=r.parameters,
                budget=new_budget,
            )
            engine._rules = [new_rule if x.rule_id == "RULE-014" else x for x in engine._rules]

    context = SessionContext(session_id=event.session_id)

    with patch("time.monotonic") as mock_mono:
        mock_mono.return_value = 100.0
        # First fire
        decisions1 = engine.evaluate(event, context)
        assert len(decisions1) > 0
        fired_014 = [d for d in decisions1 if d.rule_id == "RULE-014"]
        assert len(fired_014) == 1
        assert fired_014[0].verdict == Verdict.EXECUTE

        # Second fire immediately (+5s, within 30s cooldown)
        mock_mono.return_value = 105.0
        decisions2 = engine.evaluate(event, context)
        fired_014_2 = [d for d in decisions2 if d.rule_id == "RULE-014"]
        assert len(fired_014_2) == 1
        assert fired_014_2[0].verdict == Verdict.SUPPRESSED_COOLDOWN

        # Third fire after cooldown (+35s)
        mock_mono.return_value = 136.0
        decisions3 = engine.evaluate(event, context)
        fired_014_3 = [d for d in decisions3 if d.rule_id == "RULE-014"]
        assert len(fired_014_3) == 1
        assert fired_014_3[0].verdict == Verdict.EXECUTE
