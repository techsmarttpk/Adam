import json
from pathlib import Path
import pytest

from adam.contracts.semantic_event import SemanticEvent
from adam.policy.conditions import compile_when, _field_value
from adam.policy.loader import RuleLoader, RuleSyntaxError
from adam.policy.predicates import predicate, get_predicate

FIXTURES_DIR = Path(__file__).parents[2] / "fixtures" / "semantic_events"


def _load_event() -> SemanticEvent:
    data = json.loads((FIXTURES_DIR / "recon_domain_controller.json").read_text())
    return SemanticEvent.model_validate(data)


# --- Conditions.py Coverage Gaps ---

def test_severity_condition():
    when = {"severity": "HIGH"}
    eval_fn = compile_when(when)
    
    event = _load_event()
    event.severity = "HIGH"
    assert eval_fn(event, None) is True
    
    event.severity = "LOW"
    assert eval_fn(event, None) is False


def test_feature_equals_condition_and_field_value():
    when = {
        "feature_equals": [
            {"path": "actor.pid", "equals": 4812},
            {"path": "features.ldap_attempts", "equals": 2}
        ]
    }
    eval_fn = compile_when(when)
    
    event = _load_event()
    assert eval_fn(event, None) is True

    # Test non-matching field value
    event.actor.pid = 9999
    assert eval_fn(event, None) is False

    # Test direct _field_value helper with dict and attribute paths
    assert _field_value(event, "features.ldap_attempts") == 2
    assert _field_value(event, "actor.pid") == 9999
    assert _field_value(event, "nonexistent.path") is None


# --- Loader.py Coverage Gaps ---

def test_loader_nonexistent_path():
    loader = RuleLoader()
    with pytest.raises(RuleSyntaxError, match="does not exist"):
        loader.load("non_existent_rules_dir_12345")


def test_loader_top_level_not_list(tmp_path):
    yaml_file = tmp_path / "invalid.yaml"
    yaml_file.write_text("id: RULE-999\nwhen: {}\nthen: {}\n")
    loader = RuleLoader()
    with pytest.raises(RuleSyntaxError, match="expected a top-level list"):
        loader.load(str(tmp_path))


def test_loader_missing_top_level_fields(tmp_path):
    yaml_file = tmp_path / "missing_id.yaml"
    yaml_file.write_text("- when: {}\n  then: {}\n")
    loader = RuleLoader()
    with pytest.raises(RuleSyntaxError, match="missing required field"):
        loader.load(str(tmp_path))


def test_loader_missing_then_fields(tmp_path):
    yaml_file = tmp_path / "missing_then_action.yaml"
    yaml_file.write_text("- id: RULE-999\n  when: {}\n  then:\n    priority: 10\n")
    loader = RuleLoader()
    with pytest.raises(RuleSyntaxError, match="'then' block missing"):
        loader.load(str(tmp_path))


def test_loader_duplicate_rule_ids(tmp_path):
    yaml_file = tmp_path / "duplicate.yaml"
    yaml_file.write_text(
        "- id: RULE-999\n  when: {}\n  then:\n    action: LOG_ONLY\n    priority: 10\n"
        "- id: RULE-999\n  when: {}\n  then:\n    action: LOG_ONLY\n    priority: 10\n"
    )
    loader = RuleLoader()
    with pytest.raises(RuleSyntaxError, match="Duplicate rule id"):
        loader.load(str(tmp_path))


# --- Predicates/__init__.py Coverage Gaps ---

def test_duplicate_predicate_registration():
    with pytest.raises(ValueError, match="already registered"):
        @predicate("repeated_ldap_failure")
        def _dummy(event, context):
            return True


def test_missing_predicate_error():
    with pytest.raises(KeyError, match="No predicate registered under"):
        get_predicate("predicates.nonexistent_predicate_999")


def test_single_process_actor_predicate():
    from adam.policy.predicates.builtin import single_process_actor
    event = _load_event()
    assert single_process_actor(event, None) is True
    
    event.actor.pid = 0
    assert single_process_actor(event, None) is False
