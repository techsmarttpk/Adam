"""
Condition evaluation for the `when:` block of a rule (ARCHITECTURE.md §5.5).

The DSL deliberately covers only a handful of declarative comparisons.
Anything more expressive belongs behind a registered predicate
(adam/policy/predicates/), never bolted on here — that boundary is what
keeps 95% of the rule corpus in reviewable YAML.
"""

from __future__ import annotations

from typing import Any, Callable

from adam.contracts.interfaces import SessionContextProtocol
from adam.contracts.semantic_event import SemanticEvent
from adam.policy.predicates import get_predicate

# A compiled condition is just: (event, context) -> bool
ConditionFn = Callable[[SemanticEvent, SessionContextProtocol], bool]


def _field_value(event: SemanticEvent, dotted_path: str) -> Any:
    """Resolve 'features.ldap_attempts' style paths against a SemanticEvent."""
    value: Any = event
    for part in dotted_path.split("."):
        if isinstance(value, dict):
            value = value.get(part)
        else:
            value = getattr(value, part, None)
    return value


def compile_when(when_block: dict[str, Any]) -> ConditionFn:
    """
    Compile a rule's `when:` dict into a single callable. All keys inside
    `when` are implicitly AND-ed together — that's a deliberate simplicity
    choice; anything needing OR/NOT belongs in a predicate instead.
    """
    checks: list[ConditionFn] = []

    if "intent" in when_block:
        expected_intent = when_block["intent"]
        checks.append(lambda ev, _ctx, _v=expected_intent: ev.intent == _v)

    if "confidence_gte" in when_block:
        threshold = float(when_block["confidence_gte"])
        checks.append(lambda ev, _ctx, _t=threshold: ev.confidence >= _t)

    if "confidence_lte" in when_block:
        threshold = float(when_block["confidence_lte"])
        checks.append(lambda ev, _ctx, _t=threshold: ev.confidence <= _t)

    if "severity" in when_block:
        expected_severity = when_block["severity"]
        checks.append(lambda ev, _ctx, _v=expected_severity: ev.severity == _v)

    for field_expr in when_block.get("feature_equals", []) or []:
        path, expected = field_expr["path"], field_expr["equals"]
        checks.append(
            lambda ev, _ctx, _p=path, _v=expected: _field_value(ev, _p) == _v
        )

    if "custom" in when_block:
        predicate = get_predicate(when_block["custom"])
        checks.append(lambda ev, ctx, _p=predicate: _p(ev, ctx))

    def evaluate(event: SemanticEvent, context: SessionContextProtocol) -> bool:
        return all(check(event, context) for check in checks)

    return evaluate
