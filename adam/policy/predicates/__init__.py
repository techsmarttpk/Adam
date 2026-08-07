"""
Predicate registry — the Python escape hatch referenced by `when.custom` in
rule YAML (ARCHITECTURE.md ADR-002).

Predicates must be pure and side-effect-free. Register one with:

    from adam.policy.predicates import predicate

    @predicate("repeated_ldap_failure")
    def repeated_ldap_failure(event, context) -> bool:
        ...

Adding a predicate means adding a function with a decorator — never editing
a central list, which is exactly the kind of file four people would
otherwise conflict on (§10.3).
"""

from __future__ import annotations

from typing import Callable

from adam.contracts.interfaces import SessionContextProtocol
from adam.contracts.semantic_event import SemanticEvent

PredicateFn = Callable[[SemanticEvent, SessionContextProtocol], bool]

_REGISTRY: dict[str, PredicateFn] = {}


def predicate(name: str) -> Callable[[PredicateFn], PredicateFn]:
    def decorator(fn: PredicateFn) -> PredicateFn:
        if name in _REGISTRY:
            raise ValueError(f"Predicate '{name}' is already registered")
        _REGISTRY[name] = fn
        return fn

    return decorator


def get_predicate(dotted_name: str) -> PredicateFn:
    """
    Rules reference predicates as 'predicates.repeated_ldap_failure' — the
    'predicates.' prefix is convention only, the registry key is the bare
    function name.
    """
    name = dotted_name.split(".")[-1]
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(
            f"No predicate registered under '{name}'. "
            f"Known predicates: {sorted(_REGISTRY)}"
        ) from exc


# Import built-ins so their @predicate decorators run and populate the registry.
from adam.policy.predicates import builtin  # noqa: E402,F401
