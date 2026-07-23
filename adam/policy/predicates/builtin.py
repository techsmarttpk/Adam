"""
Built-in predicates shipped with the default ruleset. Each one is pure:
(event, context) -> bool, no I/O, no mutation.
"""

from __future__ import annotations

from adam.contracts.interfaces import SessionContextProtocol
from adam.contracts.semantic_event import SemanticEvent
from adam.policy.predicates import predicate


@predicate("repeated_ldap_failure")
def repeated_ldap_failure(event: SemanticEvent, _context: SessionContextProtocol) -> bool:
    """
    True if the correlated evidence shows 2+ failed LDAP attempts and no
    successful one — matches the example in ARCHITECTURE.md §5.5 (RULE-014).
    """
    ldap_attempts = event.features.get("ldap_attempts", 0)
    all_failed = event.features.get("all_failed", False)
    return ldap_attempts >= 2 and bool(all_failed)


@predicate("single_process_actor")
def single_process_actor(event: SemanticEvent, _context: SessionContextProtocol) -> bool:
    """True if the event's evidence trail implicates exactly one process."""
    return bool(event.actor and event.actor.pid > 0)

@predicate("distinct_registry_keys_over")
def distinct_registry_keys_over(event: SemanticEvent, _context: SessionContextProtocol) -> bool:
    """True if the event's evidence trail implicates over 5 distinct registry keys."""
    distinct_keys = event.features.get("distinct_registry_keys", 0)
    return distinct_keys > 5
