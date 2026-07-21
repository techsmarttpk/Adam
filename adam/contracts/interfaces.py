"""
ABCs for the Policy and Deception boundary (§5.5, §5.6, §11.1).

Consumers must depend on these interfaces, never on the concrete
PolicyEngine / DeceptionEngine classes (P3, §11.2). This lets Pranav's
API composition root (adam/api/deps.py) bind an interface to your
implementation without importing your internals, and lets Raghu's Fusion
tests fake a policy engine without importing yours either.

LOCAL STUB — see enums.py note. The real interfaces.py holds every ABC in
the whole project in one place; this file only has the ones relevant to
your two modules.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from adam.contracts.mutation import MutationResult
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.semantic_event import SemanticEvent


class IPolicyEngine(ABC):
    """Pure function of (event, session context) -> decisions. No I/O (P4)."""

    @abstractmethod
    def evaluate(
        self, event: SemanticEvent, context: "SessionContextProtocol"
    ) -> list[PolicyDecision]:
        ...


class IRuleLoader(ABC):
    @abstractmethod
    def load(self, ruleset_path: str) -> list[dict[str, Any]]:
        """Load and validate raw rule dicts from a ruleset directory."""
        ...


class IPredicate(ABC):
    """A named, pure, side-effect-free escape hatch used inside `when.custom`."""

    @abstractmethod
    def __call__(self, event: SemanticEvent, context: "SessionContextProtocol") -> bool:
        ...


class IDeceptionEngine(ABC):
    @abstractmethod
    def execute(self, decision: PolicyDecision) -> MutationResult:
        ...


class IDeception(ABC):
    """One deception primitive. Every primitive implements both directions."""

    @abstractmethod
    def apply(self, parameters: dict[str, Any]) -> MutationResult:
        ...

    @abstractmethod
    def revert(self, mutation: MutationResult) -> MutationResult:
        ...


class SessionContextProtocol(ABC):
    """
    Minimal shape Policy needs from session context (budget consumed,
    cooldowns, prior decisions). Passed in explicitly per ADR-004 — never
    held as hidden mutable state inside the engine.
    """

    @abstractmethod
    def budget_remaining(self, rule_id: str, max_per_session: int) -> int:
        ...

    @abstractmethod
    def cooldown_active(self, rule_id: str, cooldown_seconds: float) -> bool:
        ...

    @abstractmethod
    def record_decision(self, decision: PolicyDecision) -> None:
        ...
