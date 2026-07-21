"""
Budget and cooldown bookkeeping for the Policy Engine.

Kept as small, dependency-free, pure-data classes so SessionContext (and the
engine that uses it) stays trivially unit-testable per ARCHITECTURE.md ADR-004
(Policy must be a pure function; state is passed in, never hidden).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class RuleUsage:
    """How many times a rule has fired, and when it last fired."""

    fired_count: int = 0
    last_fired_at: float | None = None  # monotonic seconds


@dataclass
class BudgetTracker:
    """
    Tracks per-rule usage within a single session.

    One instance lives inside a SessionContext (context.py) — it is NOT
    shared across sessions, and NOT a module-level singleton (forbidden by
    §11.2).
    """

    _usage: dict[str, RuleUsage] = field(default_factory=dict)

    def _get(self, rule_id: str) -> RuleUsage:
        return self._usage.setdefault(rule_id, RuleUsage())

    def remaining(self, rule_id: str, max_per_session: int) -> int:
        used = self._get(rule_id).fired_count
        return max(0, max_per_session - used)

    def cooldown_active(self, rule_id: str, cooldown_seconds: float, *, now: float | None = None) -> bool:
        usage = self._get(rule_id)
        if usage.last_fired_at is None or cooldown_seconds <= 0:
            return False
        current = now if now is not None else time.monotonic()
        return (current - usage.last_fired_at) < cooldown_seconds

    def record_fire(self, rule_id: str, *, now: float | None = None) -> None:
        usage = self._get(rule_id)
        usage.fired_count += 1
        usage.last_fired_at = now if now is not None else time.monotonic()
