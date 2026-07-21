"""
Shared enums used across ADAM module boundaries.

NOTE: adam/contracts/ is owned jointly by all four devs (ARCHITECTURE.md P1).
This file is a LOCAL STUB so Policy + Deception can be developed and tested
offline before the real, team-reviewed adam/contracts package exists.
Do not merge this file into main as-is — reconcile with whatever Dev A/B/D
land in the real adam/contracts/enums.py first.
"""

from __future__ import annotations

from enum import Enum


class Verdict(str, Enum):
    """Outcome of evaluating a PolicyDecision (§7.4)."""

    EXECUTE = "EXECUTE"
    SUPPRESSED_BUDGET = "SUPPRESSED_BUDGET"
    SUPPRESSED_COOLDOWN = "SUPPRESSED_COOLDOWN"
    SUPPRESSED_CONFIDENCE = "SUPPRESSED_CONFIDENCE"
    SUPPRESSED_CONFLICT = "SUPPRESSED_CONFLICT"
    DRY_RUN = "DRY_RUN"


class MutationStatus(str, Enum):
    """Outcome of applying a deception primitive (§7.5)."""

    APPLIED = "APPLIED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    REVERTED = "REVERTED"
    SKIPPED = "SKIPPED"


class ChangeKind(str, Enum):
    """The category of a single environmental change inside a MutationResult."""

    REGISTRY = "REGISTRY"
    FILE = "FILE"
    NETWORK = "NETWORK"
    PROCESS = "PROCESS"
