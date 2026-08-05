"""
adam/contracts/enums.py

Every enum referenced by the frozen contract models (ARCHITECTURE.md
section 7). This file has no dependencies beyond the stdlib -- per section
5.1, `adam/contracts/` must not import anything from any other ADAM module.

Merge note (nived-dev -> pranav-dev): this file previously existed as two
independent halves that never conflicted in substance, only in text --
Dev A's `Source`/`Category`/`Arm`/`NetworkMode`/`SessionStatus` (covering
`Envelope`/`RawEvent`/`AnalysisSession`, originally scoped per
docs/dev-a-environment-and-roadmap.md's Phase 2) and Dev C's
`Verdict`/`MutationStatus`/`ChangeKind` (covering `PolicyDecision`/
`MutationResult`, section 7.4-7.5), the latter originally shipped as a
"LOCAL STUB... reconcile with whatever Dev A/B/D land in the real
adam/contracts/enums.py first" per that file's own note. This is that
reconciliation: both sets share no overlapping names, so both are kept
verbatim, unioned into the one real, jointly-owned `adam/contracts/`
package section 10.2 always intended this file to become.
"""

from __future__ import annotations

import enum


class Source(enum.Enum):
    """RawEvent.source -- ARCHITECTURE.md section 7.2 table."""

    SYSMON = "SYSMON"
    PROCMON = "PROCMON"
    WIRESHARK = "WIRESHARK"
    AGENT = "AGENT"
    ADAM = "ADAM"


class Category(enum.Enum):
    """RawEvent.category -- ARCHITECTURE.md section 7.2 table."""

    PROCESS = "PROCESS"
    FILE = "FILE"
    REGISTRY = "REGISTRY"
    NETWORK = "NETWORK"
    MODULE = "MODULE"
    WMI = "WMI"
    MUTATION = "MUTATION"
    SYSTEM = "SYSTEM"


class Arm(enum.Enum):
    """
    AnalysisSession.arm -- ARCHITECTURE.md section 7.6.

    Two sessions sharing an experiment_id and differing in arm are the unit
    of comparison for behavioural yield.
    """

    CONTROL = "CONTROL"
    TREATMENT = "TREATMENT"


class NetworkMode(enum.Enum):
    """
    AnalysisSession.config.network_mode -- ARCHITECTURE.md section 12.2
    (`network_mode = "SIMULATED"  # HOST_ONLY | SIMULATED | INTERNET`) and
    section 7.6's example (`"network_mode": "SIMULATED"`).
    """

    HOST_ONLY = "HOST_ONLY"
    SIMULATED = "SIMULATED"
    INTERNET = "INTERNET"


class SessionStatus(enum.Enum):
    """
    AnalysisSession.status.

    ARCHITECTURE.md section 7.6's example shows only the terminal value
    "COMPLETED"; the full set below is inferred from the section 6.1
    session-lifecycle diagram (create -> prepare -> detonate -> teardown ->
    report) rather than from an explicit enum in the architecture document.
    Not part of the frozen section 7 shape -- flagged for confirmation in
    the Phase 2 all-four-developer review per section 10.2.

    PARTIAL added during Phase 8 (SessionOrchestrator): section 14.2's
    governing-principle table names it explicitly ("VM lost mid-run ->
    abort, force rollback, mark PARTIAL, report what was captured ->
    Partial") and section 14.4 repeats it ("A session that errored still
    produces a report -- marked PARTIAL. Partial results are still
    evidence."). Discovered missing while implementing
    SessionOrchestrator.run_session()'s failure-handling, which needs to
    distinguish "failed before any telemetry could be captured" (FAILED)
    from "failed after collectors were already running" (PARTIAL) -- see
    that module's docstring.
    """

    PENDING = "PENDING"
    PREPARING = "PREPARING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class Verdict(str, enum.Enum):
    """Outcome of evaluating a PolicyDecision (section 7.4)."""

    EXECUTE = "EXECUTE"
    SUPPRESSED_BUDGET = "SUPPRESSED_BUDGET"
    SUPPRESSED_COOLDOWN = "SUPPRESSED_COOLDOWN"
    SUPPRESSED_CONFIDENCE = "SUPPRESSED_CONFIDENCE"
    SUPPRESSED_CONFLICT = "SUPPRESSED_CONFLICT"
    DRY_RUN = "DRY_RUN"


class MutationStatus(str, enum.Enum):
    """Outcome of applying a deception primitive (section 7.5)."""

    APPLIED = "APPLIED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    REVERTED = "REVERTED"
    SKIPPED = "SKIPPED"


class ChangeKind(str, enum.Enum):
    """The category of a single environmental change inside a MutationResult."""

    REGISTRY = "REGISTRY"
    FILE = "FILE"
    NETWORK = "NETWORK"
    PROCESS = "PROCESS"
