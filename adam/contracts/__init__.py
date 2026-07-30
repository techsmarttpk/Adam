"""
adam/contracts/

The frozen boundary (ARCHITECTURE.md section 7). Re-exports the public
models/Protocols so callers can `from adam.contracts import RawEvent` rather
than reaching into submodules.

Scope of this package today (Dev A's Phase 2 proposal, pending the
all-four-developer review required by section 10.2): `Envelope`, `RawEvent`,
`ProcessInfo`, `AnalysisSession`, `SampleRef`, `SessionConfig`,
`SessionMetrics`, the enums in `enums.py`, and `ICollector` /
`ISandboxController` (plus their minimal supporting types) in
`interfaces.py`. `SemanticEvent`, `PolicyDecision`, and
`DeceptionAction`/`MutationResult`'s canonical (Dev C-owned) form are not
yet added -- see enums.py and interfaces.py docstrings.
"""

from __future__ import annotations

from adam.contracts.enums import Arm, Category, NetworkMode, SessionStatus, Source
from adam.contracts.envelope import Envelope
from adam.contracts.interfaces import (
    ArtifactRef,
    ICollector,
    ISandboxController,
    MutationRequest,
    MutationResult,
)
from adam.contracts.raw_event import ProcessInfo, RawEvent
from adam.contracts.session import AnalysisSession, SampleRef, SessionConfig, SessionMetrics

__all__ = [
    "Arm",
    "Category",
    "NetworkMode",
    "SessionStatus",
    "Source",
    "Envelope",
    "ArtifactRef",
    "ICollector",
    "ISandboxController",
    "MutationRequest",
    "MutationResult",
    "ProcessInfo",
    "RawEvent",
    "AnalysisSession",
    "SampleRef",
    "SessionConfig",
    "SessionMetrics",
]
