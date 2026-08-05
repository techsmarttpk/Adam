"""
adam/contracts/

The frozen boundary (ARCHITECTURE.md section 7). Re-exports the public
models/Protocols/ABCs so callers can `from adam.contracts import RawEvent`
rather than reaching into submodules.

Merge note (nived-dev -> pranav-dev): this package now covers the full
joint scope from all contributing modules (section 10.2's all-four-
developer review target): `Envelope`, `RawEvent`, `ProcessInfo`,
`AnalysisSession`, `SampleRef`, `SessionConfig`, `SessionMetrics`, the
`enums.py` types, `ICollector` / `ISandboxController` (Dev A, section
5.2/5.3), `SemanticEvent` / `Actor` / `AttckRef` (Fusion, section 7.3),
`PolicyDecision` (Policy Engine, section 7.4), `MutationResult` / `Change`
(Deception Engine, section 7.5, now canonical -- see interfaces.py's
docstring for why the old Dev-A-owned inline copy was replaced by this
import), and the Policy/Deception ABCs (`IPolicyEngine`, `IRuleLoader`,
`IPredicate`, `IDeceptionEngine`, `IDeception`, `SessionContextProtocol`).
"""

from __future__ import annotations

from adam.contracts.enums import (
    Arm,
    Category,
    ChangeKind,
    MutationStatus,
    NetworkMode,
    SessionStatus,
    Source,
    Verdict,
)
from adam.contracts.envelope import Envelope
from adam.contracts.interfaces import (
    ArtifactRef,
    ICollector,
    IDeception,
    IDeceptionEngine,
    IPolicyEngine,
    IPredicate,
    IRuleLoader,
    ISandboxController,
    MutationRequest,
    MutationResult,
    SessionContextProtocol,
)
from adam.contracts.mutation import Change
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.raw_event import ProcessInfo, RawEvent
from adam.contracts.semantic_event import Actor, AttckRef, SemanticEvent
from adam.contracts.session import AnalysisSession, SampleRef, SessionConfig, SessionMetrics

__all__ = [
    "Arm",
    "Category",
    "ChangeKind",
    "MutationStatus",
    "NetworkMode",
    "SessionStatus",
    "Source",
    "Verdict",
    "Envelope",
    "ArtifactRef",
    "ICollector",
    "IDeception",
    "IDeceptionEngine",
    "IPolicyEngine",
    "IPredicate",
    "IRuleLoader",
    "ISandboxController",
    "MutationRequest",
    "MutationResult",
    "SessionContextProtocol",
    "Change",
    "PolicyDecision",
    "ProcessInfo",
    "RawEvent",
    "Actor",
    "AttckRef",
    "SemanticEvent",
    "AnalysisSession",
    "SampleRef",
    "SessionConfig",
    "SessionMetrics",
]
