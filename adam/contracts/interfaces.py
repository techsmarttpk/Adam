"""
adam/contracts/interfaces.py

Every ABC/Protocol in the whole project, in one place, per ARCHITECTURE.md
section 9's folder hierarchy comment ("every ABC/Protocol in one place").

Merge note (nived-dev -> pranav-dev): this file previously existed as two
independently-scoped halves -- Dev A's `ICollector` / `ISandboxController`
boundary (section 5.2/5.3, docs/dev-a-environment-and-roadmap.md's Phase 2
file list) and Dev C's Policy/Deception boundary (section 5.5/5.6, section
11.1), the latter shipped as a "LOCAL STUB... the real interfaces.py holds
every ABC in the whole project in one place; this file only has the ones
relevant to your two modules." This is that reconciliation.

Dev A's Protocols
------------------
Both `ICollector` and `ISandboxController` are declared `@runtime_checkable`
so `isinstance(obj, ...)` works for quick conformance checks (used by tests
and by adam/sandbox/controller.py's own verification script), while static
callers still get full `mypy --strict` structural checking against the
Protocol.

MutationRequest / MutationResult / ArtifactRef
------------------------------------------------
`ISandboxController.apply_mutation()` and `.collect_artifacts()` reference
types that ARCHITECTURE.md section 7 does not fully specify for Dev A's
scope: `MutationRequest` / `ArtifactRef` are not named as JSON contracts
anywhere in the document at all, so minimal versions are defined below so
the Protocol is syntactically complete. `MutationResult`'s wire shape
belongs to section 7.5 (owned by Dev C, the Deception Engine developer, per
section 10.1) -- this file previously carried its own provisional copy of
that model, kept in sync by hand. As of this merge, that inline copy is
removed in favour of importing Dev C's canonical `adam.contracts.mutation
.MutationResult` directly (re-exported below under the same name), since
Dev C's model is the one actually constructed by real code
(`adam/deception/engine.py`, `adam/deception/primitives/base.py`) --
`SandboxController.apply_mutation()` itself is still an unimplemented stub
(`NotImplementedError`, awaiting the Deception Engine per
docs/remaining-work-plan.md) and never constructed the old inline model, so
this swap changes no runtime behaviour anywhere that actually runs today.

Dev C's ABCs
------------
Consumers must depend on these interfaces, never on the concrete
PolicyEngine / DeceptionEngine classes (P3, section 11.2). This lets the
API composition root (adam/api/deps.py) bind an interface to an
implementation without importing internals, and lets Fusion's tests fake a
policy engine without importing the real one either.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from adam.contracts.mutation import MutationResult
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.session import SampleRef

__all__ = [
    "MutationRequest",
    "MutationResult",
    "ArtifactRef",
    "ICollector",
    "ISandboxController",
    "IPolicyEngine",
    "IRuleLoader",
    "IPredicate",
    "IDeceptionEngine",
    "IDeception",
    "SessionContextProtocol",
]


class MutationRequest(BaseModel):
    """
    Parameter type of `ISandboxController.apply_mutation()`. Deliberately
    minimal (see module docstring) -- mirrors the fields a
    `PolicyDecision` (section 7.4) would need to hand off to trigger a
    mutation: which primitive to apply and with what parameters.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: str = Field(min_length=1)
    primitive: str = Field(min_length=1)
    parameters: dict[str, Any] = Field(default_factory=dict)


class ArtifactRef(BaseModel):
    """
    One element of `ISandboxController.collect_artifacts()`'s return list.
    Not specified as a JSON contract anywhere in ARCHITECTURE.md -- see
    module docstring. Kept intentionally small: a pointer plus enough
    metadata for a caller to decide whether/how to ingest it, matching the
    "raw_ref keeps DB rows small" pattern already established by
    `RawEvent.raw_ref` (section 7.2).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str = Field(min_length=1)  # e.g. "sysmon_log", "pcap", "guest_disk_diff"
    path: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)


@runtime_checkable
class ICollector(Protocol):
    """
    ARCHITECTURE.md section 5.3. One implementation per telemetry source
    (Sysmon, ProcMon, Wireshark, guest agent). A collector normalises its
    own source into `RawEvent` and publishes to the bus -- it must not
    correlate across sources (that boundary belongs to Fusion, section 5.4).
    """

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def iter_events(self) -> AsyncIterator[RawEvent]: ...


@runtime_checkable
class ISandboxController(Protocol):
    """
    ARCHITECTURE.md section 5.2. Owns the full VM lifecycle: snapshot
    restore, boot, readiness probe, sample injection/detonation, timed
    teardown, snapshot rollback, artefact retrieval. Every method is async
    and every method has a config-driven timeout (section 5.2 design note).

    `adam/sandbox/controller.py`'s `SandboxController` is the implementation
    -- see that module for the FSM (`adam/sandbox/state.py`) enforcing the
    legal-transition guarantees this Protocol's docstrings describe.
    """

    async def prepare(self) -> None:
        """COLD -> RESTORING -> BOOTING -> READY."""
        ...

    async def detonate(self, sample: SampleRef) -> None:
        """ARMED -> RUNNING -> COMPLETED. Executes sample and blocks until exit or timeout."""
        ...

    async def apply_mutation(self, mutation: MutationRequest) -> MutationResult:
        """
        Applies one deception primitive inside the guest. Called by the
        Deception Engine (section 5.6), not by Dev A's own code -- the
        interface is declared here because SandboxController implements it
        (docs/dev-a-environment-and-roadmap.md Phase 2 note).
        """
        ...

    async def collect_artifacts(self) -> list[ArtifactRef]:
        """Retrieves telemetry/artefacts accumulated during the run."""
        ...

    async def teardown(self) -> None:
        """
        Any state -> TEARDOWN -> COLD. Idempotent and safe to call from a
        `finally` block after any failure (section 14.4). Never raises.
        """
        ...


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
    cooldowns, prior decisions). Passed in explicitly per ADR-004 -- never
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
