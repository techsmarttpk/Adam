"""
adam/sandbox/guest/channel.py

GuestChannel -- the host<->guest transport interface named in
ARCHITECTURE.md's own directory plan (section 10, `adam/sandbox/guest/
channel.py # host<->guest transport`) and section 15.3 (`httpx | sandbox |
guest agent channel`). This file did not exist until now: earlier phases
built a single concrete implementation (GuestAgent, `adam/sandbox/guest/
agent/agent.py`, driving VirtualBox's GuestControl bridge) directly, with
SessionOrchestrator depending on that concrete class. This module extracts
the interface that class was always implicitly satisfying, so a second,
architecturally "correct" implementation (a real guest-resident HTTP agent)
can be introduced alongside it without SessionOrchestrator/Runner caring
which one it's talking to.

Two implementations exist as of this phase:
  - VBoxGuestChannel (adam/sandbox/guest/vbox_channel.py) -- wraps the
    existing, UNTOUCHED GuestAgent. This is the "compatibility backend":
    kept fully operational, not deprecated, not removed, selected by
    default (`guest_backend = "vbox"` in config/default.toml) until the
    HTTP backend reaches feature parity on a real VM.
  - HTTPGuestChannel (adam/sandbox/guest/http_channel.py) -- talks to a
    persistent, guest-resident PowerShell 5.1 HTTP service (`adam/sandbox/
    guest/agent/adam_agent.ps1`, built on the guest's own built-in
    System.Net.HttpListener -- ARCHITECTURE.md's own C4 constraint: "The
    guest agent is PowerShell 5.1 compatible. No .NET Core assumption."
    No Python/FastAPI is installed in the guest; only the HOST side of
    this channel is Python, matching ARCHITECTURE.md 15.3's placement of
    `httpx` under "sandbox").

Why a `Protocol`, not an ABC. Both implementations already exist as
independently-constructed, independently-owned classes (GuestAgent
predates this file and must not be modified -- "do not patch the existing
GuestControl-based GuestAgent"). A `Protocol` lets VBoxGuestChannel
structurally satisfy this interface via simple composition/delegation
without GuestAgent itself needing to inherit from anything, and lets
mypy --strict verify both backends match this contract exactly.

Method set and signatures deliberately mirror GuestAgent's existing public
API 1:1 (verify_tools / start_captures / stop_export_and_fetch) -- this is
the exact, already-proven set of operations SessionOrchestrator needs for
one full session's guest telemetry lifecycle (ARCHITECTURE.md's own
Guarantees: always stop captures, always restore the VM, always clean up
temp files, support partial telemetry). Reuses GuestAgent's own
ToolAvailability/TelemetryArtifacts dataclasses as the shared return types
-- both backends return identical shapes, so
adam.orchestrator.session.build_collectors_from_telemetry() and every other
existing caller needs zero changes regardless of which backend is active.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from adam.sandbox.guest.agent.agent import TelemetryArtifacts, ToolAvailability

__all__ = ["GuestChannel", "ToolAvailability", "TelemetryArtifacts", "InMemoryGuestChannel"]


@runtime_checkable
class GuestChannel(Protocol):
    """
    The host<->guest transport contract SessionOrchestrator/Runner depend
    on. Any class satisfying these three async methods (structurally --
    no explicit inheritance required) is a valid backend.

    `runtime_checkable` is set so `isinstance(x, GuestChannel)` works in
    tests/diagnostics (e.g. Runner logging which concrete backend was
    selected) -- Protocol's own runtime check only verifies method
    *names* exist, not full signature compatibility, so mypy --strict
    static checking at each implementation's own definition remains the
    real enforcement; the runtime check is a convenience, not the
    contract's source of truth.
    """

    async def verify_tools(self) -> ToolAvailability:
        """
        Check that the configured telemetry tools (Procmon, tshark,
        Sysmon's log channel) are reachable in the guest, and log the
        guest workspace directory layout. Never raises -- see each
        backend's own docstring for its specific "never raises" strategy.
        """
        ...

    async def start_captures(
        self,
        session_id: str,
        *,
        capture_procmon: bool = True,
        capture_network: bool = True,
    ) -> None:
        """
        Start Procmon (backing-file mode) and/or tshark capture for this
        session, before the sample is detonated. Best-effort per source --
        a failure starting one capture must not raise and must not
        prevent the other from being attempted (ARCHITECTURE.md's "support
        partial telemetry" guarantee, which both backends must uphold
        identically).
        """
        ...

    async def stop_export_and_fetch(
        self,
        session_id: str,
        host_artifact_dir: str | Path,
        *,
        export_sysmon: bool = True,
        export_procmon: bool = True,
        export_network: bool = True,
    ) -> TelemetryArtifacts:
        """
        Stop any running captures, export each configured source's
        telemetry inside the guest, copy the results to
        `host_artifact_dir`, and best-effort clean up the guest's own
        temporary files. Each of the three sources is independently
        attempted; one failing must yield `None` for that field only, not
        raise and not affect the other two.
        """
        ...


class InMemoryGuestChannel:
    """
    In-memory guest channel for simulations, offline replays, API test execution,
    and testing where no real VM or HTTP agent is connected. Satisfies both
    GuestChannel and GuestMutationChannel protocols.
    """

    def __init__(self) -> None:
        self.applied_mutations: list[tuple[str, str, str, str | None]] = []
        self.applied_batches: list[list[tuple[str, str | None]]] = []

    async def apply_mutation(self, kind: str, target: str, operation: str, value: str | None) -> None:
        self.applied_mutations.append((kind, target, operation, value))

    async def apply_mutation_batch(
        self, file_creates: list[tuple[str, str | None]], timeout_s: float = 30.0
    ) -> None:
        self.applied_batches.append(file_creates)
        for target, value in file_creates:
            self.applied_mutations.append(("FILE", target, "CREATE", value))

    async def verify_tools(self) -> ToolAvailability:
        return ToolAvailability(
            procmon_available=True,
            tshark_available=True,
            sysmon_available=True,
        )

    async def start_captures(
        self,
        session_id: str,
        *,
        capture_procmon: bool = True,
        capture_network: bool = True,
    ) -> None:
        pass

    async def stop_export_and_fetch(
        self,
        session_id: str,
        host_artifact_dir: str | Path,
        *,
        export_sysmon: bool = True,
        export_procmon: bool = True,
        export_network: bool = True,
    ) -> TelemetryArtifacts:
        return TelemetryArtifacts(
            sysmon_evtx_path=None,
            procmon_csv_path=None,
            network_ek_json_path=None,
        )

