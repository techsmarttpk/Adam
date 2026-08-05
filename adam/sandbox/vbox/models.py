"""
adam/sandbox/vbox/models.py

Lightweight, framework-free data models returned by the VirtualBox
automation wrapper (adam/sandbox/vbox/client.py).

These are internal to the sandbox.vbox package. They are NOT the same thing
as adam.contracts models -- contracts cross module boundaries over the event
bus and the API and are reviewed/frozen per ARCHITECTURE.md section 10.2.
These models never leave this package; they exist purely so
VirtualBoxClient returns structured, typed data instead of raw dicts.

Implemented as plain dataclasses rather than Pydantic models: there is no
JSON boundary to validate here, and pulling Pydantic into an internal-only
helper type would be exactly the kind of framework this milestone is scoped
to avoid.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VMOperationResult:
    """
    Outcome of a single VBoxManage-driven operation: start, stop,
    restore_snapshot, wait_for_state, or (Milestone 2) run_in_guest,
    wait_for_guest_ready, copy_to_guest.

    Returned instead of raising an exception for any VirtualBox-reported
    failure (VM already running, VM already stopped, snapshot not found,
    restore attempted on a running VM, wait timed out) so callers -- and the
    manual test script -- can inspect exactly what happened without wrapping
    every call in try/except.

    A VBoxCommandError is still raised separately when VBoxManage itself
    cannot be invoked at all (binary missing, permission denied) or when a
    query method (get_version, get_state, list_snapshots) fails outright --
    those are environment faults, not operation outcomes, and there is no
    natural "partial" result to hand back for them.

    termination_reason is a decoding step, not an interpretation step: if
    return_code matches a well-known Windows NTSTATUS value (see ntstatus.py),
    its symbolic name is recorded here (e.g. "STATUS_ACCESS_VIOLATION"). It
    does not change success -- a non-zero return_code is still success=False
    regardless of whether it decodes to a known name -- and it does not
    explain *why* that status occurred (that's a job for whatever consumes
    this result, with more context than this wrapper has). None if
    return_code is 0, unrecognized, or synthetic (e.g. wait_for_state's own
    return_code, which isn't a real VBoxManage-reported exit code at all).
    """

    success: bool
    command: tuple[str, ...]
    duration_ms: float
    return_code: int
    stdout: str
    stderr: str
    termination_reason: str | None = None


@dataclass(frozen=True, slots=True)
class SnapshotInfo:
    """
    One snapshot as reported by `VBoxManage snapshot <vm> list --machinereadable`.

    Note: VirtualBox's machine-readable snapshot listing numbers nested
    children as SnapshotName-1, SnapshotName-1-1, etc. This parser (see
    client.py:list_snapshots) only follows one level of numbering
    (SnapshotName-<n>), which is sufficient for ADAM's flat "clean" snapshot
    convention (ARCHITECTURE.md section 11). Deeply nested snapshot trees
    are a known, documented limitation, not a silent gap.
    """

    name: str
    uuid: str
    is_current: bool


@dataclass(frozen=True, slots=True)
class VMInfo:
    """
    Minimal identity/state summary for a VM.

    Not returned by any method in this milestone. get_state() intentionally
    returns a bare VirtualBox state string, not a VMInfo, because the
    wrapper must stay a thin passthrough -- mapping VirtualBox's native
    states into an ADAM-specific enum is the Sandbox Controller FSM's job
    (Milestone 2), not this wrapper's.

    Kept here now, unused, because it was named as an expected shared model
    for this package. Wire it up once a method actually needs richer VM
    identity than a name and a state string -- resist the temptation to
    force a use for it before that need is real.
    """

    name: str
    state: str
