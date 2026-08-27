"""
adam/sandbox/state.py

The Sandbox Controller's finite state machine, per ARCHITECTURE.md section
5.2 (as amended for Milestone 3): COLD -> RESTORING -> BOOTING -> READY ->
ARMED -> RUNNING -> COMPLETED, with TEARDOWN and FAILED reachable as
described in controller.py. Illegal transitions raise SandboxStateError;
legal transitions whose underlying VirtualBoxClient call itself fails raise
SandboxOperationError.

COMPLETED was added to ARCHITECTURE.md's state list specifically to
distinguish "the sample has finished executing" from RUNNING's "the sample
is executing right now" -- a distinction that costs nothing today (the
FSM's re-arm-only-after-a-real-restore guarantee holds identically either
way) but that later milestones needing to act only while a sample is
genuinely alive will depend on. See ARCHITECTURE.md section 5.2 for the
full rationale.

Both exceptions below are folded into adam.common.errors' AdamError
hierarchy (per docs/remaining-work-plan.md's Next-bucket item 4), now that
that module exists:
  - SandboxStateError subclasses adam.common.errors.SandboxStateError --
    the frozen tree's own leaf name (ARCHITECTURE.md section 14.1) -- under
    an identical short name. This is deliberate, not an accident: the rich,
    fielded exception actually raised everywhere in this codebase stays
    right here with its existing constructor and import path
    (adam.sandbox.state.SandboxStateError), while still being a genuine
    `except adam.common.errors.SandboxStateError` (and `SandboxError`, and
    `AdamError`) match. See adam/common/errors.py's own docstring for why
    the dependency has to run this direction (adam/common/ must not import
    from adam/sandbox/).
  - SandboxOperationError subclasses adam.common.errors.VMOperationError,
    since its own docstring's failure list (restore_snapshot/start/
    wait_for_state/wait_for_guest_ready/copy_to_guest failing, or
    VBoxManage being unreachable) is exactly VMOperationError's "VBoxManage
    failed" -- the same underlying failure mode VBoxCommandError
    represents at the client layer, just surfaced here at the controller
    layer.

Neither class's name, constructor, or raise sites changed -- every
existing `except SandboxStateError` / `except SandboxOperationError` call
site (adam/sandbox/controller.py, scripts/manual_test_sandbox_controller.py)
is unaffected.
"""

from __future__ import annotations

import enum

from adam.common.errors import SandboxStateError as _CommonSandboxStateError
from adam.common.errors import VMOperationError


class SandboxState(enum.Enum):
    """
    States of the Sandbox Controller FSM.
    Covers full lifecycle: PROVISIONING -> BOOTING -> AGENT_HANDSHAKE -> READY ->
    ARMED -> DETONATING (RUNNING) -> COLLECTING -> TEARING_DOWN (TEARDOWN) -> COMPLETED (COMPLETE),
    and FAILED / ERROR reachable from any state.
    """

    COLD = "COLD"
    PROVISIONING = "PROVISIONING"
    RESTORING = "RESTORING"
    BOOTING = "BOOTING"
    AGENT_HANDSHAKE = "AGENT_HANDSHAKE"
    READY = "READY"
    ARMED = "ARMED"
    RUNNING = "RUNNING"
    DETONATING = "DETONATING"
    COLLECTING = "COLLECTING"
    TEARING_DOWN = "TEARING_DOWN"
    TEARDOWN = "TEARDOWN"
    COMPLETED = "COMPLETED"
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"
    FAILED = "FAILED"



class SandboxStateError(_CommonSandboxStateError):
    """
    Raised when a SandboxController method is called from a state it isn't
    legal from -- e.g. detonate() called before arm(), or detonate() called
    a second time without an intervening arm().

    Subclasses adam.common.errors.SandboxStateError (the frozen tree's own
    leaf name) under an identical short name -- see this module's docstring
    for why. `except adam.common.errors.SandboxStateError`,
    `except adam.common.errors.SandboxError`, and
    `except adam.common.errors.AdamError` all now match this class, in
    addition to the existing `except SandboxStateError` call sites, which
    are unaffected.
    """

    def __init__(
        self,
        current_state: SandboxState,
        attempted_operation: str,
        expected_states: tuple[SandboxState, ...],
    ) -> None:
        self.current_state = current_state
        self.attempted_operation = attempted_operation
        self.expected_states = expected_states
        expected = ", ".join(s.value for s in expected_states)
        super().__init__(
            f"cannot {attempted_operation} from state {current_state.value} "
            f"(expected one of: {expected})"
        )


class SandboxOperationError(VMOperationError):
    """
    Raised when a legal operation's underlying VirtualBoxClient call itself
    fails during prepare() or arm() -- restore_snapshot, start,
    wait_for_state, wait_for_guest_ready, or copy_to_guest reporting
    failure, or VBoxManage being unreachable entirely. Drives the
    controller to FAILED.

    Deliberately NOT raised for detonate()'s sample-execution outcome -- a
    sample crashing or returning a non-zero exit code is data about the
    sample, not an infrastructure failure, and detonate() returns its
    VMOperationResult as-is rather than raising for it. VBoxManage being
    unreachable *during* detonate() is still an infrastructure failure,
    though, and does raise this -- see controller.py's detonate().

    Subclasses adam.common.errors.VMOperationError: every failure mode
    listed above is "VBoxManage failed" (section 14.1's own description of
    that leaf), the same underlying category VBoxCommandError represents
    at the client layer -- this is that same failure surfaced at the
    controller layer. detail is either a VMOperationResult (operation-level
    failure) or a VBoxCommandError (VBoxManage itself unreachable) -- kept
    as the raw object rather than pre-formatted, so a caller can inspect
    whichever fields matter to them.
    """

    def __init__(self, operation: str, detail: object) -> None:
        self.operation = operation
        self.detail = detail
        super().__init__(f"{operation} failed: {detail}")
