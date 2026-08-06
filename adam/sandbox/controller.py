"""
adam/sandbox/controller.py

SandboxController: the finite state machine from ARCHITECTURE.md section
5.2, wrapping VirtualBoxClient (Milestones 1-2) to provide a safe, ordered
prepare -> arm -> detonate -> teardown lifecycle for one VM.

Reconciled against adam.contracts.interfaces.ISandboxController (added once
adam/contracts/ existed -- see docs/remaining-work-plan.md, Immediate #2):
`detonate()` now takes a `SampleRef` and returns `None`, matching the
Protocol exactly, instead of the earlier `(guest_target_path, arguments,
timeout) -> VMOperationResult` shape. See `detonate()`'s own docstring for
how the guest path and timeout are now sourced. `apply_mutation()` is a new
stub required by the Protocol's full method set -- see its docstring.

`collect_artifacts()` is still deliberately not included. Real
telemetry/artifact retrieval depends on Collector Orchestration (Phase 7),
which doesn't exist yet -- adding a method that can't do anything real yet
would repeat the mistake avoided earlier with detonate() before guest
execution existed. This is a real, tracked gap against the full Protocol
(docs/remaining-work-plan.md, "Later" bucket item 17), not an oversight.

`detonate_timeout` is a plain constructor argument for now, same as
`boot_timeout`/`guest_ready_timeout` were before Milestone 4's
`adam.common.config` landed -- wiring it into `SandboxSettings` is tracked
separately (remaining-work-plan.md, Next #11 area) and should not change
this class's public interface when it happens.

Error-handling design (read this before changing a method):

  prepare() and arm() raise SandboxOperationError for ANY failure in their
  underlying VirtualBoxClient calls -- whether that's a VMOperationResult
  reporting success=False, or a VBoxCommandError (VBoxManage itself
  unreachable). Both mean the sandbox infrastructure isn't in the state it
  needs to be in, and both drive the controller to FAILED.

  detonate() treats these two failure modes differently, deliberately.
  VMOperationResult(success=False) -- including VirtualBox reporting a
  crash-looking NTSTATUS return code -- is returned to the caller as-is,
  never raised: that is data describing what the SAMPLE did, not a
  statement about the sandbox's own health. A VBoxCommandError during
  detonate() (VBoxManage itself unreachable) is different -- that IS an
  infrastructure failure regardless of which method it happens in, so it
  still raises SandboxOperationError and drives to FAILED, same as
  prepare()/arm().

  teardown() never raises anything. It is the method a `finally` block
  depends on (ARCHITECTURE.md section 14.4), so every VirtualBoxClient call
  inside it is individually guarded and best-effort.
"""

from __future__ import annotations

import logging
from typing import Coroutine, Any

from adam.contracts.interfaces import MutationRequest, MutationResult
from adam.contracts.session import SampleRef
from adam.sandbox.state import SandboxOperationError, SandboxState, SandboxStateError
from adam.sandbox.vbox.client import VBoxCommandError, VirtualBoxClient
from adam.sandbox.vbox.models import VMOperationResult

logger = logging.getLogger(__name__)


class SandboxController:
    """See module docstring for scope and error-handling design."""

    def __init__(
        self,
        client: VirtualBoxClient,
        vm_name: str,
        *,
        snapshot_name: str = "clean",
        guest_username: str,
        guest_password: str,
        boot_timeout: float = 60.0,
        guest_ready_timeout: float = 150.0,
        detonate_timeout: float = 300.0,
    ) -> None:
        self._client = client
        self._vm_name = vm_name
        self._snapshot_name = snapshot_name
        self._guest_username = guest_username
        self._guest_password = guest_password
        self._boot_timeout = boot_timeout
        self._guest_ready_timeout = guest_ready_timeout
        self._detonate_timeout = detonate_timeout
        self._state = SandboxState.COLD

        # Recorded by arm(), consumed by detonate(sample) -- see detonate()'s
        # docstring for why the guest path is no longer a detonate() argument.
        self._armed_guest_target_path: str | None = None

        # Introspection only -- ISandboxController.detonate() returns None
        # (matching the Protocol), so a caller that needs the underlying
        # VMOperationResult (exit code, stdout/stderr, termination_reason)
        # reads it here immediately afterwards, same information as before,
        # just not smuggled through the return value.
        self._last_detonation_result: VMOperationResult | None = None
        self._last_detonated_sample: SampleRef | None = None

    @property
    def state(self) -> SandboxState:
        return self._state

    @property
    def last_detonation_result(self) -> VMOperationResult | None:
        """
        The VMOperationResult from the most recent detonate() call, or None
        if detonate() has never been called. See __init__'s comment: this
        exists because ISandboxController.detonate() returns None, so this
        is how a caller recovers the same success/return_code/stdout/stderr/
        termination_reason detail the pre-Phase-2 detonate() used to return
        directly.
        """
        return self._last_detonation_result

    @property
    def last_detonated_sample(self) -> SampleRef | None:
        """The SampleRef passed to the most recent detonate() call, or None."""
        return self._last_detonated_sample

    # ------------------------------------------------------------------ #
    # internal
    # ------------------------------------------------------------------ #

    def _require_state(self, operation: str, *expected: SandboxState) -> None:
        if self._state not in expected:
            raise SandboxStateError(self._state, operation, expected)

    @staticmethod
    async def _step(operation: str, coro: "Coroutine[Any, Any, VMOperationResult]") -> VMOperationResult:
        """
        Await coro (a VirtualBoxClient call used by prepare()/arm()) and
        raise SandboxOperationError uniformly whether the failure is a
        VMOperationResult(success=False) or a VBoxCommandError -- both are
        infrastructure failures from prepare()/arm()'s point of view. Not
        used by detonate(), which treats these two cases differently (see
        module docstring).
        """
        try:
            result = await coro
        except VBoxCommandError as exc:
            raise SandboxOperationError(operation, exc) from exc
        if not result.success:
            raise SandboxOperationError(operation, result)
        return result

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #

    async def prepare(self) -> None:
        """
        COLD -> RESTORING -> BOOTING -> READY.

        Restores the clean snapshot, starts the VM, waits for VirtualBox to
        report it running, then waits for Guest Additions to respond.
        """
        self._require_state("prepare", SandboxState.COLD)
        self._state = SandboxState.RESTORING

        try:
            await self._step(
                "restore_snapshot",
                self._client.restore_snapshot(self._vm_name, self._snapshot_name),
            )

            self._state = SandboxState.BOOTING

            logger.info("sandbox: Waiting for VM... (vm=%s, timeout=%.1fs)", self._vm_name, self._boot_timeout)
            await self._step("start", self._client.start(self._vm_name, headless=True))
            await self._step(
                "wait_for_state(running)",
                self._client.wait_for_state(self._vm_name, "running", timeout=self._boot_timeout),
            )
            logger.info("sandbox: VM ready.")

            logger.info(
                "sandbox: Waiting for Guest Additions... (vm=%s, timeout=%.1fs)",
                self._vm_name, self._guest_ready_timeout,
            )
            await self._step(
                "wait_for_guest_ready",
                self._client.wait_for_guest_ready(
                    self._vm_name,
                    guest_username=self._guest_username,
                    guest_password=self._guest_password,
                    timeout=self._guest_ready_timeout,
                ),
            )
            logger.info("sandbox: Guest Additions ready.")
        except SandboxOperationError:
            self._state = SandboxState.FAILED
            raise

        self._state = SandboxState.READY

    async def arm(self, host_sample_path: str, guest_target_path: str, *, timeout: float = 30.0) -> None:
        """READY -> ARMED. Copies the sample onto the guest."""
        self._require_state("arm", SandboxState.READY)

        try:
            await self._step(
                "copy_to_guest",
                self._client.copy_to_guest(
                    self._vm_name,
                    guest_username=self._guest_username,
                    guest_password=self._guest_password,
                    host_source_path=host_sample_path,
                    guest_target_path=guest_target_path,
                    timeout=timeout,
                ),
            )
        except SandboxOperationError:
            self._state = SandboxState.FAILED
            raise

        self._armed_guest_target_path = guest_target_path
        self._state = SandboxState.ARMED

    async def detonate(self, sample: SampleRef) -> None:
        """
        ARMED -> RUNNING -> COMPLETED. Matches
        adam.contracts.interfaces.ISandboxController.detonate() exactly.

        Executes the sample previously delivered by arm() -- at the guest
        path arm() copied it to, recorded in self._armed_guest_target_path
        -- and blocks until it exits or self._detonate_timeout elapses. No
        separate `arguments`/`timeout` parameters exist anymore, per the
        Protocol: a sandbox detonates the sample it was armed with, run
        directly, not an arbitrary guest command. `sample` is recorded via
        last_detonated_sample for introspection/future session metrics but
        is not otherwise required to match the armed file -- arm() and
        detonate() are not currently cross-validated against each other's
        SampleRef, since arm()'s host_sample_path is still a plain path (see
        arm()'s own signature); that reconciliation is a smaller, separate
        follow-up, not blocking here.

        The result -- including a non-zero return_code or a VBoxManage-
        reported crash -- is stored on self._last_detonation_result rather
        than returned (the Protocol's return type is None) and is never
        raised for; see module docstring. Only VBoxManage itself being
        unreachable raises (SandboxOperationError, wrapping the underlying
        VBoxCommandError), since that is an infrastructure failure rather
        than data about the sample.

        State moves to RUNNING the instant the sample is dispatched and to
        COMPLETED synchronously before this method returns (on the success
        path) -- a caller polling .state from a separate task sees an
        honest read throughout.
        """
        self._require_state("detonate", SandboxState.ARMED)
        assert self._armed_guest_target_path is not None, (
            "invariant violated: state is ARMED but no guest target path was "
            "recorded by arm() -- see arm()'s implementation"
        )
        self._state = SandboxState.RUNNING

        try:
            result = await self._client.run_in_guest(
                self._vm_name,
                guest_username=self._guest_username,
                guest_password=self._guest_password,
                executable_path=self._armed_guest_target_path,
                arguments=None,
                timeout=self._detonate_timeout,
            )
        except VBoxCommandError as exc:
            self._state = SandboxState.FAILED
            raise SandboxOperationError("detonate (VBoxManage unreachable)", exc) from exc

        self._last_detonation_result = result
        self._last_detonated_sample = sample
        self._state = SandboxState.COMPLETED

    async def apply_mutation(self, mutation: MutationRequest) -> MutationResult:
        """
        ISandboxController.apply_mutation() -- ARCHITECTURE.md sections 5.2
        (this class exposes it) and 5.6 (Dev C's Deception Engine calls it).

        Not yet implemented: applying a deception primitive inside the guest
        is the Deception Engine's concern, and that engine doesn't exist yet
        (Phase blocked per docs/implementation-audit.md). This stub exists
        so SandboxController satisfies the full ISandboxController Protocol
        surface -- checkable via isinstance()/mypy -- ahead of that engine
        landing, per docs/remaining-work-plan.md's Immediate bucket, rather
        than silently missing one Protocol method the way it did before
        Phase 2 existed to check against.

        Deliberately still validates state (a mutation request against a
        controller that isn't RUNNING is a caller error worth surfacing
        distinctly from "not implemented yet") before raising.
        """
        self._require_state("apply_mutation", SandboxState.RUNNING)
        raise NotImplementedError(
            "apply_mutation() is not yet implemented -- awaiting the "
            "Deception Engine (ARCHITECTURE.md section 5.6, Dev C). "
            "Tracked in docs/remaining-work-plan.md, 'Next' bucket item 10."
        )

    async def teardown(self) -> None:
        """
        Callable from ANY state, including COLD (no-op-ish) and FAILED.
        Best-effort stop(poweroff) + restore_snapshot(clean); always ends
        in COLD. Never raises.
        """
        self._state = SandboxState.TEARDOWN

        try:
            await self._client.stop(self._vm_name, mode="poweroff")
        except VBoxCommandError:
            pass  # best-effort: VBoxManage unreachable is not fixable by raising here

        try:
            await self._client.restore_snapshot(self._vm_name, self._snapshot_name)
        except VBoxCommandError:
            pass  # same reasoning

        self._state = SandboxState.COLD
