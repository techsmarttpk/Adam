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

import asyncio
import logging
from typing import Coroutine, Any

from adam.contracts.interfaces import MutationRequest, MutationResult
from adam.contracts.session import SampleRef
from adam.sandbox.guest.channel import GuestChannel
from adam.sandbox.guest.http_models import GuestAgentUnreachableError
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
        guest_channel: GuestChannel | None = None,
        guest_agent: GuestChannel | None = None,
        boot_timeout: float = 60.0,
        guest_ready_timeout: float = 150.0,
        detonate_timeout: float = 300.0,
        headless: bool = True,
    ) -> None:
        self._client = client
        self._vm_name = vm_name
        self._snapshot_name = snapshot_name
        self._guest_username = guest_username
        self._guest_password = guest_password
        self._guest_channel = guest_channel or guest_agent
        self._boot_timeout = boot_timeout
        self._guest_ready_timeout = guest_ready_timeout
        self._detonate_timeout = detonate_timeout
        self._state = SandboxState.COLD
        self.vm_profile = None
        self._headless = headless

        # Recorded by arm(), consumed by detonate(sample)
        self._armed_guest_target_path: str | None = None

        self._last_detonation_result: VMOperationResult | None = None
        self._last_detonated_sample: SampleRef | None = None

    @property
    def state(self) -> SandboxState:
        return self._state

    @property
    def last_detonation_result(self) -> VMOperationResult | None:
        return self._last_detonation_result

    @property
    def last_detonated_sample(self) -> SampleRef | None:
        return self._last_detonated_sample

    @property
    def guest_channel(self) -> GuestChannel | None:
        return self._guest_channel

    # ------------------------------------------------------------------ #
    # internal
    # ------------------------------------------------------------------ #

    def _require_state(self, operation: str, *expected: SandboxState) -> None:
        if self._state not in expected:
            raise SandboxStateError(self._state, operation, expected)

    @staticmethod
    async def _step(operation: str, coro: "Coroutine[Any, Any, VMOperationResult]") -> VMOperationResult:
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
        COLD -> PROVISIONING -> RESTORING -> BOOTING -> AGENT_HANDSHAKE -> READY.

        Restores the clean snapshot, starts the VM, waits for VirtualBox to
        report it running, waits for Guest Additions, performs agent handshake,
        and transitions to READY. Guaranteed snapshot restore on any failure past PROVISIONING.
        """
        self._require_state("prepare", SandboxState.COLD)
        self._state = SandboxState.PROVISIONING

        try:
            current_state = await self._client.get_state(self._vm_name)
            if current_state in ("running", "paused", "stuck"):
                await self._client.stop(self._vm_name, mode="poweroff")
            elif current_state == "saved":
                await self._client.discard_saved_state(self._vm_name)

            self._state = SandboxState.RESTORING
            await self._step(
                "restore_snapshot",
                self._client.restore_snapshot(self._vm_name, self._snapshot_name),
            )
            await asyncio.sleep(2.0)

            # Apply profile hardware if specified
            if getattr(self, "vm_profile", None) and self.vm_profile != "bare_control":
                try:
                    from adam.sandbox.vbox.profile_applier import load_profile, apply_profile_hardware
                    profile = load_profile(f"win10_x64_{self.vm_profile}")
                    await apply_profile_hardware(self._client, self._vm_name, profile)
                except Exception as e:
                    logger.warning("Failed to apply profile hardware: %s", e)

            self._state = SandboxState.BOOTING

            await self._step("start", self._client.start(self._vm_name, headless=self._headless))
            await self._step(
                "wait_for_state(running)",
                self._client.wait_for_state(self._vm_name, "running", timeout=self._boot_timeout),
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

            self._state = SandboxState.AGENT_HANDSHAKE
            if self._guest_channel is not None:
                if hasattr(self._guest_channel, "wait_until_ready"):
                    await self._guest_channel.wait_until_ready()
                else:
                    await self._guest_channel.verify_tools()

                # Apply profile persona if specified
                if getattr(self, "vm_profile", None) and self.vm_profile != "bare_control":
                    try:
                        from adam.sandbox.vbox.profile_applier import load_profile, apply_profile_persona
                        profile = load_profile(f"win10_x64_{self.vm_profile}")
                        await apply_profile_persona(self._guest_channel, profile)
                    except Exception as e:
                        logger.warning("Failed to apply profile persona: %s", e)

        except Exception as exc:
            try:
                await self._client.stop(self._vm_name, mode="poweroff")
            except Exception:
                pass
            try:
                await self._client.restore_snapshot(self._vm_name, self._snapshot_name)
            except Exception:
                pass
            self._state = SandboxState.ERROR
            if isinstance(exc, SandboxOperationError):
                raise
            raise SandboxOperationError("prepare", exc) from exc

        self._state = SandboxState.READY

    async def arm(self, host_sample_path: str, guest_target_path: str, *, timeout: float = 60.0) -> None:
        """READY -> ARMED. Stages the sample onto the guest via HTTP agent (fallback to copy_to_guest)."""
        self._require_state("arm", SandboxState.READY)

        try:
            if self._guest_channel is not None and hasattr(self._guest_channel, "stage_sample"):
                try:
                    await self._guest_channel.stage_sample(
                        host_sample_path, guest_target_path, timeout=timeout
                    )
                except GuestAgentUnreachableError as exc:
                    logger.warning(
                        "HTTP guest agent unreachable during arm(), falling back to guestcontrol copyto: %s",
                        exc,
                    )
                    await self._step(
                        "copy_to_guest (fallback)",
                        self._client.copy_to_guest(
                            self._vm_name,
                            guest_username=self._guest_username,
                            guest_password=self._guest_password,
                            host_source_path=host_sample_path,
                            guest_target_path=guest_target_path,
                            timeout=timeout,
                        ),
                    )
            else:
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
        except Exception as exc:
            try:
                await self._client.stop(self._vm_name, mode="poweroff")
            except Exception:
                pass
            try:
                await self._client.restore_snapshot(self._vm_name, self._snapshot_name)
            except Exception:
                pass
            self._state = SandboxState.ERROR
            if isinstance(exc, SandboxOperationError):
                raise
            raise SandboxOperationError("arm", exc) from exc

        self._armed_guest_target_path = guest_target_path
        self._state = SandboxState.ARMED

    async def detonate(self, sample: SampleRef) -> None:
        """
        ARMED -> DETONATING (RUNNING) -> COLLECTING -> COMPLETED.
        Matches adam.contracts.interfaces.ISandboxController.detonate() exactly.
        Executes sample via HTTP agent /process/start (fallback to run_in_guest).
        """
        self._require_state("detonate", SandboxState.ARMED)
        assert self._armed_guest_target_path is not None, (
            "invariant violated: state is ARMED but no guest target path was "
            "recorded by arm() -- see arm()'s implementation"
        )
        self._state = SandboxState.DETONATING

        try:
            if self._guest_channel is not None and hasattr(self._guest_channel, "run_process"):
                try:
                    result = await self._guest_channel.run_process(
                        executable_path=self._armed_guest_target_path,
                        arguments=None,
                        wait=True,
                        timeout_s=self._detonate_timeout,
                    )
                except GuestAgentUnreachableError as exc:
                    logger.warning(
                        "HTTP guest agent unreachable during detonate(), falling back to guestcontrol run: %s",
                        exc,
                    )
                    result = await self._client.run_in_guest(
                        self._vm_name,
                        guest_username=self._guest_username,
                        guest_password=self._guest_password,
                        executable_path=self._armed_guest_target_path,
                        arguments=None,
                        timeout=self._detonate_timeout,
                    )
            else:
                result = await self._client.run_in_guest(
                    self._vm_name,
                    guest_username=self._guest_username,
                    guest_password=self._guest_password,
                    executable_path=self._armed_guest_target_path,
                    arguments=None,
                    timeout=self._detonate_timeout,
                )
        except VBoxCommandError as exc:
            try:
                await self._client.stop(self._vm_name, mode="poweroff")
            except Exception:
                pass
            try:
                await self._client.restore_snapshot(self._vm_name, self._snapshot_name)
            except Exception:
                pass
            self._state = SandboxState.ERROR
            raise SandboxOperationError("detonate (VBoxManage unreachable)", exc) from exc
        except Exception as exc:
            try:
                await self._client.stop(self._vm_name, mode="poweroff")
            except Exception:
                pass
            try:
                await self._client.restore_snapshot(self._vm_name, self._snapshot_name)
            except Exception:
                pass
            self._state = SandboxState.ERROR
            raise SandboxOperationError("detonate", exc) from exc

        self._state = SandboxState.COLLECTING
        self._last_detonation_result = result
        self._last_detonated_sample = sample
        self._state = SandboxState.COMPLETED

    async def apply_mutation(self, mutation: MutationRequest) -> MutationResult:
        """
        ISandboxController.apply_mutation() stub.
        """
        self._require_state("apply_mutation", SandboxState.RUNNING, SandboxState.DETONATING)
        raise NotImplementedError(
            "apply_mutation() is not yet implemented -- awaiting the "
            "Deception Engine (ARCHITECTURE.md section 5.6, Dev C). "
        )

    async def teardown(self) -> None:
        """
        Callable from ANY state, including COLD and ERROR / FAILED.
        Best-effort stop(poweroff) + restore_snapshot(clean); always ends
        in COLD. Never raises.
        """
        self._state = SandboxState.TEARING_DOWN

        try:
            state = await self._client.get_state(self._vm_name)
            if state in ("running", "paused", "stuck"):
                await self._client.stop(self._vm_name, mode="poweroff")
            elif state == "saved":
                await self._client.discard_saved_state(self._vm_name)
        except Exception:
            pass

        try:
            await self._client.restore_snapshot(self._vm_name, self._snapshot_name)
        except VBoxCommandError:
            pass

        self._state = SandboxState.COLD

