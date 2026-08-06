"""
adam/sandbox/vbox/client.py

VirtualBoxClient: the only component in ADAM permitted to shell out to
VBoxManage directly (ARCHITECTURE.md section 5.2). Every other module that
needs VM control goes through this wrapper -- never through subprocess
calls of its own.

Milestone scope (Milestone 1 -- VirtualBox integration de-risking): prove
Python can reliably detect, query, start, stop, and snapshot-restore the
ADAM_WIN10_OFFICE VM. No event bus, no configuration framework, no
structured logging, no ADAM-level state machine -- those are later
milestones (Sandbox Controller, Configuration, Logging, Collector
Orchestration) layered on top of this file, not inside it.

Milestone 2 addition -- guest execution (TEMPORARY BRIDGE): run_in_guest,
wait_for_guest_ready, and copy_to_guest use VBoxManage's built-in
guestcontrol to prove out execution and file transfer into the guest,
ahead of the HTTP-based custom agent ARCHITECTURE.md section 15.3 actually
commits to. They require Guest Additions running in the guest and a valid
guest OS account. Once the real agent exists, these three methods should
be considered deprecated, not extended further -- resist building more
guestcontrol-based features on top of this bridge.

Naming note: this class is VirtualBoxClient, not VBoxClient, so that a
future provider-agnostic abstraction (SandboxProvider -> VirtualBoxClient /
VMwareClient / QemuClient) can be introduced later without a rename. No such
base class exists yet -- building it now would be exactly the kind of
premature abstraction this milestone's "no business logic beyond VirtualBox
automation" constraint rules out. ARCHITECTURE.md commits to VirtualBox as
the technology stack for this project; provider-agnosticism is future
extensibility (see ARCHITECTURE.md section 18), not a current requirement.

Error-handling design (read this before adding a method):

  Query methods -- get_version, vm_exists, get_state, snapshot_exists,
  list_snapshots -- raise VBoxCommandError when the command fails
  unexpectedly. There is no meaningful "partial" value to return for a
  failed query, so the exception is the whole signal. The one exception to
  the exception: "not found" is not a failure. vm_exists and
  snapshot_exists return False for a clean not-found case; list_snapshots
  returns an empty list when a real VM genuinely has zero snapshots.

  State-changing methods -- start, stop, restore_snapshot, wait_for_state,
  and (Milestone 2) run_in_guest, wait_for_guest_ready, copy_to_guest --
  never raise for a VirtualBox-reported failure. VM already running, VM
  already stopped, snapshot not found, restore attempted on a running VM,
  wait timed out, guest command timed out, bad guest credentials: all of
  these come back as a VMOperationResult with success=False and
  VirtualBox's own message in stderr, not an exception. These are exactly
  the edge cases explicitly required to be understood now (see
  scripts/manual_test_vbox_client.py and manual_test_guest_execution.py) --
  a returned result you can inspect in a print statement serves that
  better than an exception you have to catch for every single call.

  Across both categories, VBoxCommandError is always raised if VBoxManage
  itself cannot be started at all (binary missing, permission denied) --
  that is an environment fault, not an operation outcome, and it can happen
  to a query or an operation call equally.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Literal

from adam.common.errors import VMOperationError
from adam.sandbox.vbox.models import SnapshotInfo, VMOperationResult
from adam.sandbox.vbox.ntstatus import decode_ntstatus

_STATE_LINE = re.compile(r'^VMState="([^"]+)"')
_SNAPSHOT_NAME = re.compile(r'^SnapshotName(-\d+)?="([^"]*)"')
_SNAPSHOT_UUID = re.compile(r'^SnapshotUUID(-\d+)?="([^"]*)"')
_CURRENT_SNAPSHOT_UUID = re.compile(r'^CurrentSnapshotUUID="([^"]*)"')


class VBoxCommandError(VMOperationError):
    """
    Raised when VBoxManage cannot be invoked at all (binary missing,
    permission denied) or when a query command fails unexpectedly.

    Carries the full diagnostic picture as attributes -- command,
    return_code, stdout, stderr -- rather than collapsing them into a
    single generic message string. `message` is a short human-readable
    summary of *what went wrong*; the raw command output is preserved
    untouched alongside it, so a caller (or a person reading a traceback)
    can see exactly what VBoxManage actually said, not a paraphrase of it.

    Folded into adam.common.errors' hierarchy as a VMOperationError
    (ARCHITECTURE.md section 14.1: "VMOperationError -- VBoxManage
    failed", exactly this class's own description) per
    docs/remaining-work-plan.md's Next-bucket item 4. Every existing
    `except VBoxCommandError` call site is unaffected -- same class name,
    same constructor, same raise sites; only the base class changed, so
    `except VMOperationError`, `except SandboxError`, and
    `except AdamError` now also catch it.
    """

    def __init__(
        self,
        message: str,
        *,
        command: tuple[str, ...],
        return_code: int | None,
        stdout: str,
        stderr: str,
    ) -> None:
        self.message = message
        self.command = command
        self.return_code = return_code
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"{message}\n"
            f"  command:     {' '.join(command)}\n"
            f"  return_code: {return_code}\n"
            f"  stdout:      {stdout.strip()}\n"
            f"  stderr:      {stderr.strip()}"
        )


class VirtualBoxClient:
    """Thin async wrapper around the VBoxManage CLI. See module docstring for error-handling design."""

    def __init__(self, vboxmanage_path: str = "VBoxManage") -> None:
        self._vboxmanage_path = vboxmanage_path

    # ------------------------------------------------------------------ #
    # internal
    # ------------------------------------------------------------------ #

    async def _run(self, *args: str, timeout: float | None = None) -> VMOperationResult:
        """
        Invoke VBoxManage with the given arguments and capture the outcome.

        Never raises for a non-zero VBoxManage exit -- that is reported via
        VMOperationResult.success. Raises VBoxCommandError only if the
        VBoxManage binary itself could not be started at all.

        timeout (seconds, default None = unbounded) bounds how long we wait
        for the command to finish. This parameter is additive: every method
        from Milestone 1 calls _run without it and is unaffected. It exists
        for Milestone 2's guest-execution methods, where a guest process
        that never exits would otherwise hang this call forever. On expiry
        the subprocess is killed and a VMOperationResult with success=False
        is returned -- not an exception, for the same reason a non-zero
        exit isn't one: VBoxManage behaved, it just didn't finish in time.
        Any partial stdout/stderr produced before the kill is not
        recovered -- a deliberate simplification, not a guarantee of
        best-effort output capture.
        """
        command = (self._vboxmanage_path, *args)
        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise VBoxCommandError(
                f"VBoxManage executable not found at '{self._vboxmanage_path}'",
                command=command,
                return_code=None,
                stdout="",
                stderr=str(exc),
            ) from exc
        except OSError as exc:
            raise VBoxCommandError(
                f"failed to launch VBoxManage: {exc}",
                command=command,
                return_code=None,
                stdout="",
                stderr=str(exc),
            ) from exc

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            duration_ms = (time.monotonic() - start) * 1000
            return VMOperationResult(
                success=False,
                command=command,
                duration_ms=duration_ms,
                return_code=-1,
                stdout="",
                stderr=f"timed out after {timeout}s and was killed",
                termination_reason=decode_ntstatus(-1),  # always None; kept for consistency
            )

        duration_ms = (time.monotonic() - start) * 1000
        return_code = proc.returncode if proc.returncode is not None else -1

        return VMOperationResult(
            success=(proc.returncode == 0),
            command=command,
            duration_ms=duration_ms,
            return_code=return_code,
            stdout=stdout_bytes.decode(errors="replace"),
            stderr=stderr_bytes.decode(errors="replace"),
            termination_reason=decode_ntstatus(return_code),
        )

    @staticmethod
    def _require_success(result: VMOperationResult) -> VMOperationResult:
        """Raise VBoxCommandError for query paths, which have no other way to signal failure."""
        if not result.success:
            raise VBoxCommandError(
                "VBoxManage command failed",
                command=result.command,
                return_code=result.return_code,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        return result

    # ------------------------------------------------------------------ #
    # detection / query
    # ------------------------------------------------------------------ #

    async def get_version(self) -> str:
        """Return VBoxManage's reported version string. Proves VirtualBox is installed and reachable."""
        result = self._require_success(await self._run("--version"))
        return result.stdout.strip()

    async def vm_exists(self, vm_name: str) -> bool:
        """True if a VM registered under vm_name exists. False for a clean not-found -- never raises for that case."""
        result = self._require_success(await self._run("list", "vms"))
        # Each line looks like: "ADAM_WIN10_OFFICE" {8b2e2222-...-...}
        needle = f'"{vm_name}"'
        return any(line.startswith(needle) for line in result.stdout.splitlines())

    async def get_state(self, vm_name: str) -> str:
        """
        Return VirtualBox's native power-state string for vm_name verbatim
        (e.g. "running", "poweroff", "saved", "paused").

        Deliberately NOT mapped to an ADAM-specific enum -- that mapping is
        the Sandbox Controller FSM's job (a later milestone). Keeping this thin
        is what lets the FSM own its own state semantics without this file
        needing to change every time the FSM's states do.
        """
        result = self._require_success(await self._run("showvminfo", vm_name, "--machinereadable"))
        for line in result.stdout.splitlines():
            match = _STATE_LINE.match(line)
            if match:
                return match.group(1)
        raise VBoxCommandError(
            f"VMState not found in showvminfo output for '{vm_name}'",
            command=result.command,
            return_code=result.return_code,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    async def snapshot_exists(self, vm_name: str, snapshot_name: str) -> bool:
        """True if a snapshot named snapshot_name exists for vm_name."""
        snapshots = await self.list_snapshots(vm_name)
        return any(snapshot.name == snapshot_name for snapshot in snapshots)

    async def list_snapshots(self, vm_name: str) -> list[SnapshotInfo]:
        """
        Return every snapshot registered against vm_name, parsed from
        `VBoxManage snapshot <vm> list --machinereadable`.

        A VM with zero snapshots is not an error -- VBoxManage reports it as
        a failed command with a "does not have any snapshots" message, which
        this method translates into an empty list. An invalid/nonexistent
        VM name is a real error and raises VBoxCommandError, since there is
        no way to distinguish "empty but valid" from "invalid" without it.
        """
        result = await self._run("snapshot", vm_name, "list", "--machinereadable")
        if not result.success:
            if "does not have any snapshots" in result.stderr:
                return []
            raise VBoxCommandError(
                "failed to list snapshots",
                command=result.command,
                return_code=result.return_code,
                stdout=result.stdout,
                stderr=result.stderr,
            )

        current_uuid: str | None = None
        # key -> [name, uuid]; key is "" for the top-level snapshot, "-1", "-2", ...
        # for VirtualBox's one level of child numbering (see SnapshotInfo docstring
        # re: deeper nesting not being handled).
        pairs: dict[str, list[str | None]] = {}

        for line in result.stdout.splitlines():
            if match := _CURRENT_SNAPSHOT_UUID.match(line):
                current_uuid = match.group(1)
                continue
            if match := _SNAPSHOT_NAME.match(line):
                key = match.group(1) or ""
                pairs.setdefault(key, [None, None])[0] = match.group(2)
                continue
            if match := _SNAPSHOT_UUID.match(line):
                key = match.group(1) or ""
                pairs.setdefault(key, [None, None])[1] = match.group(2)

        snapshots: list[SnapshotInfo] = []
        for name, uuid in pairs.values():
            if name is None or uuid is None:
                continue
            snapshots.append(SnapshotInfo(name=name, uuid=uuid, is_current=(uuid == current_uuid)))
        return snapshots

    # ------------------------------------------------------------------ #
    # state-changing operations
    # ------------------------------------------------------------------ #

    async def start(self, vm_name: str, headless: bool = True) -> VMOperationResult:
        """
        Start vm_name. Returns a VMOperationResult regardless of outcome --
        including when the VM is already running, which VBoxManage reports
        as a failed command ("already running") rather than a silent no-op.
        """
        vm_type = "headless" if headless else "gui"
        return await self._run("startvm", vm_name, "--type", vm_type)

    async def stop(self, vm_name: str, mode: Literal["acpi", "poweroff"] = "acpi") -> VMOperationResult:
        """
        Stop vm_name. "acpi" sends a graceful shutdown signal the guest may
        never act on if nothing inside it is listening -- pair this with
        wait_for_state to detect that rather than assuming it worked.
        "poweroff" is immediate and unconditional.

        Calling this when the VM is already stopped returns success=False
        with VBoxManage's own "not currently running" message in stderr --
        not treated as an ADAM-level error, just reported as-is.
        """
        subcommand = "acpipowerbutton" if mode == "acpi" else "poweroff"
        return await self._run("controlvm", vm_name, subcommand)

    async def restore_snapshot(self, vm_name: str, snapshot_name: str) -> VMOperationResult:
        """
        Restore snapshot_name for vm_name.

        Does not check snapshot_exists() or VM power state first --
        VirtualBox's own errors for "no such snapshot" and "machine must be
        powered off" are returned verbatim in the result rather than
        pre-validated here, so callers see exactly what VirtualBox says.
        Pre-flight guarding belongs to the Sandbox Controller (a later
        milestone), which has the state-machine context to decide what to
        do about a failed restore.
        """
        return await self._run("snapshot", vm_name, "restore", snapshot_name)

    async def wait_for_state(
        self,
        vm_name: str,
        expected_state: str,
        timeout: float,
        poll_interval: float = 1.0,
    ) -> VMOperationResult:
        """
        Poll get_state(vm_name) until it equals expected_state or timeout
        (seconds) elapses. Exists so callers don't each hand-roll their own
        polling loop around get_state().

        Reuses VMOperationResult rather than introducing a fourth model:
        command is a synthetic marker for the wait itself, stdout carries
        the last observed state, success reflects whether expected_state
        was reached in time.

        Note: get_state() itself still raises VBoxCommandError if a single
        poll's showvminfo call fails outright (e.g. the VM was unregistered
        mid-wait). That exception propagates out of wait_for_state rather
        than being swallowed into a timeout result -- a genuine query
        failure is an environment fault, not a "didn't reach state in time"
        outcome, and conflating the two would hide a real problem.
        """
        command = (self._vboxmanage_path, "wait_for_state", vm_name, expected_state)
        start = time.monotonic()
        last_state = ""

        while True:
            last_state = await self.get_state(vm_name)
            elapsed = time.monotonic() - start

            if last_state == expected_state:
                return VMOperationResult(
                    success=True,
                    command=command,
                    duration_ms=elapsed * 1000,
                    return_code=0,
                    stdout=last_state,
                    stderr="",
                )

            if elapsed >= timeout:
                return VMOperationResult(
                    success=False,
                    command=command,
                    duration_ms=elapsed * 1000,
                    return_code=-1,
                    stdout=last_state,
                    stderr=(
                        f"timed out after {timeout}s waiting for state "
                        f"'{expected_state}', last observed '{last_state}'"
                    ),
                )

            await asyncio.sleep(poll_interval)

    # ------------------------------------------------------------------ #
    # guest execution -- TEMPORARY BRIDGE (Milestone 2)
    #
    # Uses VBoxManage's built-in guestcontrol to prove out execution and
    # file transfer into the guest, ahead of the HTTP-based custom agent
    # ARCHITECTURE.md section 15.3 actually commits to. Requires Guest
    # Additions running in the guest and a valid guest OS account. Once
    # the real agent exists, these three methods should be considered
    # deprecated, not extended further.
    # ------------------------------------------------------------------ #

    async def run_in_guest(
        self,
        vm_name: str,
        *,
        guest_username: str,
        guest_password: str,
        executable_path: str,
        arguments: list[str] | None = None,
        timeout: float | None = None,
        unquoted_args: bool = False,
    ) -> VMOperationResult:
        """
        Run executable_path inside the guest via `VBoxManage guestcontrol
        run`, waiting for it to exit and capturing stdout/stderr/exit code.

        timeout is not optional in practice: a guest process that never
        exits will otherwise hang this call forever (see _run's timeout
        handling). Pass an explicit value for anything that isn't a
        known-fast command.

        Credentials are passed as plain arguments, not stored on the
        client -- they are session-specific inputs, not fixed
        configuration, and this avoids holding a guest password on a
        long-lived object. They are visible in the host's process listing
        while this command runs; that is a VBoxManage limitation, not
        something this wrapper can hide.

        unquoted_args: passes `--unquoted-args`, a real, documented
        VBoxManage guestcontrol option ("Disables escaped double quoting
        ... on arguments passed to the executed program" -- Oracle VM
        VirtualBox User Manual, "VBoxManage guestcontrol"). Defaults to
        False, preserving VBoxManage's own default argument-reconstruction
        behavior for every existing caller. Set True only when a caller
        needs to build a single shell-composed command line itself byte-
        for-byte (e.g. one that mixes a space-containing path with `>`
        redirection for cmd.exe) and cannot tolerate VBoxManage silently
        re-quoting or re-escaping its own arguments underneath it --
        see adam/sandbox/guest/agent/agent.py's _export_network() for the
        one call site that needs this and why.
        """
        args = [
            "guestcontrol", vm_name, "run",
            "--username", guest_username,
            "--password", guest_password,
            "--exe", executable_path,
        ]
        if unquoted_args:
            args.append("--unquoted-args")
        args.extend(["--wait-stdout", "--wait-stderr"])
        if arguments:
            args.append("--")
            args.extend(arguments)
        return await self._run(*args, timeout=timeout)

    async def wait_for_guest_ready(
        self,
        vm_name: str,
        *,
        guest_username: str,
        guest_password: str,
        timeout: float,
        probe_timeout: float = 15.0,
        poll_interval: float = 2.0,
    ) -> VMOperationResult:
        """
        Poll a trivial guestcontrol command until it succeeds (Guest
        Additions / VBoxService responsive inside the guest) or timeout
        (seconds) elapses.

        guestcontrol calls attempted before VBoxService is up inside the
        guest fail unpredictably -- sometimes a clean error, sometimes a
        long hang. This exists so every other guest-execution call has a
        reliable "is it safe to proceed" check to make first, the same
        role wait_for_state plays for VM power state.

        Three independent time budgets, deliberately not conflated:
          - timeout: the overall budget for this method, across every retry.
          - probe_timeout: how long a SINGLE guestcontrol attempt is allowed
            to take before it's killed and counted as "not ready yet."
          - poll_interval: how long to sleep between attempts.

        probe_timeout was originally hardcoded to equal poll_interval (2.0s),
        which is wrong: a single guestcontrol round trip (authenticate,
        open a guest session, spawn cmd.exe, wait for exit, tear the
        session down) has real overhead that can legitimately exceed a
        couple of seconds even when the guest is perfectly healthy --
        VBoxService running, Guest Additions ready, nothing hung. With the
        old code, every attempt that took longer than poll_interval got
        killed and counted as a failed readiness check, so the loop could
        exhaust the entire outer timeout retrying an operation that was
        never actually failing, just consistently running a bit long.
        probe_timeout gives each attempt room to genuinely finish; raising
        the outer timeout alone would not have fixed this, since the
        per-attempt cap was the actual bottleneck.
        """
        command = (self._vboxmanage_path, "wait_for_guest_ready", vm_name)
        start = time.monotonic()
        last_stderr = ""
        attempt = 0

        while True:
            attempt += 1

            # ============================================================ #
            # TEMPORARY DIAGNOSTIC -- readiness intermittent-failure
            # investigation. Remove once root cause is confirmed, or
            # replace with real structured logging once Milestone 5 lands.
            # ============================================================ #
            elapsed_before = time.monotonic() - start
            try:
                vm_state_before = await self.get_state(vm_name)
            except VBoxCommandError as exc:
                vm_state_before = f"<error querying state: {exc.message}>"
            probe_start_ts = time.time()
            print(
                f"[DIAG wait_for_guest_ready] attempt={attempt} "
                f"elapsed_since_entry={elapsed_before:.2f}s "
                f"vm_state_before_probe={vm_state_before} "
                f"probe_start_ts={probe_start_ts:.3f}"
            )
            # ============================================================ #

            probe = await self.run_in_guest(
                vm_name,
                guest_username=guest_username,
                guest_password=guest_password,
                executable_path="cmd.exe",
                arguments=["/c", "exit 0"],
                timeout=probe_timeout,
            )

            # ============================================================ #
            # TEMPORARY DIAGNOSTIC (continued)
            # ============================================================ #
            probe_end_ts = time.time()
            probe_duration = probe_end_ts - probe_start_ts
            if probe.success:
                outcome = "SUCCEEDED"
            elif probe.stderr.startswith("timed out after") and "was killed" in probe.stderr:
                outcome = "TIMED_OUT (killed by _run's own asyncio.wait_for)"
            else:
                outcome = "VBOXMANAGE_ERROR (non-zero exit, not a timeout)"
            print(
                f"[DIAG wait_for_guest_ready] attempt={attempt} outcome={outcome} "
                f"probe_end_ts={probe_end_ts:.3f} probe_duration={probe_duration:.2f}s "
                f"return_code={probe.return_code} "
                f"command={' '.join(probe.command)}"
            )
            if probe.stdout.strip():
                print(f"[DIAG wait_for_guest_ready] attempt={attempt} guest_stdout={probe.stdout.strip()!r}")
            if probe.stderr.strip():
                print(f"[DIAG wait_for_guest_ready] attempt={attempt} guest_stderr={probe.stderr.strip()!r}")
            # ============================================================ #

            elapsed = time.monotonic() - start

            if probe.success:
                print(
                    f"[DIAG wait_for_guest_ready] READY after {attempt} attempt(s), "
                    f"total_elapsed={elapsed:.2f}s"
                )
                return VMOperationResult(
                    success=True,
                    command=command,
                    duration_ms=elapsed * 1000,
                    return_code=0,
                    stdout="guest additions ready",
                    stderr="",
                )

            last_stderr = probe.stderr
            if elapsed >= timeout:
                print(
                    f"[DIAG wait_for_guest_ready] GAVE UP after {attempt} attempt(s), "
                    f"total_elapsed={elapsed:.2f}s"
                )
                return VMOperationResult(
                    success=False,
                    command=command,
                    duration_ms=elapsed * 1000,
                    return_code=-1,
                    stdout="",
                    stderr=(
                        f"timed out after {timeout}s waiting for guest additions; "
                        f"last probe stderr: {last_stderr.strip()}"
                    ),
                )

            await asyncio.sleep(poll_interval)

    async def copy_to_guest(
        self,
        vm_name: str,
        *,
        guest_username: str,
        guest_password: str,
        host_source_path: str,
        guest_target_path: str,
        timeout: float | None = None,
    ) -> VMOperationResult:
        """
        Copy a single file from the host into the guest via
        `VBoxManage guestcontrol copyto`.

        This is the sample-transfer mechanism for this milestone only -- a
        deliberate, temporary stand-in for the ISO-mount transfer path
        described in the roadmap doc, chosen because it needs nothing
        beyond what guestcontrol already requires. Not intended to be
        extended into a general file-sync mechanism.
        """
        return await self._run(
            "guestcontrol", vm_name, "copyto",
            "--username", guest_username,
            "--password", guest_password,
            host_source_path, guest_target_path,
            timeout=timeout,
        )

    async def copy_from_guest(
        self,
        vm_name: str,
        *,
        guest_username: str,
        guest_password: str,
        guest_source_path: str,
        host_target_path: str,
        timeout: float | None = None,
    ) -> VMOperationResult:
        """
        Copy a single file from the guest onto the host via
        `VBoxManage guestcontrol copyfrom` -- the reverse direction of
        copy_to_guest(), added for Phase 5 (Guest Agent) to retrieve
        exported telemetry (Sysmon EVTX, ProcMon CSV, tshark EK JSON) after
        a session's captures have been stopped and converted in-guest.

        Same TEMPORARY BRIDGE category as copy_to_guest() and the other
        guestcontrol-based methods in this section -- see this section's
        own header comment. Not pre-validated against guest_source_path
        existing; a missing source comes back as success=False with
        VirtualBox's own error in stderr, same convention as every other
        state-changing method in this class.
        """
        return await self._run(
            "guestcontrol", vm_name, "copyfrom",
            "--username", guest_username,
            "--password", guest_password,
            guest_source_path, host_target_path,
            timeout=timeout,
        )

    async def start_in_guest(
        self,
        vm_name: str,
        *,
        guest_username: str,
        guest_password: str,
        executable_path: str,
        arguments: list[str] | None = None,
        timeout: float | None = None,
    ) -> VMOperationResult:
        """
        Launch executable_path inside the guest via `VBoxManage guestcontrol
        start`, WITHOUT waiting for it to exit -- the detached counterpart
        to run_in_guest(), added for Phase 5 (Guest Agent) to start
        long-running background captures (Procmon, tshark) that must keep
        running while the sample detonates, then be stopped explicitly by a
        later, separate call (there is no way to "wait for exit" on a
        process that isn't meant to exit on its own).

        `timeout` here bounds only the `guestcontrol start` invocation
        itself (VBoxManage confirming the process was launched inside the
        guest), not the launched process's own runtime -- unlike
        run_in_guest(), where timeout bounds the guest process's entire
        execution. A short default-ish value (the caller's own
        tool_verify_timeout_s-scale budget) is appropriate here; the
        launched process's actual lifetime is controlled separately, by
        whatever later sends it a stop signal (e.g. Procmon's own
        `/Terminate` switch, or `taskkill` for tshark -- see
        adam/sandbox/guest/agent/agent.py).

        Same credentials-as-plain-arguments caveat as run_in_guest() --
        see that method's docstring.
        """
        args = [
            "guestcontrol", vm_name, "start",
            "--username", guest_username,
            "--password", guest_password,
            "--exe", executable_path,
        ]
        if arguments:
            args.append("--")
            args.extend(arguments)
        return await self._run(*args, timeout=timeout)
