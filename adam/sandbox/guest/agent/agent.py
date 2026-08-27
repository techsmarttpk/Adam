r"""
adam/sandbox/guest/agent/agent.py

GuestAgent -- Phase 5 (Guest Agent & Host<->Guest Channel), scoped
pragmatically per this phase's own EXECUTION MODE instructions (see
"Design note" below) to host-orchestrated automation of the already-
installed guest telemetry tools (Sysmon, Procmon, tshark) via the existing
VirtualBoxClient guestcontrol bridge, NOT the PowerShell/HTTP agent
originally sketched in docs/dev-a-environment-and-roadmap.md's Phase 5
section.

Design note -- why this differs from the roadmap's literal Phase 5 spec.
docs/dev-a-environment-and-roadmap.md describes Phase 5 as building
`adam/sandbox/guest/agent/adam_agent.ps1` (a PowerShell HTTP listener
running inside the guest) plus a `channel.py` (an async httpx client on the
host talking to it). That remains the eventual, architecturally "correct"
design (ARCHITECTURE.md section 15.3 names `httpx` for exactly this
reason) and is NOT what this module implements. This module was built
against an explicit instruction whose own "Current implementation status"
names "GuestControl communication" as already complete and directs
automating telemetry generation on top of it -- i.e. it asks for Phase 5's
practical *outcome* (telemetry is captured and exported automatically, the
"session COMPLETED (0 raw events captured)" gap is fixed) via tooling
already proven reliable (VirtualBoxClient's guestcontrol methods), rather
than the new, unbuilt, unproven HTTP-agent path. This is a deliberate,
disclosed scope substitution, not a silent deviation: the PowerShell/HTTP
agent remains unbuilt, and adam/sandbox/vbox/client.py's guestcontrol
methods remain documented as a "TEMPORARY BRIDGE ... not extended
further" -- this module is the one disclosed, instructed exception to that
guidance, made because building an unproven HTTP listener under a
directive to execute directly and produce a runnable end state carries
materially higher risk than automating the bridge already known to work.

Responsibilities (the numbered lifecycle from this phase's own spec):
  1.   verify_tools()            -- check Procmon64.exe, tshark.exe, and the
                                     Sysmon log channel are reachable in the
                                     guest, and log the guest workspace
                                     directory layout. Never raises; returns
                                     a ToolAvailability report. See
                                     Guarantees.
  2-3. start_captures()          -- start Procmon (backing-file mode) and
                                     tshark, both detached
                                     (VirtualBoxClient.start_in_guest()),
                                     then independently verify each one
                                     actually took (process running,
                                     backing/capture file present).
  (4-5, sample execution + timeout, are SandboxController.detonate()'s job
  -- this class does not duplicate that. SessionOrchestrator calls
  detonate() between start_captures() and stop_export_and_fetch().)
  6-9. stop_export_and_fetch()   -- stop Procmon (/Terminate) and tshark
                                     (taskkill), export EVTX/CSV/EK-JSON
                                     in-guest, copy all three to the host
                                     session artifact directory, best-effort
                                     clean up the guest's own temp files.
  10.  (build/start SysmonCollector/ProcmonCollector/NetworkCollector from
       the returned TelemetryArtifacts) is
       adam.orchestrator.session.build_collectors_from_telemetry()'s job,
       called by SessionOrchestrator -- not this class's concern.

=====================================================================
DIAGNOSTICS -- read this before touching logging in this file.
=====================================================================
This module was heavily instrumented against a specific debugging
directive (see docs/implementation-audit.md's Phase 5 diagnostics note)
whose telemetry pipeline reached the guest, executed the sample, and
completed the session, but every one of Sysmon/Procmon/tshark's telemetry
still came back empty -- "the failures are now isolated to telemetry
generation," with no visibility into *why*. That directive's own words:
"DO NOT FIX THE BUGS YET. Instead, expose enough diagnostics that the real
bug becomes obvious," and explicitly: "Do not swallow failures... instead
include: original VBoxManage stderr, command executed, tool output,
directory listing, process status."

Two logging tiers, deliberately not one:
  - `logger.debug(...)` -- the exhaustive, per-call dump every single
    run_in_guest()/start_in_guest()/copy_from_guest() call produces via
    `_log_call()` below: executable, full argument list, the fully
    expanded command line, timeout, return code, success flag, duration,
    and stdout/stderr VERBATIM (never paraphrased, never replaced with a
    simplified message). Off by default (Python's logging module shows
    only WARNING+ with no handler configured) -- this is the "guarded
    behind a verbose/debug logging level" the directive asked for. Opt in
    via `adam run --verbose` (adam/cli/run.py) or any standard
    `logging.basicConfig(level=logging.DEBUG)` call.
  - `logger.info(...)` -- a readable, chronological timeline of milestones
    ("[GuestAgent] Start Procmon", "[GuestAgent] Backing file exists",
    ...) letting a whole session's telemetry lifecycle be reconstructed
    from logs without needing full DEBUG verbosity.
  - `logger.warning(...)` -- every existing "telemetry unavailable"
    message now ALSO carries the original VBoxManage stderr, the exact
    command that was run, and (for a missing file) a full directory
    listing of the capture directory inline in the same message -- this
    tier stays visible at default logging levels specifically so a
    real-VM failure is diagnosable without needing --verbose at all.

This instrumentation is intentionally verbose and, per the directive that
produced it, temporary -- once the real root cause behind a real-VM run is
identified and fixed, the DEBUG-tier dumps in particular are candidates
for trimming. Nothing here changes GuestAgent's public interface,
constructor signature, or method signatures; every addition is either a
new private helper or additional logging inside an existing method body.

Guarantees (this phase's own "Guarantees" section, reproduced as this
class's actual contract):
  - Always stop captures: stop_export_and_fetch() attempts the Procmon-stop
    and tshark-stop pipelines unconditionally and independently -- a
    failure in one never skips the other.
  - Always restore the VM: this class never touches VM power state or
    snapshots -- that remains exclusively SandboxController/teardown()'s
    job. This class only ever issues guestcontrol calls against an
    already-running, already-armed guest; SessionOrchestrator's existing
    try/finally around controller.teardown() is untouched by this class's
    presence, and nothing in this class can prevent teardown() from
    running.
  - Always clean up temporary files: guest-side capture files are best-
    effort deleted after a successful copy-to-host. A failed cleanup is
    logged, never raised -- and is not even load-bearing, since a leftover
    file in the guest is erased by the next session's snapshot restore
    regardless (see the Sysmon-log-freshness note below for the same
    underlying guarantee applied to a different problem).
  - Support partial telemetry: every one of verify_tools(),
    start_captures(), and stop_export_and_fetch()'s three per-source
    pipelines (Sysmon / Procmon / tshark) is independently wrapped -- one
    source failing at any step never raises out of this class and never
    prevents the other two from being attempted. TelemetryArtifacts'
    fields are `str | None`; `None` means "this source produced nothing
    usable this session," logged with a specific, now much more detailed,
    reason at the point of failure, never a silent gap.

Resolved -- tshark EK JSON conversion, "'C:\Program' is not recognized".
A real VM run showed VBoxManage's own argument-to-command-line
reconstruction does not reliably auto-quote a space-containing argv
element for this call shape (a `cmd.exe /c` command mixing one such
element with shell redirection), contrary to what the earlier Bug #1 fix
assumed. Fixed using the officially documented `--unquoted-args`
guestcontrol option (Oracle VM VirtualBox User Manual) to disable
VBoxManage's own quoting entirely, combined with a single, flat, non-
nested manual quote around only the one token that needs it -- see
_export_network()'s own inline comment for the full reasoning and why this
does not reintroduce the original Bug #1 nested-quote problem.

Known Issues -- GuestControl's filtered, non-elevated token. Two apparently
separate symptoms (Sysmon export access-denied; Procmon launches but never
captures) are suspected, on real-world evidence, to share ONE root cause:
VirtualBox GuestControl-launched processes run with a *filtered* Windows
access token even for an account that is nominally an administrator (the
same UAC "split token" behavior that applies to interactive admin sessions),
and GuestControl has no supported way to request an elevated one. This is
now backed by both this project's own real-VM evidence and independent,
external, official/documented sources -- not a guess:
  - Official confirmation GuestControl cannot elevate: the Oracle VM
    VirtualBox User Manual's "VBoxManage guestcontrol" reference documents
    no elevation flag on `run`/`start` at all, and VirtualBox's own bug
    tracker/forums (e.g. "[Solved] VERR_PROC_ELEVATION_REQUIRED (VirtualBox
    guestcontrol execute)", forums.virtualbox.org/viewtopic.php?t=94312)
    confirm attempting to launch a process that requires elevation via
    guestcontrol fails outright, and disabling UAC on the guest does not
    reliably fix it either -- this is a documented product limitation, not
    a configuration mistake in this codebase.
  - This project's own real-VM evidence: `whoami /groups` (captured by the
    probes below) shows `BUILTIN\Administrators` present but marked "Group
    used for deny only", with a Medium (not High) Mandatory Label -- the
    textbook signature of a filtered/non-elevated token.

Symptom 1 -- Sysmon EVTX export "Access is denied". `wevtutil epl <sysmon
channel> <path>` fails with "Access is denied" even though verify_tools()
independently confirms the Sysmon64 service is running, the channel exists,
and Get-WinEvent can enumerate events in it moments earlier in the same
session -- `wevtutil epl`'s specific export operation requires a privilege
(SeBackupPrivilege) or Event Log Readers membership genuinely active in the
token, which a filtered token doesn't have even if the account is nominally
a member of both groups.

Symptom 2 -- Procmon launches but never captures, then /Terminate hangs.
Confirmed on a real VM run: Procmon64.exe appears in `tasklist` (the process
object exists), but no `.pml` backing file is ever created, and a
subsequent `/Terminate` (already sent with `/AcceptEula` per Bug #3's fix)
hangs until timeout instead of completing. Procmon's own driver
(PROCMON*.SYS) requires SeLoadDriverPrivilege to load -- a real, externally
documented Sysinternals/Microsoft issue independent of this project ("Process
Monitor Error - Capture requires Administrators group membership",
learn.microsoft.com/en-us/answers/questions/433927; confirmed there that
even "Run as Administrator" does not help when the privilege itself has been
stripped from the token, and that the SYSTEM account or a genuinely-elevated
token is what actually succeeds). A process that starts but whose driver
never attaches would look exactly like this: alive in tasklist, no capture
ever happening, and /Terminate hanging because whatever Procmon uses to
signal the "real" running instance also depends on the driver being loaded.
Note this specifically REVISES an earlier, incorrect hypothesis: Procmon
does not inherently require an interactive desktop session to capture (a
Microsoft-documented technique runs it successfully from a fully
non-interactive Session 0 via Task Scheduler, provided the executing token
has SeLoadDriverPrivilege) -- so the fix target is the token's privilege
set, not GuestControl's interactive/non-interactive launch mode as such.

Per this project's own explicit instruction ("if the issue cannot be safely
fixed without architectural changes, preserve the diagnostics and document
the root cause; do not redesign the telemetry pipeline" / "do not replace
Procmon, do not redesign the capture pipeline"), neither symptom is blindly
"fixed" in code with a guessed workaround. What IS in code:
  - `_whoami_diagnostics()`: runs `whoami /groups` + `whoami /priv` and logs
    both, called from both _export_sysmon()'s failure path and
    start_captures()'s Procmon verification, so every real run directly
    confirms or refutes the filtered-token hypothesis rather than assuming
    it.
  - start_captures() additionally probes the running Procmon64.exe's own
    command line + session ID (`Get-CimInstance Win32_Process`, since
    tasklist shows neither) and whether its driver is actually loaded
    (`driverquery`) -- see _driverquery_grep()'s docstring.
  - _export_sysmon() additionally tries ONE documented alternate export
    mechanism before giving up -- see _export_sysmon_raw_copy_fallback():
    a direct file copy of the channel's own underlying .evtx file, which
    is a different Windows operation from wevtutil's "epl" API and might
    not be gated by the same privilege check. Whether it succeeds or fails
    is itself useful evidence, logged either way.
  Manual remediation (guest-side configuration, out of this class's own
  scope -- must be baked into the `clean` snapshot itself, since a runtime
  change made only in a live guest session is rolled back by the next
  session's snapshot restore): grant the automation account genuine
  SeBackupPrivilege and SeLoadDriverPrivilege (not merely present-but-
  disabled) via secpol.msc / Local Security Policy, add it to "Event Log
  Readers", or disable UAC's admin-approval-mode / linked-token filtering
  for that specific account (registry
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
  FilterAdministratorToken`). Whichever applies should be evident from the
  `whoami /priv` output this build now logs at the point of each failure.

Sysmon-log-freshness note. Sysmon is a continuously-running guest service
per this phase's own explicit environment note (already installed, already
logging -- installing or starting it is explicitly out of this class's
scope). Exporting its FULL operational log via `wevtutil epl` after every
session, rather than only events from this session's time window, relies
on SandboxController's own existing guarantee: every session's prepare()
restores the guest to the `clean` snapshot BEFORE booting, which rolls the
guest's Sysmon log back to whatever state it was in when that snapshot was
taken. As long as the `clean` snapshot was itself captured before (or with
an empty) Sysmon log, each session's full-log export contains only that
session's own records. This is a real, existing architectural guarantee
this class depends on, not a new assumption -- disclosed here because it
is the one place this class's correctness rests on something outside its
own code.

ProcMon-CSV-column note. adam.collectors.parsers.pml requires a
"Date & Time" CSV column that is a persisted GUI/registry setting inside
Procmon itself, not something a command-line export flag can force. This
class does NOT import adam.collectors.parsers.pml to pre-validate that
column (ARCHITECTURE.md section 5.1/P2: modules must not import siblings
-- adam/sandbox/ and adam/collectors/ are siblings under adam/, and their
only sanctioned communication is via the bus or an injected interface, not
a direct import). Instead, this class relies on ProcmonCollector's own
already-implemented, already-tested tolerance for a mismatched header (see
adam/collectors/procmon.py: an unrecognised header line is logged and
never treated as data, so a misconfigured export naturally yields zero
ProcMon events rather than a crash or garbage RawEvents) -- exactly the
"support partial telemetry" outcome this class is required to guarantee,
achieved by reuse rather than duplicated validation logic.

Guest workspace layout note. This class assumes (but, per the directive
above, now explicitly VERIFIES and LOGS rather than silently assumes) a
standardized guest workspace rooted at the parent of `capture_dir`
(`config/default.toml`'s `[guest_tools].capture_dir`, "C:\\ADAM\\telemetry"
by default) -- sibling directories "samples" and "temp" alongside
"telemetry". These sibling paths are derived, not independently
configured (no new Settings fields were added for them -- see
`_log_workspace_directories()`'s own docstring for why), specifically to
avoid introducing a new configuration surface for a purely diagnostic
check.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from adam.common.config import GuestToolsSettings
from adam.sandbox.vbox.client import VBoxCommandError, VirtualBoxClient
from adam.sandbox.vbox.models import VMOperationResult

logger = logging.getLogger(__name__)

# Bug #2 fix: VBoxManage guestcontrol does NOT resolve executables through
# the guest's PATH the way a real interactive shell does -- `run_in_guest`/
# `start_in_guest`'s `executable_path` is passed straight to the guest's
# CreateProcessW, which requires either a full path or a name resolvable
# via Windows' own (much narrower) "search the launching process's own
# directory, then System32, then Windows, then PATH" rules -- and under
# guestcontrol, that search does not reliably include PATH at all
# (observed directly: "No such file or directory 'powershell.exe' on
# guest"). Every PowerShell invocation in this class uses this absolute,
# standard 64-bit Windows PowerShell path instead of the bare "powershell
# .exe" name relied on previously.
_POWERSHELL_PATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


@dataclass(frozen=True, slots=True)
class ToolAvailability:
    """verify_tools()'s report. `detail` maps tool name -> human-readable unavailability reason (absent key = available)."""

    procmon_available: bool
    tshark_available: bool
    sysmon_log_available: bool
    detail: dict[str, str]


@dataclass(frozen=True, slots=True)
class TelemetryArtifacts:
    """
    stop_export_and_fetch()'s result: host-accessible paths for whichever
    telemetry sources this session successfully captured, exported, and
    copied. Each field is None if that source was not configured, not
    available in the guest, or failed at any step -- see this module's
    "Support partial telemetry" guarantee.
    """

    sysmon_evtx_path: str | None = None
    procmon_csv_path: str | None = None
    network_ek_json_path: str | None = None


class GuestAgent:
    """See module docstring for full scope, lifecycle, guarantees, and diagnostics tiers."""

    def __init__(
        self,
        client: VirtualBoxClient,
        vm_name: str,
        *,
        guest_username: str,
        guest_password: str,
        settings: GuestToolsSettings,
    ) -> None:
        self._client = client
        self._vm_name = vm_name
        self._guest_username = guest_username
        self._guest_password = guest_password
        self._settings = settings

    # ------------------------------------------------------------------ #
    # internal guestcontrol helpers -- every one of these swallows
    # VBoxCommandError (VBoxManage itself unreachable) into a logged
    # warning and a None/failure return, never a raise, per this class's
    # "support partial telemetry" guarantee. Every call is fully
    # instrumented via _log_call() -- see module docstring's DIAGNOSTICS
    # section.
    # ------------------------------------------------------------------ #

    @staticmethod
    def _format_command_line(executable: str, arguments: list[str]) -> str:
        """Reconstructs a human-readable, fully expanded command line for logging -- not itself passed to any subprocess."""
        parts = [f'"{executable}"' if " " in executable else executable]
        for arg in arguments:
            parts.append(f'"{arg}"' if " " in arg and not arg.startswith('"') else arg)
        return " ".join(parts)

    def _log_call(
        self,
        label: str,
        *,
        operation: str,
        executable: str,
        arguments: list[str],
        timeout: float,
        result: VMOperationResult | None,
        vbox_error: str | None = None,
        unquoted_args: bool = False,
    ) -> None:
        """
        The single instrumentation point every run_in_guest()/
        start_in_guest()/copy_from_guest() call funnels through (via
        _run_quiet()/_start_quiet()/_fetch() below). Logs every field this
        module's diagnostics directive asked for, verbatim -- stdout/
        stderr are never paraphrased, truncated, or replaced with a
        simplified message here. DEBUG-level: off by default, see module
        docstring.

        unquoted_args is logged too (Issue #1 fix) -- whether VBoxManage's
        own `--unquoted-args` flag was set for this call materially changes
        how the guest reconstructs the final command line, so it belongs in
        the same diagnostic dump as the rest of the call's exact shape.
        """
        if result is not None:
            return_code: object = result.return_code
            success = result.success
            duration = f"{result.duration_ms:.1f}ms"
            stdout = result.stdout
            stderr = result.stderr
        else:
            return_code = "N/A"
            success = False
            duration = "N/A"
            stdout = ""
            stderr = vbox_error or "VBoxManage itself could not be invoked (see warning above)"

        logger.debug(
            "[GuestAgent] %s\n"
            "  operation     : %s\n"
            "  executable    : %s\n"
            "  arguments     : %r\n"
            "  command line  : %s\n"
            "  unquoted_args : %s\n"
            "  timeout       : %.1fs\n"
            "  return_code   : %s\n"
            "  success       : %s\n"
            "  duration      : %s\n"
            "  stdout        : %r\n"
            "  stderr        : %r",
            label,
            operation,
            executable,
            arguments,
            self._format_command_line(executable, arguments),
            unquoted_args,
            timeout,
            return_code,
            success,
            duration,
            stdout,
            stderr,
        )

    async def _run_quiet(
        self, executable: str, arguments: list[str], timeout: float, label: str, *, unquoted_args: bool = False
    ) -> VMOperationResult | None:
        try:
            result = await self._client.run_in_guest(
                self._vm_name,
                guest_username=self._guest_username,
                guest_password=self._guest_password,
                executable_path=executable,
                arguments=arguments,
                timeout=timeout,
                unquoted_args=unquoted_args,
            )
        except VBoxCommandError as exc:
            self._log_call(
                label, operation="run_in_guest", executable=executable, arguments=arguments,
                timeout=timeout, result=None, vbox_error=exc.message, unquoted_args=unquoted_args,
            )
            logger.warning("guest_agent: %s failed (VBoxManage unreachable): %s", label, exc.message)
            return None

        self._log_call(
            label, operation="run_in_guest", executable=executable, arguments=arguments,
            timeout=timeout, result=result, unquoted_args=unquoted_args,
        )
        return result

    async def _start_quiet(
        self, executable: str, arguments: list[str], timeout: float, label: str
    ) -> VMOperationResult | None:
        try:
            result = await self._client.start_in_guest(
                self._vm_name,
                guest_username=self._guest_username,
                guest_password=self._guest_password,
                executable_path=executable,
                arguments=arguments,
                timeout=timeout,
            )
        except VBoxCommandError as exc:
            self._log_call(
                label, operation="start_in_guest", executable=executable, arguments=arguments,
                timeout=timeout, result=None, vbox_error=exc.message,
            )
            logger.warning("guest_agent: %s failed (VBoxManage unreachable): %s", label, exc.message)
            return None

        self._log_call(label, operation="start_in_guest", executable=executable, arguments=arguments, timeout=timeout, result=result)
        return result

    async def _path_exists_in_guest(self, path: str) -> bool:
        """
        Bug #1 fix: uses a plain `dir <path>` call (return code 0 if found,
        non-zero "File Not Found" if not) instead of the previous
        `if exist "<path>" (exit 0) else (exit 1)` construct. See module
        docstring's "Quoting note" -- that construct required embedding a
        literal `"` character inside a single argument string that ALSO
        needed its own wrapping (because the surrounding "(exit 0) else
        (exit 1)" text contains spaces), producing nested/mismatched
        quotes once VBoxManage's own argv-to-Windows-command-line
        marshaling re-escaped the embedded quote with a backslash -- a
        style cmd.exe's own `/c` parser does not understand the way a
        standard MSVCRT argv parser would, hence "The filename, directory
        name, or volume label syntax is incorrect." `dir <path>` needs no
        such construct: `path` is passed as its own, unquoted-by-us argv
        element, and VBoxManage quotes it automatically (correctly, with
        no embedded quotes to conflict with) only if it happens to contain
        a space.
        """
        result = await self._run_quiet(
            "cmd.exe", ["/c", "dir", path], self._settings.tool_verify_timeout_s, f"check path {path}"
        )
        return result is not None and result.success

    async def _dir_listing(self, path: str) -> str:
        """
        Raw `dir` output (stdout+stderr) for `path` -- used for both the
        "does this file exist, what size" check and the "dump the whole
        directory" fallback the diagnostics directive asks for.

        Bug #1 fix: `path` is its own argv element (`["/c", "dir", path]`),
        not manually wrapped in literal quotes (`f'dir "{path}"'`, the
        previous, broken form) -- see `_path_exists_in_guest()`'s docstring
        for the full quoting-mismatch explanation this applies to every
        cmd.exe invocation in this class.
        """
        result = await self._run_quiet(
            "cmd.exe", ["/c", "dir", path], self._settings.tool_verify_timeout_s, f"dir listing of {path}"
        )
        if result is None:
            return "<no output -- VBoxManage unreachable>"
        combined = result.stdout.strip()
        if result.stderr.strip():
            combined = f"{combined}\n[stderr] {result.stderr.strip()}"
        return combined or "<empty dir output>"

    async def _tasklist_grep(self, process_name: str) -> str:
        """Raw `tasklist | findstr <name>` output -- process-status verification the diagnostics directive asks for after every tool launch."""
        result = await self._run_quiet(
            "cmd.exe", ["/c", f"tasklist | findstr {process_name}"], self._settings.tool_verify_timeout_s,
            f"tasklist check for {process_name}",
        )
        if result is None:
            return "<no output -- VBoxManage unreachable>"
        stdout = result.stdout.strip()
        return stdout if stdout else f"<no matching process found for {process_name!r}>"

    async def _driverquery_grep(self, driver_name_fragment: str) -> str:
        """
        Raw `driverquery | findstr /I <fragment>` output -- Issue #2
        diagnostic (start_captures()): confirms whether a kernel-mode
        driver whose name contains `driver_name_fragment` (e.g. "procmon")
        is actually loaded, independent of whether the owning user-mode
        process (Procmon64.exe) merely exists in `tasklist`. A process can
        be running with no driver loaded if driver-load failed silently
        (e.g. the executing token lacks SeLoadDriverPrivilege -- see this
        module's "Known Issues" section) -- tasklist alone cannot
        distinguish "really capturing" from "process object exists, driver
        never attached."
        """
        result = await self._run_quiet(
            "cmd.exe", ["/c", f"driverquery | findstr /I {driver_name_fragment}"], self._settings.tool_verify_timeout_s,
            f"driverquery check for {driver_name_fragment}",
        )
        if result is None:
            return "<no output -- VBoxManage unreachable>"
        stdout = result.stdout.strip()
        return stdout if stdout else f"<no matching driver found for {driver_name_fragment!r}>"

    async def _whoami_diagnostics(self, label: str) -> tuple[str, str]:
        """
        Runs `whoami /groups` and `whoami /priv` and returns their raw
        stdout, unconditionally logging both at INFO level under `label`.

        Factored out of _export_sysmon()'s original Bug #4 probes (kept
        behaviorally identical there) so start_captures() can run the same
        probe for Issue #2's Procmon investigation without duplicating the
        two calls -- both issues are, per this module's "Known Issues"
        section, suspected to share one root cause (GuestControl's filtered/
        non-elevated token), so the same evidence-gathering probe answers
        both questions. Not a new public interface; a private helper used
        only within this file.
        """
        whoami_groups = await self._run_quiet(
            "whoami.exe", ["/groups"], self._settings.tool_verify_timeout_s, f"whoami /groups ({label})"
        )
        whoami_priv = await self._run_quiet(
            "whoami.exe", ["/priv"], self._settings.tool_verify_timeout_s, f"whoami /priv ({label})"
        )
        groups_output = whoami_groups.stdout.strip() if whoami_groups is not None else "<probe failed -- VBoxManage unreachable>"
        priv_output = whoami_priv.stdout.strip() if whoami_priv is not None else "<probe failed -- VBoxManage unreachable>"
        logger.info("[GuestAgent] %s -- whoami /groups:\n%s", label, groups_output)
        logger.info("[GuestAgent] %s -- whoami /priv:\n%s", label, priv_output)
        return groups_output, priv_output

    @staticmethod
    def _procmon_args(*args: str) -> list[str]:
        """
        Bug #3 fix: EVERY Procmon64.exe invocation must include
        `/AcceptEula`, unconditionally -- not just the initial launch.
        Confirmed on a real run: `/Terminate` without it re-displays the
        Sysinternals EULA dialog, which guestcontrol has no way to click
        through, so the call hangs until its own timeout rather than
        actually terminating the capture. The same applies to `/OpenLog`/
        `/SaveAs` conversion and any future Procmon64.exe invocation this
        class adds -- routing every call through this one helper is what
        keeps that guarantee from silently drifting if a call site is
        added later without remembering the flag.
        """
        return ["/AcceptEula", *args]

    def _guest_path(self, filename: str) -> str:
        return f"{self._settings.capture_dir}\\{filename}"

    def _guest_pml_path(self, session_id: str) -> str:
        return self._guest_path(f"{session_id}_procmon.pml")

    def _guest_csv_path(self, session_id: str) -> str:
        return self._guest_path(f"{session_id}_procmon.csv")

    def _guest_pcap_path(self, session_id: str) -> str:
        return self._guest_path(f"{session_id}_network.pcapng")

    def _guest_ek_path(self, session_id: str) -> str:
        return self._guest_path(f"{session_id}_network.ek.json")

    def _guest_evtx_path(self, session_id: str) -> str:
        return self._guest_path(f"{session_id}_sysmon.evtx")

    # ------------------------------------------------------------------ #
    # step 1
    # ------------------------------------------------------------------ #

    async def _log_workspace_directories(self) -> None:
        """
        DIRECTORY DIAGNOSTICS (diagnostics directive): logs, at GuestAgent
        startup, whether the capture/sample/temp directories exist in the
        guest, and which one is missing if any are.

        Sample and temp directories are DERIVED from `capture_dir`'s
        parent (e.g. capture_dir "C:\\ADAM\\telemetry" -> sample dir
        "C:\\ADAM\\samples", temp dir "C:\\ADAM\\temp") rather than given
        their own new `GuestToolsSettings` fields -- this is a purely
        diagnostic check (this class never writes to or reads from the
        sample/temp directories itself; sample placement is
        SandboxController.arm()'s concern via SessionOrchestrator's own
        `guest_target_path_template`), and adding new configuration
        surface for a diagnostic-only value would be exactly the kind of
        new abstraction this debugging task was scoped to avoid. Uses
        `PureWindowsPath`, not `Path`, since these are guest Windows paths
        being manipulated from a host process that may itself be running
        on a non-Windows OS.

        Does NOT create any missing directory -- verifies and logs only,
        per the directive's explicit "Do not silently create them without
        logging" (start_captures()'s own `mkdir` for capture_dir remains
        the only directory-creation this class performs, and it already
        logs via _log_call()).
        """
        capture_dir = self._settings.capture_dir
        root = PureWindowsPath(capture_dir).parent
        sample_dir = str(root / "samples")
        temp_dir = str(root / "temp")

        logger.info(
            "[GuestAgent] Workspace directories -- capture=%s sample=%s temp=%s",
            capture_dir, sample_dir, temp_dir,
        )

        for label, directory in (("capture", capture_dir), ("sample", sample_dir), ("temp", temp_dir)):
            exists = await self._path_exists_in_guest(directory)
            if exists:
                logger.info("[GuestAgent] %s directory exists: %s", label, directory)
            else:
                logger.warning("[GuestAgent] %s directory does NOT exist: %s", label, directory)

    async def verify_tools(self) -> ToolAvailability:
        """
        Step 1. Logs the guest workspace directory layout (see
        _log_workspace_directories()), then checks each configured tool
        path exists in the guest (`cmd.exe /c if exist ...`) and that the
        Sysmon log channel is readable (`wevtutil gli`). An unconfigured
        path (settings field is None) is reported unavailable with a
        distinct, specific reason from "configured but not found" -- both
        are real, useful diagnostics, and this class never conflates them.

        Never raises. Returns a report; callers (start_captures(),
        stop_export_and_fetch()) independently re-check availability at
        each step regardless of this report, since availability could -- in
        principle -- change between verify_tools() being called and a
        later step running (e.g. a flaky guestcontrol call). This method
        exists primarily to produce the up-front diagnostic log messages
        this phase's spec explicitly asks for ("fail with meaningful
        diagnostics if missing"), not as a gate other methods depend on.

        Diagnostics addition: SessionOrchestrator now actually calls this
        method once per session (before start_captures()) specifically so
        these diagnostics run on every real session, not just when a
        caller remembers to invoke it -- see adam/orchestrator/session.py.
        """
        logger.info("[GuestAgent] verify_tools starting")
        await self._log_workspace_directories()

        detail: dict[str, str] = {}

        procmon_available = False
        if self._settings.procmon_path is None:
            detail["procmon"] = "guest_tools.procmon_path is not configured"
        else:
            procmon_available = await self._path_exists_in_guest(self._settings.procmon_path)
            if not procmon_available:
                detail["procmon"] = f"not found in guest at configured path {self._settings.procmon_path!r}"

        tshark_available = False
        if self._settings.tshark_path is None:
            detail["tshark"] = "guest_tools.tshark_path is not configured"
        else:
            tshark_available = await self._path_exists_in_guest(self._settings.tshark_path)
            if not tshark_available:
                detail["tshark"] = f"not found in guest at configured path {self._settings.tshark_path!r}"

        sysmon_probe = await self._run_quiet(
            "wevtutil.exe",
            ["gli", self._settings.sysmon_log],
            self._settings.tool_verify_timeout_s,
            f"check sysmon log {self._settings.sysmon_log}",
        )
        sysmon_log_available = sysmon_probe is not None and sysmon_probe.success
        if not sysmon_log_available:
            stderr = sysmon_probe.stderr.strip() if sysmon_probe is not None else "VBoxManage unreachable"
            detail["sysmon"] = f"event log channel {self._settings.sysmon_log!r} not found or unreadable (wevtutil stderr: {stderr!r})"

        for tool, reason in detail.items():
            logger.warning("guest_agent: tool unavailable -- %s: %s", tool, reason)

        logger.info(
            "[GuestAgent] verify_tools result: procmon=%s tshark=%s sysmon=%s",
            procmon_available, tshark_available, sysmon_log_available,
        )

        return ToolAvailability(
            procmon_available=procmon_available,
            tshark_available=tshark_available,
            sysmon_log_available=sysmon_log_available,
            detail=detail,
        )

    # ------------------------------------------------------------------ #
    # steps 2-3
    # ------------------------------------------------------------------ #

    async def start_captures(
        self,
        session_id: str,
        *,
        capture_procmon: bool = True,
        capture_network: bool = True,
    ) -> None:
        """
        Steps 2-3: start Procmon (backing-file mode) and tshark, both
        detached via VirtualBoxClient.start_in_guest() so they keep
        running through the sample's execution -- then, per the
        diagnostics directive, INDEPENDENTLY VERIFY each launch actually
        took: wait 2s, check the process is in `tasklist`, check the
        expected backing/capture file exists (logging its `dir` listing
        if so, or a full directory dump of capture_dir if not).

        `capture_procmon`/`capture_network` let a caller skip a source
        entirely -- adam/orchestrator/runner.py sets these False for any
        source a CLI override path already covers, so this class never
        captures something that would just be discarded (this phase's own
        instruction: "existing CLI flags ... remain only as optional
        overrides for testing").

        Best-effort throughout: a failure starting either capture is
        logged and this method still returns normally.
        stop_export_and_fetch() independently checks for each capture's
        expected output file before attempting to convert/export it, so a
        capture that never started simply yields None for that source
        later -- not a special case, the same "support partial telemetry"
        path any other failure takes.
        """
        logger.info("[GuestAgent] session=%s start_captures beginning", session_id)

        # Bug #1 fix: every path is its own argv element, not embedded in a
        # manually-quoted string -- see _path_exists_in_guest()'s docstring.
        await self._run_quiet(
            "cmd.exe",
            ["/c", "if", "not", "exist", self._settings.capture_dir, "mkdir", self._settings.capture_dir],
            self._settings.tool_verify_timeout_s,
            "ensure guest capture directory",
        )

        if capture_procmon and self._settings.procmon_path is not None:
            logger.info("[GuestAgent] session=%s Start Procmon", session_id)
            pml_path = self._guest_pml_path(session_id)
            procmon_start_args = self._procmon_args("/Quiet", "/Minimized", "/BackingFile", pml_path)
            launch = await self._start_quiet(
                self._settings.procmon_path,
                procmon_start_args,
                self._settings.tool_verify_timeout_s,
                "start Procmon capture",
            )
            if launch is None or not launch.success:
                logger.warning(
                    "guest_agent: session=%s Procmon launch command failed. command=%s stderr=%r",
                    session_id,
                    self._format_command_line(self._settings.procmon_path, procmon_start_args),
                    launch.stderr if launch is not None else "VBoxManage unreachable",
                )
            else:
                logger.info("[GuestAgent] session=%s Procmon launch command succeeded, verifying...", session_id)

            await asyncio.sleep(2.0)

            tasklist_output = await self._tasklist_grep("Procmon")
            logger.info("[GuestAgent] session=%s Procmon tasklist check: %s", session_id, tasklist_output)

            # Issue #2 diagnostics: tasklist alone only proves the process
            # OBJECT exists, not that it actually started capturing. Three
            # more targeted probes, none of them a blind fix, per "Do NOT
            # guess. Instrument and investigate":
            #   1. The running process's own command line + session ID
            #      (tasklist doesn't show either) -- confirms /BackingFile
            #      was really received, and reveals interactive vs. non-
            #      interactive session placement ("whether GuestControl
            #      launch mode affects capture").
            #   2. Whether Procmon's kernel driver is actually loaded --
            #      distinguishes "process running, driver never attached"
            #      from "process running, driver attached, something else
            #      wrong."
            #   3. The same whoami /groups + /priv probe already used for
            #      Bug #4's Sysmon investigation -- see this module's
            #      "Known Issues" section for why Procmon and Sysmon are
            #      suspected to share one root cause (a filtered,
            #      non-elevated GuestControl token lacking the privilege
            #      each tool's driver-load/export operation needs).
            procmon_cmdline_probe = await self._run_quiet(
                _POWERSHELL_PATH,
                [
                    "-NoProfile", "-NonInteractive", "-Command",
                    "Get-CimInstance Win32_Process -Filter \"Name='Procmon64.exe'\" | "
                    "ForEach-Object { \"PID=$($_.ProcessId) SessionId=$($_.SessionId) CommandLine=$($_.CommandLine)\" }",
                ],
                self._settings.tool_verify_timeout_s,
                "Issue #2 diagnostic: Procmon64.exe command line + session ID",
            )
            logger.info(
                "[GuestAgent] session=%s Procmon process command-line/session probe: %s",
                session_id,
                procmon_cmdline_probe.stdout.strip() if procmon_cmdline_probe is not None and procmon_cmdline_probe.success
                else f"<probe failed: {procmon_cmdline_probe.stderr if procmon_cmdline_probe is not None else 'VBoxManage unreachable'}>",
            )

            driver_output = await self._driverquery_grep("procmon")
            logger.info("[GuestAgent] session=%s Procmon driver-loaded check (driverquery): %s", session_id, driver_output)

            await self._whoami_diagnostics(f"session={session_id} Procmon capture verification")

            if await self._path_exists_in_guest(pml_path):
                listing = await self._dir_listing(pml_path)
                logger.info("[GuestAgent] session=%s Backing file exists at %s:\n%s", session_id, pml_path, listing)
            else:
                dir_dump = await self._dir_listing(self._settings.capture_dir)
                logger.warning(
                    "guest_agent: session=%s Backing file does NOT exist at %s. "
                    "Directory listing of %s:\n%s",
                    session_id, pml_path, self._settings.capture_dir, dir_dump,
                )

        if capture_network and self._settings.tshark_path is not None:
            logger.info("[GuestAgent] session=%s Start tshark", session_id)
            pcap_path = self._guest_pcap_path(session_id)
            interfaces = await self._run_quiet(
                self._settings.tshark_path, ["-D"], self._settings.tool_verify_timeout_s, "list tshark interfaces (-D)"
            )
            logger.info(
                "[GuestAgent] session=%s tshark -D available interfaces:\n%s (attempting interface=%r)",
                session_id,
                interfaces.stdout.strip() if interfaces is not None else "<no output -- VBoxManage unreachable>",
                self._settings.tshark_interface,
            )

            launch = await self._start_quiet(
                self._settings.tshark_path,
                ["-i", self._settings.tshark_interface, "-w", pcap_path],
                self._settings.tool_verify_timeout_s,
                "start tshark capture",
            )
            if launch is None or not launch.success:
                logger.warning(
                    "guest_agent: session=%s tshark launch command failed. command=%s stderr=%r",
                    session_id,
                    self._format_command_line(self._settings.tshark_path, ["-i", self._settings.tshark_interface, "-w", pcap_path]),
                    launch.stderr if launch is not None else "VBoxManage unreachable",
                )
            else:
                logger.info("[GuestAgent] session=%s tshark launch command succeeded, verifying...", session_id)

            await asyncio.sleep(2.0)

            tshark_tasklist = await self._tasklist_grep("tshark")
            dumpcap_tasklist = await self._tasklist_grep("dumpcap")
            logger.info(
                "[GuestAgent] session=%s tshark tasklist check: %s | dumpcap tasklist check: %s",
                session_id, tshark_tasklist, dumpcap_tasklist,
            )

            if await self._path_exists_in_guest(pcap_path):
                listing = await self._dir_listing(pcap_path)
                logger.info("[GuestAgent] session=%s Capture file exists at %s:\n%s", session_id, pcap_path, listing)
            else:
                dir_dump = await self._dir_listing(self._settings.capture_dir)
                logger.warning(
                    "guest_agent: session=%s Capture file does NOT exist at %s. "
                    "Directory listing of %s:\n%s",
                    session_id, pcap_path, self._settings.capture_dir, dir_dump,
                )

    # ------------------------------------------------------------------ #
    # steps 6-9
    # ------------------------------------------------------------------ #

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
        Steps 6-9, run for all three sources unconditionally and
        independently (the `export_*` flags are the same per-source
        skip mechanism as start_captures()'s `capture_*` flags -- a
        source whose file was supplied via CLI override is never
        re-captured or re-exported here).

        Each per-source pipeline (`_export_sysmon`/`_export_procmon`/
        `_export_network`) fully owns its own stop -> export -> copy ->
        cleanup sequence and never raises; a failure at any point in one
        pipeline logs a specific reason and yields None for that field
        only, per this module's "support partial telemetry" guarantee.
        """
        logger.info("[GuestAgent] session=%s stop_export_and_fetch beginning", session_id)
        host_dir = Path(host_artifact_dir)
        host_dir.mkdir(parents=True, exist_ok=True)

        sysmon_path = await self._export_sysmon(session_id, host_dir) if export_sysmon else None
        procmon_path = await self._export_procmon(session_id, host_dir) if export_procmon else None
        network_path = await self._export_network(session_id, host_dir) if export_network else None

        logger.info(
            "[GuestAgent] session=%s stop_export_and_fetch complete: sysmon=%s procmon=%s network=%s",
            session_id, sysmon_path, procmon_path, network_path,
        )

        return TelemetryArtifacts(
            sysmon_evtx_path=sysmon_path,
            procmon_csv_path=procmon_path,
            network_ek_json_path=network_path,
        )

    async def _export_sysmon(self, session_id: str, host_dir: Path) -> str | None:
        """
        Sysmon has no start/stop lifecycle here (module docstring: it is a
        continuously-running guest service, not something this class
        starts or stops) -- export is the whole job. See module docstring's
        Sysmon-log-freshness note for why a full-log export is correct.

        Diagnostics addition: before exporting, probes `Get-WinEvent`
        directly (not just `wevtutil gli`'s "does the channel exist" check
        verify_tools() already does) to log how many events are actually
        sitting in the log right now -- the diagnostics directive's own
        explicit ask ("verify: Get-WinEvent returns events. Log number of
        events found").
        """
        logger.info("[GuestAgent] session=%s Sysmon: pre-export Get-WinEvent probe", session_id)
        probe = await self._run_quiet(
            _POWERSHELL_PATH,
            [
                "-NoProfile", "-NonInteractive", "-Command",
                f"(Get-WinEvent -LogName '{self._settings.sysmon_log}' -ErrorAction SilentlyContinue | Measure-Object).Count",
            ],
            self._settings.tool_verify_timeout_s,
            "Get-WinEvent event count probe",
        )
        if probe is not None and probe.success:
            logger.info(
                "[GuestAgent] session=%s Get-WinEvent reports %s event(s) in %s",
                session_id, probe.stdout.strip() or "<empty>", self._settings.sysmon_log,
            )
        else:
            logger.warning(
                "guest_agent: session=%s Get-WinEvent probe failed. stdout=%r stderr=%r",
                session_id,
                probe.stdout if probe is not None else "",
                probe.stderr if probe is not None else "VBoxManage unreachable",
            )

        guest_evtx = self._guest_evtx_path(session_id)
        logger.info("[GuestAgent] session=%s Export Sysmon EVTX", session_id)
        result = await self._run_quiet(
            "wevtutil.exe",
            ["epl", self._settings.sysmon_log, guest_evtx],
            self._settings.tool_verify_timeout_s,
            "export sysmon EVTX",
        )
        if result is None or not result.success:
            # Bug #4 diagnostics: "Access is denied" from `wevtutil epl` is
            # NOT blindly fixed here -- see this module's "Known Issues"
            # section for why a code-level fix isn't safe to guess at, and
            # what the most likely root cause is. This probe exists purely
            # to CONFIRM it on this guest, so the real fix (a guest-side
            # configuration change) can be applied with confidence rather
            # than trial and error.
            await self._whoami_diagnostics(f"session={session_id} Sysmon wevtutil epl failure")
            logger.warning(
                "guest_agent: session=%s sysmon EVTX export via wevtutil epl failed -- trying Issue #3's "
                "fallback export mechanism before giving up. command=%s return_code=%s stdout=%r stderr=%r. "
                "See adam/sandbox/guest/agent/agent.py's module docstring, 'Known Issues' section, for how "
                "to read the whoami output just logged above.",
                session_id,
                self._format_command_line("wevtutil.exe", ["epl", self._settings.sysmon_log, guest_evtx]),
                result.return_code if result is not None else "N/A",
                result.stdout if result is not None else "",
                result.stderr if result is not None else "VBoxManage unreachable",
            )
            if not await self._export_sysmon_raw_copy_fallback(session_id, guest_evtx):
                return None
            # Fallback succeeded -- guest_evtx now holds real content from
            # the raw copy; fall through to the same existence-check/copy-
            # to-host flow below exactly as if wevtutil epl had succeeded.

        if await self._path_exists_in_guest(guest_evtx):
            listing = await self._dir_listing(guest_evtx)
            logger.info("[GuestAgent] session=%s EVTX file exists at %s:\n%s", session_id, guest_evtx, listing)
        else:
            dir_dump = await self._dir_listing(self._settings.capture_dir)
            logger.warning(
                "guest_agent: session=%s wevtutil epl reported success but EVTX file does NOT exist at %s. "
                "Directory listing of %s:\n%s",
                session_id, guest_evtx, self._settings.capture_dir, dir_dump,
            )
            return None

        logger.info("[GuestAgent] session=%s Copy Sysmon EVTX to host", session_id)
        return await self._fetch(guest_evtx, host_dir / "sysmon.evtx", session_id, "sysmon")

    async def _export_sysmon_raw_copy_fallback(self, session_id: str, target_evtx_path: str) -> bool:
        """
        Issue #3's "another supported export mechanism" fallback, tried
        only after `wevtutil epl` has already failed. Rather than asking
        wevtutil to programmatically export the channel (an operation
        gated by SeBackupPrivilege / an elevated token -- see this
        module's "Known Issues" section), this copies the channel's own
        underlying .evtx file directly from its well-known, standard
        filesystem location. A plain file copy is a materially different
        Windows operation from wevtutil's own "epl" export API (different
        privilege check, different code path) -- worth trying even though
        it may still hit the same access-denied wall for the same
        underlying reason; either outcome is useful evidence.

        The standard Windows Event Log "Applications and Services Logs"
        file-naming convention (a channel's forward slashes become "%4" in
        its own backing file name -- Microsoft's own Event Log
        architecture, not specific to Sysmon) is used to derive the path
        from the configured `sysmon_log` channel name. This assumes the
        default/standard log file location, correct for a normal Sysmon
        install but potentially wrong for a non-standard one -- logged
        either way so a wrong guess is visible, not silent.

        Copies directly into `target_evtx_path` (the SAME session-specific
        guest path `_export_sysmon()` already uses for wevtutil's own
        output), so the rest of that method's existence-check/copy-to-host
        flow needs no special-casing for which mechanism actually produced
        the file.

        Returns True if the fallback copy succeeded, False otherwise.
        Never raises -- a failed fallback just means "no sysmon telemetry
        this session," the same outcome wevtutil epl failing alone would
        have produced, per this module's "support partial telemetry"
        guarantee.
        """
        raw_source_path = "C:\\Windows\\System32\\winevt\\Logs\\" + self._settings.sysmon_log.replace("/", "%4") + ".evtx"
        logger.info(
            "[GuestAgent] session=%s Issue #3 fallback: attempting raw file copy of %s "
            "(assumes standard Windows Event Log file-naming convention for channel %r)",
            session_id, raw_source_path, self._settings.sysmon_log,
        )

        if not await self._path_exists_in_guest(raw_source_path):
            listing = await self._dir_listing("C:\\Windows\\System32\\winevt\\Logs")
            logger.warning(
                "guest_agent: session=%s Issue #3 fallback: raw log file not found at %s (the standard-path "
                "assumption may not hold for this guest, or this account cannot even see the directory). "
                "Directory listing of C:\\Windows\\System32\\winevt\\Logs:\n%s",
                session_id, raw_source_path, listing,
            )
            return False

        copy_result = await self._run_quiet(
            "cmd.exe",
            ["/c", "copy", "/Y", raw_source_path, target_evtx_path],
            self._settings.tool_verify_timeout_s,
            "Issue #3 fallback: raw copy of Sysmon .evtx file",
        )
        if copy_result is None or not copy_result.success:
            logger.warning(
                "guest_agent: session=%s Issue #3 fallback: raw copy of %s failed too -- both wevtutil epl "
                "and a direct file copy were denied, which is strong evidence this guest's GuestControl token "
                "genuinely cannot read this channel at all (see 'Known Issues' section), not merely a "
                "wevtutil-specific restriction. return_code=%s stdout=%r stderr=%r",
                session_id,
                raw_source_path,
                copy_result.return_code if copy_result is not None else "N/A",
                copy_result.stdout if copy_result is not None else "",
                copy_result.stderr if copy_result is not None else "VBoxManage unreachable",
            )
            return False

        logger.info(
            "[GuestAgent] session=%s Issue #3 fallback SUCCEEDED: raw copy of %s -> %s worked even though "
            "wevtutil epl was denied -- useful evidence the restriction is specific to wevtutil's own export "
            "API, not a blanket denial of all read access to the channel.",
            session_id, raw_source_path, target_evtx_path,
        )
        return True

    async def _export_procmon(self, session_id: str, host_dir: Path) -> str | None:
        if self._settings.procmon_path is None:
            return None

        pml_path = self._guest_pml_path(session_id)
        csv_path = self._guest_csv_path(session_id)

        # /Terminate signals the running instance to stop capturing and
        # flush its backing file; it is not itself a reliable success
        # signal (observed to vary across Procmon versions), so the real
        # "did anything actually get captured" check is the backing
        # file's existence, checked next.
        logger.info("[GuestAgent] session=%s Terminate Procmon", session_id)
        terminate = await self._run_quiet(
            self._settings.procmon_path,
            self._procmon_args("/Terminate"),
            self._settings.procmon_terminate_timeout_s,
            "stop Procmon capture",
        )
        if terminate is None or not terminate.success:
            logger.warning(
                "guest_agent: session=%s Procmon /Terminate reported failure (may be benign, checked below). "
                "return_code=%s stdout=%r stderr=%r",
                session_id,
                terminate.return_code if terminate is not None else "N/A",
                terminate.stdout if terminate is not None else "",
                terminate.stderr if terminate is not None else "VBoxManage unreachable",
            )

        if await self._path_exists_in_guest(pml_path):
            listing = await self._dir_listing(pml_path)
            logger.info("[GuestAgent] session=%s pre-conversion backing file exists at %s:\n%s", session_id, pml_path, listing)
        else:
            dir_dump = await self._dir_listing(self._settings.capture_dir)
            logger.warning(
                "guest_agent: session=%s no Procmon backing file at %s -- capture likely never started, "
                "procmon telemetry unavailable this session. Directory listing of %s:\n%s",
                session_id, pml_path, self._settings.capture_dir, dir_dump,
            )
            return None

        logger.info("[GuestAgent] session=%s Export Procmon CSV", session_id)
        procmon_convert_args = self._procmon_args("/OpenLog", pml_path, "/SaveAs", csv_path, "/Quiet")
        convert = await self._run_quiet(
            self._settings.procmon_path,
            procmon_convert_args,
            self._settings.procmon_export_timeout_s,
            "convert Procmon PML to CSV",
        )
        if convert is None or not convert.success:
            logger.warning(
                "guest_agent: session=%s Procmon PML->CSV conversion failed -- procmon telemetry unavailable this session. "
                "command=%s return_code=%s stdout=%r stderr=%r",
                session_id,
                self._format_command_line(self._settings.procmon_path, procmon_convert_args),
                convert.return_code if convert is not None else "N/A",
                convert.stdout if convert is not None else "",
                convert.stderr if convert is not None else "VBoxManage unreachable",
            )
            return None

        if await self._path_exists_in_guest(csv_path):
            listing = await self._dir_listing(csv_path)
            logger.info("[GuestAgent] session=%s CSV file exists at %s:\n%s", session_id, csv_path, listing)
        else:
            dir_dump = await self._dir_listing(self._settings.capture_dir)
            logger.warning(
                "guest_agent: session=%s Procmon reported a successful CSV conversion but CSV file does NOT exist at %s. "
                "Directory listing of %s:\n%s",
                session_id, csv_path, self._settings.capture_dir, dir_dump,
            )
            return None

        logger.info("[GuestAgent] session=%s Copy Procmon CSV to host", session_id)
        return await self._fetch(csv_path, host_dir / "procmon.csv", session_id, "procmon")

    async def _export_network(self, session_id: str, host_dir: Path) -> str | None:
        if self._settings.tshark_path is None:
            return None

        pcap_path = self._guest_pcap_path(session_id)
        ek_path = self._guest_ek_path(session_id)

        # tshark spawns a privileged dumpcap.exe helper to perform the
        # actual packet capture (true cross-platform, not Windows-
        # specific) -- killing only tshark.exe can leave dumpcap.exe still
        # holding/writing the file. Both are killed independently,
        # best-effort; a missing process ("not found") is not treated as
        # an error by either call.
        logger.info("[GuestAgent] session=%s Terminate tshark/dumpcap", session_id)
        kill_tshark = await self._run_quiet(
            "taskkill.exe", ["/IM", "tshark.exe", "/F"], self._settings.tshark_stop_timeout_s, "stop tshark"
        )
        kill_dumpcap = await self._run_quiet(
            "taskkill.exe", ["/IM", "dumpcap.exe", "/F"], self._settings.tshark_stop_timeout_s, "stop dumpcap"
        )
        logger.info(
            "[GuestAgent] session=%s taskkill tshark: return_code=%s stderr=%r | taskkill dumpcap: return_code=%s stderr=%r",
            session_id,
            kill_tshark.return_code if kill_tshark is not None else "N/A",
            kill_tshark.stderr if kill_tshark is not None else "VBoxManage unreachable",
            kill_dumpcap.return_code if kill_dumpcap is not None else "N/A",
            kill_dumpcap.stderr if kill_dumpcap is not None else "VBoxManage unreachable",
        )

        if await self._path_exists_in_guest(pcap_path):
            listing = await self._dir_listing(pcap_path)
            logger.info("[GuestAgent] session=%s pre-conversion capture file exists at %s:\n%s", session_id, pcap_path, listing)
        else:
            dir_dump = await self._dir_listing(self._settings.capture_dir)
            logger.warning(
                "guest_agent: session=%s no tshark capture file at %s -- capture likely never started, "
                "network telemetry unavailable this session. Directory listing of %s:\n%s",
                session_id, pcap_path, self._settings.capture_dir, dir_dump,
            )
            return None

        logger.info("[GuestAgent] session=%s Export network EK JSON", session_id)
        # Issue #1 fix (superseding the earlier Bug #1 fix's assumption for
        # THIS specific call): the earlier fix assumed VBoxManage
        # automatically wraps any space-containing argv element in quotes
        # when reconstructing the guest's command line. A real VM run
        # disproved that for this call: the actual error --
        # "'C:\Program' is not recognized as an internal or external
        # command" -- proves tshark_path ("C:\Program Files\Wireshark\
        # tshark.exe") reached cmd.exe completely UNQUOTED, naively space-
        # joined, so cmd.exe split it at the first space. VBoxManage's own
        # per-token quoting is real but undocumented/unreliable for this
        # exact shape (a `cmd.exe /c` command mixing a space-containing
        # token with shell redirection); relying on it further would just
        # be guessing again.
        #
        # Fix, per the OFFICIALLY DOCUMENTED `--unquoted-args` guestcontrol
        # option ("Disables escaped double quoting ... on arguments passed
        # to the executed program" -- Oracle VM VirtualBox User Manual,
        # "VBoxManage guestcontrol"): pass `unquoted_args=True` so
        # VBoxManage does NOT apply any quoting/escaping of its own, then
        # build the command line ourselves, deterministically. Only
        # tshark_path is wrapped -- a single, flat quote pair around one
        # isolated token with no embedded quote characters, NOT the nested
        # "nqhote-inside-a-string-that-also-needs-its-own-wrapping"
        # construct that caused the original Bug #1 (see
        # _path_exists_in_guest()'s docstring). Every other token
        # (pcap_path, ek_path, "-r", "-T", "ek", ">") is left as its own
        # separate, unquoted argv element, since none of them contain
        # spaces and --unquoted-args means nothing will add quotes around
        # them for us.
        tshark_path = self._settings.tshark_path
        quoted_tshark_path = f'"{tshark_path}"' if " " in tshark_path else tshark_path
        network_ek_args = [quoted_tshark_path, "-r", pcap_path, "-T", "ek", ">", ek_path]
        convert = await self._run_quiet(
            "cmd.exe",
            ["/c", *network_ek_args],
            self._settings.tshark_export_timeout_s,
            "convert capture to EK JSON",
            unquoted_args=True,
        )
        if convert is None or not convert.success:
            logger.warning(
                "guest_agent: session=%s tshark EK JSON conversion failed -- network telemetry unavailable this session. "
                "command=%s return_code=%s stdout=%r stderr=%r",
                session_id,
                self._format_command_line("cmd.exe", ["/c", *network_ek_args]),
                convert.return_code if convert is not None else "N/A",
                convert.stdout if convert is not None else "",
                convert.stderr if convert is not None else "VBoxManage unreachable",
            )
            return None

        if await self._path_exists_in_guest(ek_path):
            listing = await self._dir_listing(ek_path)
            logger.info("[GuestAgent] session=%s EK JSON file exists at %s:\n%s", session_id, ek_path, listing)
        else:
            dir_dump = await self._dir_listing(self._settings.capture_dir)
            logger.warning(
                "guest_agent: session=%s tshark reported a successful EK JSON conversion but the file does NOT exist at %s. "
                "Directory listing of %s:\n%s",
                session_id, ek_path, self._settings.capture_dir, dir_dump,
            )
            return None

        logger.info("[GuestAgent] session=%s Copy network EK JSON to host", session_id)
        return await self._fetch(ek_path, host_dir / "network.ek.json", session_id, "network")

    async def _fetch(self, guest_path: str, host_path: Path, session_id: str, source: str) -> str | None:
        """
        Copies guest_path to host_path via VirtualBoxClient.copy_from_guest(),
        then best-effort deletes guest_path (module docstring's "always
        clean up temporary files" guarantee -- cleanup failure is logged,
        never raised, and never undoes an already-successful copy).

        Diagnostics addition: logs the guest-side file's `dir` listing
        immediately before the copy (size/existence, belt-and-suspenders
        alongside each exporter's own pre-copy check above) and the host-
        side file's actual size immediately after, per the diagnostics
        directive's "before copy: verify file exists, log size. after
        copy: verify host file exists, log host size."
        """
        pre_listing = await self._dir_listing(guest_path)
        logger.info("[GuestAgent] session=%s pre-copy guest listing for %s (%s):\n%s", session_id, source, guest_path, pre_listing)

        try:
            result = await self._client.copy_from_guest(
                self._vm_name,
                guest_username=self._guest_username,
                guest_password=self._guest_password,
                guest_source_path=guest_path,
                host_target_path=str(host_path),
                timeout=self._settings.copy_from_guest_timeout_s,
            )
        except VBoxCommandError as exc:
            self._log_call(
                f"copy {source} telemetry from guest", operation="copy_from_guest",
                executable="(copyfrom)", arguments=[guest_path, str(host_path)],
                timeout=self._settings.copy_from_guest_timeout_s, result=None, vbox_error=exc.message,
            )
            logger.warning(
                "guest_agent: session=%s failed to copy %s telemetry from guest (VBoxManage unreachable): %s",
                session_id,
                source,
                exc.message,
            )
            return None

        self._log_call(
            f"copy {source} telemetry from guest", operation="copy_from_guest",
            executable="(copyfrom)", arguments=[guest_path, str(host_path)],
            timeout=self._settings.copy_from_guest_timeout_s, result=result,
        )

        if not result.success:
            logger.warning(
                "guest_agent: session=%s failed to copy %s telemetry from guest. "
                "guest_path=%s host_path=%s return_code=%s stdout=%r stderr=%r",
                session_id,
                source,
                guest_path,
                host_path,
                result.return_code,
                result.stdout,
                result.stderr,
            )
            return None

        if host_path.exists():
            logger.info(
                "[GuestAgent] session=%s %s copied to host: %s (%d bytes)",
                session_id, source, host_path, host_path.stat().st_size,
            )
        else:
            logger.warning(
                "guest_agent: session=%s copy_from_guest reported success but host file does NOT exist at %s "
                "(source=%s, guest_path=%s)",
                session_id, host_path, source, guest_path,
            )
            return None

        # Bug #1 fix: separate argv tokens, no manually-embedded quotes.
        cleanup = await self._run_quiet(
            "cmd.exe",
            ["/c", "del", "/f", "/q", guest_path],
            self._settings.tool_verify_timeout_s,
            f"cleanup {source} guest temp file",
        )
        if cleanup is None or not cleanup.success:
            logger.warning(
                "guest_agent: session=%s cleanup of guest temp file %s did not report success (non-fatal): stderr=%r",
                session_id, guest_path, cleanup.stderr if cleanup is not None else "VBoxManage unreachable",
            )

        return str(host_path)
