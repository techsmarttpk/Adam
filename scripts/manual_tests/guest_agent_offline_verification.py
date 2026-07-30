"""
scripts/manual_tests/guest_agent_offline_verification.py

Offline, no-VM verification harness for Phase 5 (adam.sandbox.guest.agent
.agent.GuestAgent) and its integration into SessionOrchestrator/Runner.

Unlike every other script in this directory (see README.md's own opening
paragraph -- "None of them import or depend on SandboxController,
VirtualBoxClient, or wait_for_guest_ready()"), this one deliberately DOES:
it is the offline counterpart to those live-VM diagnostics, verifying
GuestAgent's own orchestration logic and its wiring into
SessionOrchestrator/collectors without a live VM, using the same
fake-the-VBoxManage-boundary methodology already established throughout
this project (FakeClient(VirtualBoxClient) overriding only _run() --
see docs/implementation-audit.md's Phase 3/4/8 sections for the precedent).
Every scenario below drives real production code (GuestAgent,
SandboxController, SessionOrchestrator, ProcmonCollector, NetworkCollector)
against a fake VBoxManage process boundary; nothing about GuestAgent's own
logic, the collectors' parsing, or SessionOrchestrator's orchestration is
faked.

This project has no pytest/unittest infrastructure (docs/implementation-
audit.md's Technical Debt: "No automated tests exist anywhere in the
repository"). This script follows this directory's own established
convention instead -- a standalone, directly-runnable script using plain
`assert` and `print()` -- rather than introducing a new test framework
unprompted.

Scenarios covered:
  1. verify_tools() reports every tool available when the guest has them.
  2. verify_tools() reports specific, correct diagnostics for missing tools.
  3. Full capture -> export -> fetch produces real, byte-correct host files
     for all three sources.
  4. Partial telemetry: Procmon capture never starting does not affect
     Sysmon or network export/fetch.
  5. A full SessionOrchestrator session with GuestAgent and zero CLI
     override paths -- the real, previously-broken "adam run <sample>"
     case -- produces genuine RawEvents from Procmon+network telemetry
     (raw_events == 2; Sysmon is expected to fail against this harness's
     necessarily-fake, non-binary EVTX content -- no real .evtx file is
     available in this environment, the same disclosed limitation Phase 7's
     own SysmonCollector verification already carries).
  6. A CLI-override collector for one source (e.g. --procmon-csv-path)
     causes GuestAgent to never issue a single guestcontrol command
     touching that source.

Run with (from the project root):
    python -m scripts.manual_tests.guest_agent_offline_verification
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from adam.collectors.base import BaseCollector
from adam.common.bus import EventBus
from adam.common.config import GuestToolsSettings, Settings
from adam.contracts.enums import Arm
from adam.contracts.session import SampleRef
from adam.orchestrator.session import SessionOrchestrator
from adam.sandbox.controller import SandboxController
from adam.sandbox.guest.agent.agent import _POWERSHELL_PATH, GuestAgent
from adam.sandbox.vbox.client import VirtualBoxClient
from adam.sandbox.vbox.models import VMOperationResult

VM_NAME = "ADAM_TEST_VM"
GUEST_USER = "Admin"
GUEST_PASS = "windows10"
PROCMON_PATH = "C:\\Users\\Admin\\Downloads\\ProcessMonitor\\Procmon64.exe"
TSHARK_PATH = "C:\\Program Files\\Wireshark\\tshark.exe"
SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"

PROCMON_CSV_FIXTURE = (
    # \n, not ProcMon's real \r\n -- this harness only exercises GuestAgent's
    # byte-for-byte copy_from_guest fidelity, not ProcmonCollector's own
    # newline handling (already independently verified in Phase 7's own
    # harness -- adam/collectors/procmon.py's `newline=""` read). Using \r\n
    # here would only exercise this script's own read-back call, not
    # GuestAgent itself.
    "Date & Time,Process Name,PID,Operation,Path,Result,Detail\n"
    "7/28/2026 2:32:11.4012207 PM,notepad.exe,4321,RegOpenKey,"
    "HKCU\\Software\\Test,SUCCESS,Desired Access: Read\n"
)
NETWORK_EK_FIXTURE = (
    # adam.collectors.parsers.pcap.parse_tshark_ek_line() reads these
    # fields as plain scalars (frame.number, frame.time_epoch, etc. are
    # inherently single-valued), not tshark's array convention reserved for
    # genuinely multi-valued fields -- see pcap.py's _layer()/int(number_raw).
    '{"index": {"_index": "packets"}}\n'
    '{"timestamp": "1690000000000", "layers": {"frame": {"frame.number": "1", '
    '"frame.time_epoch": "1690000000.0"}, "ip": {"ip.src": "10.0.0.5", '
    '"ip.dst": "10.0.0.6"}, "tcp": {"tcp.srcport": "1234", "tcp.dstport": "443"}}}\n'
)


def _split_guestcontrol_call(args: tuple) -> tuple[str, str, list[str]]:
    """Parses a ("guestcontrol", vm, "run"|"start", ..., "--exe", exe, "--", *arguments) tuple."""
    subcommand = args[2]
    exe_index = args.index("--exe")
    exe = args[exe_index + 1]
    if "--" in args[exe_index + 1 :]:
        dashdash = args.index("--", exe_index)
        arguments = list(args[dashdash + 1 :])
    else:
        arguments = []
    return subcommand, exe, arguments


class FakeVirtualBoxClient(VirtualBoxClient):
    """
    Simulates VBoxManage for both SandboxController's lifecycle calls and
    GuestAgent's guestcontrol calls, overriding only _run() -- every real
    method on VirtualBoxClient (run_in_guest, start_in_guest, copy_to_guest,
    copy_from_guest, restore_snapshot, ...) still executes, they just funnel
    through this fake boundary instead of a real subprocess.

    `guest_files` models the guest's own filesystem for files this fake
    creates/deletes; copy_from_guest only succeeds for a path present in
    it, and writes real FIXTURE content to the real host path so
    ProcmonCollector/NetworkCollector ingest genuine, parseable data --
    proving the "0 raw events captured" gap is actually fixed, not just
    that the plumbing didn't crash.
    """

    def __init__(
        self,
        *,
        procmon_tool_present: bool = True,
        tshark_tool_present: bool = True,
        sysmon_log_present: bool = True,
        procmon_capture_starts: bool = True,
        tshark_capture_starts: bool = True,
    ) -> None:
        super().__init__()
        self.calls: list[tuple] = []
        self.procmon_tool_present = procmon_tool_present
        self.tshark_tool_present = tshark_tool_present
        self.sysmon_log_present = sysmon_log_present
        self.procmon_capture_starts = procmon_capture_starts
        self.tshark_capture_starts = tshark_capture_starts
        self.guest_files: set[str] = set()

    async def _run(self, *args: str, timeout: float | None = None) -> VMOperationResult:
        self.calls.append(args)

        def ok(stdout: str = "") -> VMOperationResult:
            return VMOperationResult(success=True, command=args, duration_ms=1.0, return_code=0, stdout=stdout, stderr="")

        def fail(stderr: str = "simulated failure") -> VMOperationResult:
            return VMOperationResult(success=False, command=args, duration_ms=1.0, return_code=1, stdout="", stderr=stderr)

        # ---- SandboxController lifecycle ----
        if args[:2] == ("list", "vms"):
            return ok(f'"{VM_NAME}" {{fake-uuid}}')
        if args[0] == "showvminfo":
            return ok('VMState="running"')
        if args[0] == "snapshot" and len(args) > 2 and args[2] == "restore":
            return ok()
        if args[0] == "startvm":
            return ok()
        if args[0] == "controlvm":
            return ok()

        # ---- guestcontrol ----
        if args[0] == "guestcontrol":
            subcommand = args[2]

            if subcommand == "copyto":
                return ok()  # arm()'s sample transfer -- not under test here

            if subcommand == "copyfrom":
                guest_source_path, host_target_path = args[-2], args[-1]
                if guest_source_path not in self.guest_files:
                    return fail(f"no such file in guest: {guest_source_path}")
                if "sysmon" in guest_source_path.lower():
                    Path(host_target_path).write_bytes(b"FAKE-EVTX-NOT-REAL-BINARY")
                elif "procmon" in guest_source_path.lower():
                    Path(host_target_path).write_text(PROCMON_CSV_FIXTURE, encoding="utf-8")
                elif "network" in guest_source_path.lower():
                    Path(host_target_path).write_text(NETWORK_EK_FIXTURE, encoding="utf-8")
                return ok()

            subcommand, exe, arguments = _split_guestcontrol_call(args)
            exe_lower = exe.lower()

            if exe_lower == "cmd.exe":
                joined = " ".join(arguments)

                # Bug #1 fix (Task D): existence checks and directory dumps
                # now issue a bare `dir <path>` call as three separate argv
                # elements ("/c", "dir", path) instead of the old
                # `if exist "<path>" (exit 0) else (exit 1)` construct this
                # fake previously simulated -- see agent.py's
                # _path_exists_in_guest()/_dir_listing() docstrings.
                if len(arguments) == 3 and arguments[0] == "/c" and arguments[1] == "dir":
                    checked_path = arguments[2]
                    exists = checked_path in self.guest_files or (
                        (checked_path == PROCMON_PATH and self.procmon_tool_present)
                        or (checked_path == TSHARK_PATH and self.tshark_tool_present)
                    )
                    return ok(f" Directory of {checked_path}\n\n<fake dir listing>") if exists else fail("File Not Found")

                # Bug #1 fix: `if not exist <dir> mkdir <dir>` -- each token
                # (including capture_dir, repeated) is its own argv element.
                if "mkdir" in arguments:
                    return ok()

                # Bug #1 fix: `del /f /q <path>` -- path is its own argv
                # element, not embedded in a manually-quoted string.
                if "del" in arguments:
                    for path in list(self.guest_files):
                        if path in arguments:
                            self.guest_files.discard(path)
                    return ok()

                # Bug #1 fix: tshark -> EK JSON conversion now passes
                # tshark_path/"-r"/pcap_path/"-T"/"ek"/">"/ek_path as
                # separate, unquoted argv elements -- see agent.py's
                # _export_network() docstring. ek_path is read positionally
                # (the element right after ">"), not parsed out of a
                # quoted string the way the pre-fix version required.
                if "-T" in arguments and "ek" in arguments:
                    ek_path = arguments[arguments.index(">") + 1] if ">" in arguments else arguments[-1]
                    pcap_candidates = [p for p in self.guest_files if p.endswith(".pcapng")]
                    if not pcap_candidates:
                        return fail("no capture to convert")
                    self.guest_files.add(ek_path)
                    return ok()

                if "tasklist" in joined:
                    return ok()  # process-status checks -- not asserted on in this harness

                return ok()

            if exe_lower == "wevtutil.exe":
                if arguments[0] == "gli":
                    return ok() if self.sysmon_log_present else fail("channel not found")
                if arguments[0] == "epl":
                    evtx_path = arguments[2]
                    if not self.sysmon_log_present:
                        return fail("channel not found")
                    self.guest_files.add(evtx_path)
                    return ok()

            if exe_lower == "taskkill.exe":
                return ok()

            if exe_lower == PROCMON_PATH.lower():
                if "/Terminate" in arguments:
                    return ok()
                if "/BackingFile" in arguments:
                    if not self.procmon_capture_starts:
                        return fail("could not start Procmon")
                    pml_path = arguments[arguments.index("/BackingFile") + 1]
                    self.guest_files.add(pml_path)
                    return ok()
                if "/OpenLog" in arguments:
                    pml_path = arguments[arguments.index("/OpenLog") + 1]
                    csv_path = arguments[arguments.index("/SaveAs") + 1]
                    if pml_path not in self.guest_files:
                        return fail("no such backing file")
                    self.guest_files.add(csv_path)
                    return ok()

            if exe_lower == TSHARK_PATH.lower():
                if "-D" in arguments:
                    return ok("1. \\Device\\NPF_{FAKE-INTERFACE-GUID} (Ethernet)")
                if "-w" in arguments:
                    if not self.tshark_capture_starts:
                        return fail("could not start tshark")
                    pcap_path = arguments[arguments.index("-w") + 1]
                    self.guest_files.add(pcap_path)
                    return ok()

            if exe_lower == _POWERSHELL_PATH.lower():
                # Bug #2 fix (Task D): GuestAgent's pre-export Get-WinEvent
                # probe now uses the absolute PowerShell path, not the bare
                # "powershell.exe" name -- see agent.py's _POWERSHELL_PATH.
                return ok("1") if self.sysmon_log_present else fail("Get-WinEvent: no events found")

            if exe_lower == "whoami.exe":
                # Bug #4 diagnostics (Task D): probes run only when wevtutil
                # epl fails; this harness's sysmon_log_present=True path
                # never triggers them, but a fake response is provided for
                # completeness / for any future scenario that does.
                return ok("BUILTIN\\Administrators" if "/groups" in arguments else "SeBackupPrivilege  Disabled")

        return ok()


def _settings(**guest_tools_overrides: object) -> Settings:
    # pydantic coerces this plain dict into SandboxSettings at runtime (and
    # every scenario above proves it does); mypy doesn't know that, hence
    # the ignore.
    return Settings(
        sandbox={  # type: ignore[arg-type]
            "vm_name": VM_NAME,
            "guest_username": GUEST_USER,
            "guest_password": GUEST_PASS,
        },
        guest_tools=GuestToolsSettings(
            procmon_path=PROCMON_PATH,
            tshark_path=TSHARK_PATH,
            sysmon_log=SYSMON_LOG,
            **guest_tools_overrides,  # type: ignore[arg-type]
        ),
    )


async def scenario_verify_tools_all_present() -> None:
    client = FakeVirtualBoxClient()
    agent = GuestAgent(client, VM_NAME, guest_username=GUEST_USER, guest_password=GUEST_PASS, settings=_settings().guest_tools)
    report = await agent.verify_tools()
    assert report.procmon_available and report.tshark_available and report.sysmon_log_available, report
    assert report.detail == {}, report.detail
    print("PASS scenario_verify_tools_all_present")


async def scenario_verify_tools_missing_diagnostics() -> None:
    client = FakeVirtualBoxClient(procmon_tool_present=False, sysmon_log_present=False)
    agent = GuestAgent(client, VM_NAME, guest_username=GUEST_USER, guest_password=GUEST_PASS, settings=_settings().guest_tools)
    report = await agent.verify_tools()
    assert report.procmon_available is False
    assert report.tshark_available is True
    assert report.sysmon_log_available is False
    assert "procmon" in report.detail and repr(PROCMON_PATH) in report.detail["procmon"]
    assert "sysmon" in report.detail and SYSMON_LOG in report.detail["sysmon"]
    print("PASS scenario_verify_tools_missing_diagnostics:", report.detail)


async def scenario_full_capture_export_fetch() -> None:
    client = FakeVirtualBoxClient()
    agent = GuestAgent(client, VM_NAME, guest_username=GUEST_USER, guest_password=GUEST_PASS, settings=_settings().guest_tools)
    with tempfile.TemporaryDirectory() as tmp:
        await agent.start_captures("sess_test_001")
        artifacts = await agent.stop_export_and_fetch("sess_test_001", tmp)

        assert artifacts.sysmon_evtx_path is not None
        assert artifacts.procmon_csv_path is not None
        assert artifacts.network_ek_json_path is not None
        assert Path(artifacts.procmon_csv_path).read_text(encoding="utf-8") == PROCMON_CSV_FIXTURE
        assert "frame.number" in Path(artifacts.network_ek_json_path).read_text(encoding="utf-8")
    print("PASS scenario_full_capture_export_fetch:", artifacts)


async def scenario_partial_telemetry_procmon_never_starts() -> None:
    client = FakeVirtualBoxClient(procmon_capture_starts=False)
    agent = GuestAgent(client, VM_NAME, guest_username=GUEST_USER, guest_password=GUEST_PASS, settings=_settings().guest_tools)
    with tempfile.TemporaryDirectory() as tmp:
        await agent.start_captures("sess_test_002")
        artifacts = await agent.stop_export_and_fetch("sess_test_002", tmp)

    assert artifacts.sysmon_evtx_path is not None, "sysmon should be unaffected by procmon failing"
    assert artifacts.procmon_csv_path is None, "procmon should have failed gracefully"
    assert artifacts.network_ek_json_path is not None, "network should be unaffected by procmon failing"
    print("PASS scenario_partial_telemetry_procmon_never_starts:", artifacts)


class _FakeCollectorForOverrideCheck(BaseCollector):
    """Minimal stand-in occupying source_name='procmon' in the constructor-injected collectors list, for the override-skip scenario only."""

    @property
    def source_name(self) -> str:
        return "procmon"

    async def _run(self) -> None:
        while not self._stop_requested():
            await asyncio.sleep(0.01)


async def scenario_full_session_end_to_end() -> None:
    """
    The real, previously-broken case this phase exists to fix: `adam run
    <sample>` with NO CLI flags at all. Drives GuestAgent through a real
    SandboxController/SessionOrchestrator against the fake VBoxManage
    boundary and asserts raw.jsonl ends up genuinely populated -- not the
    "session COMPLETED (0 raw events captured)" starting point.
    """
    client = FakeVirtualBoxClient()
    settings = _settings()
    controller = SandboxController(
        client,
        VM_NAME,
        guest_username=GUEST_USER,
        guest_password=GUEST_PASS,
        boot_timeout=5.0,
        guest_ready_timeout=5.0,
        detonate_timeout=5.0,
    )
    bus = EventBus()
    guest_agent = GuestAgent(client, VM_NAME, guest_username=GUEST_USER, guest_password=GUEST_PASS, settings=settings.guest_tools)

    with tempfile.TemporaryDirectory() as tmp:
        orchestrator = SessionOrchestrator(
            controller, bus, [], artifacts_dir=tmp, guest_agent=guest_agent, post_detonation_drain_seconds=0.3
        )
        sample = SampleRef(sha256="a" * 64, md5="b" * 32, filename="benign.exe", size_bytes=10, file_type="PE32 executable")

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ-fake-binary")
            host_sample_path = f.name

        session = await orchestrator.run_session(
            sample, settings, host_sample_path=host_sample_path, session_id="sess_e2e_003", arm=Arm.CONTROL,
        )

    # 2, not 3: Sysmon's own event is expected to fail to parse -- this
    # harness's fake EVTX content is not a real binary EVTX file (no real
    # .evtx file is available in this environment to test against, the
    # same disclosed limitation as Phase 7's own SysmonCollector
    # verification). Procmon (1 real CSV row) and network (1 real EK JSON
    # document) are genuine, parseable fixtures and are expected to
    # succeed, proving the "0 raw events captured" gap is fixed for the
    # two sources this environment can actually exercise end-to-end.
    assert session.status.value == "COMPLETED", session
    assert session.metrics.raw_events == 2, f"expected 2 real RawEvents (procmon+network), got {session.metrics.raw_events}"
    print(f"PASS scenario_full_session_end_to_end: status={session.status.value} raw_events={session.metrics.raw_events}")


async def scenario_cli_override_skips_guest_capture() -> None:
    """
    Verifies a CLI-override collector (source_name='procmon') prevents
    GuestAgent from ever LAUNCHING Procmon (start_captures'/
    stop_export_and_fetch's `capture_procmon`/`export_procmon` flags never
    fire for this source) -- "existing CLI flags ... remain only as
    optional overrides."

    Deliberately narrower than "GuestAgent never mentions PROCMON_PATH
    anywhere": SessionOrchestrator calls verify_tools() unconditionally for
    every session regardless of CLI overrides (Task C's diagnostics wiring,
    agent.py's verify_tools() docstring -- "This method exists primarily to
    produce the up-front diagnostic log messages ... not as a gate other
    methods depend on"), and verify_tools() legitimately issues a
    `cmd.exe /c dir <procmon_path>` existence check as part of that,
    touching PROCMON_PATH without ever launching Procmon64.exe itself. A
    pre-Bug-#1-fix version of this assertion (`PROCMON_PATH in c`, exact
    tuple-element membership) accidentally never caught that diagnostic
    call, because the old, broken `if exist "<path>" (exit 0) else
    (exit 1)` quoting embedded PROCMON_PATH inside a single longer string
    argument rather than as its own exact argv element -- so the assertion
    passed for the wrong reason. The Bug #1 quoting fix makes `dir <path>`
    pass PROCMON_PATH as its own exact argv element, correctly exposing
    that gap. The real guarantee this scenario exists to prove -- Procmon
    is never *executed* for a CLI-overridden source -- is what's checked
    below: no call's `--exe` argument is Procmon64.exe.
    """
    client = FakeVirtualBoxClient()
    settings = _settings()
    controller = SandboxController(
        client, VM_NAME, guest_username=GUEST_USER, guest_password=GUEST_PASS,
        boot_timeout=5.0, guest_ready_timeout=5.0, detonate_timeout=5.0,
    )
    bus = EventBus()
    guest_agent = GuestAgent(client, VM_NAME, guest_username=GUEST_USER, guest_password=GUEST_PASS, settings=settings.guest_tools)
    override_collector = _FakeCollectorForOverrideCheck()

    with tempfile.TemporaryDirectory() as tmp:
        orchestrator = SessionOrchestrator(
            controller, bus, [override_collector], artifacts_dir=tmp, guest_agent=guest_agent, post_detonation_drain_seconds=0.2
        )
        sample = SampleRef(sha256="c" * 64, md5="d" * 32, filename="benign2.exe", size_bytes=10, file_type="PE32 executable")
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ-fake-binary")
            host_sample_path = f.name

        session = await orchestrator.run_session(
            sample, settings, host_sample_path=host_sample_path, session_id="sess_override_004",
        )

    assert session.status.value == "COMPLETED", session
    procmon_exec_calls = [
        c for c in client.calls if "--exe" in c and c[c.index("--exe") + 1].lower() == PROCMON_PATH.lower()
    ]
    assert procmon_exec_calls == [], f"GuestAgent should never have executed Procmon64.exe, but issued: {procmon_exec_calls}"
    print("PASS scenario_cli_override_skips_guest_capture (0 Procmon64.exe executions issued, as expected)")


async def main() -> None:
    await scenario_verify_tools_all_present()
    await scenario_verify_tools_missing_diagnostics()
    await scenario_full_capture_export_fetch()
    await scenario_partial_telemetry_procmon_never_starts()
    await scenario_full_session_end_to_end()
    await scenario_cli_override_skips_guest_capture()
    print("\nALL SCENARIOS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
