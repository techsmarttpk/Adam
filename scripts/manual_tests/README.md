# scripts/manual_tests/

Standalone infrastructure diagnostics for investigating VirtualBox
Guest Additions and GuestControl readiness -- specifically, the
~70-100 second delay observed between a VM reporting "running" and
GuestControl actually accepting sessions after a snapshot restore.

**Most of these scripts are intentionally isolated from production code.**
None of `guest_runlevel_monitor.py`/`guestcontrol_probe.py`/
`waitrunlevel_monitor.py`/`guestproperty_dump.py`/`boot_readiness_trace.py`
import or depend on `SandboxController`, `VirtualBoxClient`, or
`wait_for_guest_ready()`. They exist to gather evidence *before* deciding
whether any architectural change to those is even warranted. Each calls
`VBoxManage` directly through the shared `vbox_cli.run_vboxmanage()`
wrapper -- nothing there reuses or touches `adam/sandbox/vbox/client.py`.

**One script here is the deliberate exception:**
`guest_agent_offline_verification.py` (below) exercises real production
code (`GuestAgent`, `SandboxController`, `SessionOrchestrator`, the
collectors) end to end, offline, against a faked VBoxManage boundary --
it does not touch a real VM at all, unlike every other script in this
directory.

All scripts require Python 3.11, run on Windows (the host), and must be
invoked as modules from the project root so their `scripts.manual_tests.*`
imports resolve, e.g.:

```
python -m scripts.manual_tests.guest_runlevel_monitor --vm ADAM_WIN10_OFFICE
```

Logs are written under `logs/manual_tests/` (created automatically).
Every script logs full detail to a timestamped file there via
`logging`, and prints only a short final summary via plain `print()`.

## Files

### `vbox_cli.py`
The shared `VBoxManage` wrapper every other script here is built on.
`run_vboxmanage(args, *, timeout=None) -> VBoxCommandResult` runs
`subprocess.run()`, times it, and returns a typed result (`command`,
`return_code`, `stdout`, `stderr`, `duration_ms`) instead of raising on
a non-zero exit code -- non-zero/timeout outcomes are exactly what
these tools exist to observe. Not a script you run directly.

### `logging_utils.py`
Shared logging setup (`setup_logging(script_name) -> (logger, log_path)`)
used by every script below. Not a script you run directly.

### `guest_runlevel_monitor.py`
**What it measures:** how long it takes Guest Additions to progress
through its run levels -- `Unknown -> None (0) -> System (1) ->
Userland (2) -> Desktop (3)` -- by polling the guest property
`/VirtualBox/GuestAdd/RunLevel` on an interval.

**When to use it:** to answer *"has Guest Additions itself finished
initializing yet, independent of whether GuestControl works"*. This is
a plain guest-property read, so it has none of GuestControl's own
failure modes.

**Expected output:** a `TRANSITION` log line each time the level
changes, and a final summary like:
```
Guest Additions reached Desktop run level after 68.80 seconds (35 polls).
```

**Args:** `--vm` (default `ADAM_WIN10_OFFICE`), `--interval` (default
`1.0`), `--timeout` (default `180.0`).

### `guestcontrol_probe.py`
**What it measures:** the exact moment `guestcontrol run` starts
working, by repeatedly attempting `cmd.exe /c echo READY` until it
succeeds.

**When to use it:** to answer *"when can I actually run something in
the guest"* -- the real-world question `wait_for_guest_ready()` exists
to answer, measured independently of that production code. Classifies
every failed attempt as either the `CreateSession` stage ("Guest
Additions not ready") or the `WaitForArray` stage ("execution service
not ready"), matching the two known VBoxManage error signatures.

**Expected output:** one log line per attempt, then:
```
GuestControl became available after 74.30 seconds (34 attempts).
```

**Args:** `--vm`, `--username` (default `Admin`), `--password` (default
`windows10`), `--interval` (default `2.0`), `--timeout` (default `180.0`).

### `waitrunlevel_monitor.py`
**What it measures:** the same readiness question as
`guestcontrol_probe.py`, but using VirtualBox's own dedicated blocking
call, `VBoxManage guestcontrol <vm> waitrunlevel userland`, instead of
polling with a real process launch.

**When to use it:** to check whether `waitrunlevel` is a cheaper, more
accurate readiness signal than probing with `guestcontrol run` --
compare its reported duration against `guestcontrol_probe.py`'s.

**Expected output:** a single log line with the call's duration and
result, then a one-line summary.

**Args:** `--vm`, `--level` (`system` | `userland` | `desktop`, default
`userland`), `--timeout` (default `180.0`).

### `guestproperty_dump.py`
**What it measures:** nothing by itself -- it's a snapshot tool. Runs
`VBoxManage guestproperty enumerate <vm>` and saves the full output to
`logs/manual_tests/guestproperties_<timestamp>.txt`.

**When to use it:** whenever you want to eyeball everything VirtualBox
currently knows about the guest (GA version, OS info, network state,
logged-in users) without remembering individual property names --
useful before/after a Guest Additions reinstall, or alongside a trace
run for extra context.

**Args:** `--vm`.

### `boot_readiness_trace.py`
**The primary investigation tool.** Runs `guest_runlevel_monitor` and
`guestcontrol_probe` *concurrently* (via `asyncio.to_thread`, since
`run_vboxmanage()` is intentionally a blocking call) against the same
boot, and merges both event streams into one chronological timeline:

```
00.0 trace started (assumes VM was just started/restored)
03.1 RunLevel = 1
04.2 GuestControl: Guest Additions not ready
09.5 RunLevel = 2
10.1 GuestControl: execution service not ready
68.8 RunLevel = 3
74.3 GuestControl SUCCESS
```

**When to use it:** this is the tool that actually answers "does
GuestControl readiness track RunLevel, or lag behind it by a
separately-explainable amount (e.g. VBoxService being a Delayed Auto
Start Windows service)". Start (or restore-then-start) the VM yourself
immediately before running it, so elapsed time is measured from as
close to "VM powered on" as practical.

**Output:** `logs/manual_tests/boot_trace_<timestamp>.log` (the merged
timeline) plus the usual full per-attempt log.

**Args:** `--vm`, `--username`, `--password`, `--interval` (applies to
both monitors), `--timeout` (applies to both monitors).

### `guest_services_report.bat`
**Runs INSIDE the guest**, not on the host -- copy it in (shared folder,
or just retype it) and run it manually from a guest command prompt.
Collects, into one timestamped report file next to the script:
- `sc query VBoxService` -- is the service actually running?
- `sc qc VBoxService` -- its startup type. **This is the single most
  important line in the whole report**: if it reads `AUTO_START
  (DELAYED)`, that is very likely the entire explanation for the
  ~70-100s delay (Windows intentionally holds delayed-start services
  back for roughly the first 1-2 minutes after boot, to reduce startup
  contention -- the timing lines up almost exactly).
- `sc query seclogon` -- Secondary Logon, needed for GuestControl to
  run processes as a specific user.
- `tasklist | findstr VBox` -- which VBox processes are actually alive.
- `VBoxControl.exe --version` -- Guest Additions version, from inside.
- `systeminfo` -- OS build and boot time.

**When to use it:** whenever `guest_runlevel_monitor.py` /
`guestcontrol_probe.py` show a long delay and you want to know *why*
from the guest's own perspective, especially to check VBoxService's
startup type.

### `guest_agent_offline_verification.py`
**What it verifies:** Phase 5's `GuestAgent` (`adam/sandbox/guest/agent/agent.py`)
and its integration into `SessionOrchestrator`/`Runner` -- tool-verification
diagnostics, full capture/export/fetch producing real host files, partial
telemetry (one source failing doesn't affect the others), a full
`SessionOrchestrator` session with zero CLI override paths producing real
`RawEvent`s (the "0 raw events captured" gap this phase exists to fix), and
a CLI-override path correctly stopping GuestAgent from ever touching that
source.

**When to use it:** after any change to `GuestAgent`, `SessionOrchestrator`,
or the collectors' wiring, to re-verify the whole chain without a VM.

**Does NOT require a live VM, VBoxManage, Procmon, tshark, or Sysmon to be
present anywhere** -- everything is faked at the `VirtualBoxClient._run()`
boundary, the same technique used throughout this project's own offline
verification (see docs/implementation-audit.md's Phase 3/4/8 sections).

**Expected output:** one `PASS <scenario_name>` line per scenario, then
`ALL SCENARIOS PASSED`. Any `AssertionError` or unhandled traceback means a
real regression.

**Run:**
```
python -m scripts.manual_tests.guest_agent_offline_verification
```
(from the project root; needs `ADAM__SANDBOX__GUEST_USERNAME` /
`ADAM__SANDBOX__GUEST_PASSWORD` set to any value, same as every other
`Settings()`-constructing entrypoint -- see adam/common/config.py.)

## How these distinguish the five open questions

1. **Guest Additions not initialized at all** -- `guest_runlevel_monitor.py`
   stuck at `Unknown` or `None (0)` for a long time; `guest_services_report.bat`
   showing `VBoxService` not `RUNNING` in `sc query`.
2. **GuestControl specifically unavailable (even though GA is up)** --
   `guest_runlevel_monitor.py` already past `Userland (2)` while
   `guestcontrol_probe.py` still failing; check `guest_services_report.bat`'s
   `seclogon` status.
3. **VBoxService issues specifically** -- `guest_services_report.bat`'s
   `sc query VBoxService` / `sc qc VBoxService` output -- not running,
   crashing, or (most likely per the last investigation) registered as
   Delayed Auto Start.
4. **RunLevel timing** -- `guest_runlevel_monitor.py`'s transition
   timestamps alone, run-to-run, to see how consistent (or not) the
   climb through System -> Userland -> Desktop is.
5. **Boot timing overall, and how RunLevel/GuestControl relate to it** --
   `boot_readiness_trace.py`'s merged timeline is the tool built
   specifically for this: it's the only one that shows both signals on
   the same clock, from the same boot.
