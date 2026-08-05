"""
scripts/manual_tests/boot_readiness_trace.py

Primary investigation tool. Runs guest_runlevel_monitor's RunLevel
polling and guestcontrol_probe's GuestControl probing CONCURRENTLY
against the same boot, and merges both event streams into one
chronological timeline, e.g.:

    00.0 trace started (assumes VM was just started/restored)
    03.1 RunLevel = 1
    04.2 GuestControl: Guest Additions not ready
    09.5 RunLevel = 2
    10.1 GuestControl: execution service not ready
    68.8 RunLevel = 3
    74.3 GuestControl SUCCESS

That is exactly what answers the open question from the manual
investigation: does GuestControl readiness track RunLevel directly, or
lag behind it by a separately-explainable amount (e.g. VBoxService
being registered as a Delayed Auto Start Windows service)?

Concurrency note: vbox_cli.run_vboxmanage() is a deliberately blocking
subprocess.run() call (see vbox_cli.py's docstring). To run the two
monitors at the same time without reimplementing the wrapper as async,
each one is handed to its own thread via asyncio.to_thread() and
awaited together with asyncio.gather(). Neither monitor touches
SandboxController, VirtualBoxClient, or wait_for_guest_ready() -- this
script only ever calls VBoxManage directly via vbox_cli.run_vboxmanage().

You are expected to start (or restore-then-start) the VM yourself
immediately before running this script, so elapsed time is measured
from as close to "VM powered on" as practical.

Run standalone:
    python -m scripts.manual_tests.boot_readiness_trace --vm ADAM_WIN10_OFFICE \\
        --username Admin --password windows10
"""

from __future__ import annotations

import argparse
import asyncio
import threading
import time

from scripts.manual_tests.guest_runlevel_monitor import monitor_runlevel
from scripts.manual_tests.guestcontrol_probe import probe_guestcontrol
from scripts.manual_tests.logging_utils import LOGS_DIR, setup_logging, timestamp_tag


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", default="ADAM_WIN10_OFFICE")
    parser.add_argument("--username", default="Admin")
    parser.add_argument("--password", default="windows10")
    parser.add_argument("--interval", type=float, default=1.0, help="Poll interval for BOTH monitors (default: 1.0)")
    parser.add_argument("--timeout", type=float, default=180.0, help="Overall budget for BOTH monitors (default: 180.0)")
    args = parser.parse_args()

    logger, log_path = setup_logging("boot_readiness_trace")
    logger.info(
        "Starting combined boot readiness trace: vm=%s interval=%.2fs timeout=%.2fs",
        args.vm, args.interval, args.timeout,
    )

    events: list[tuple[float, str]] = []
    events_lock = threading.Lock()
    trace_start = time.monotonic()

    def record(elapsed: float, message: str) -> None:
        # `elapsed` is relative to each monitor's own start time; both
        # monitors are launched together in run_both() below, so their
        # elapsed values are comparable to within normal thread-
        # scheduling jitter (milliseconds, not seconds).
        with events_lock:
            events.append((elapsed, message))

    record(0.0, "trace started (assumes VM was just started/restored)")

    async def run_both() -> None:
        await asyncio.gather(
            asyncio.to_thread(
                monitor_runlevel, args.vm, args.interval, args.timeout, logger, record
            ),
            asyncio.to_thread(
                probe_guestcontrol,
                args.vm, args.username, args.password, args.interval, args.timeout, logger, record,
            ),
        )

    asyncio.run(run_both())

    total_duration = time.monotonic() - trace_start
    logger.info("Both monitors finished after %.2fs total", total_duration)

    events.sort(key=lambda item: item[0])

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    trace_path = LOGS_DIR / f"boot_trace_{timestamp_tag()}.log"
    with trace_path.open("w", encoding="utf-8") as f:
        for elapsed, message in events:
            f.write(f"{elapsed:05.1f} {message}\n")

    print(f"Boot readiness trace ({len(events)} events) written to: {trace_path}")
    print(f"Full per-attempt log: {log_path}")


if __name__ == "__main__":
    main()
