"""
scripts/manual_tests/guest_runlevel_monitor.py

Purpose: continuously poll VirtualBox's own Guest Additions run-level
guest property (/VirtualBox/GuestAdd/RunLevel) and log every state
transition, from "Unknown" (property not set yet) through:

    Unknown -> None (0) -> System (1) -> Userland (2) -> Desktop (3)

This is a plain guest-property read -- it does NOT open a GuestControl
session, so it has none of the CreateSession/WaitForArray failure modes
that guestcontrol_probe.py exists to observe. Comparing this script's
timeline against guestcontrol_probe.py's (see boot_readiness_trace.py)
is how we find out whether GuestControl readiness tracks RunLevel
directly or lags behind it by a separately-explainable amount.

Run standalone:
    python -m scripts.manual_tests.guest_runlevel_monitor --vm ADAM_WIN10_OFFICE
"""

from __future__ import annotations

import argparse
import logging
import time
from typing import Callable

from scripts.manual_tests.logging_utils import setup_logging
from scripts.manual_tests.vbox_cli import run_vboxmanage

RUN_LEVEL_NAMES: dict[int, str] = {
    0: "None",
    1: "System",
    2: "Userland",
    3: "Desktop",
}

# Called with (elapsed_seconds, message) once per observed TRANSITION
# (not once per poll) -- see monitor_runlevel().
RunLevelEventCallback = Callable[[float, str], None]


def _parse_runlevel(stdout: str) -> int | None:
    """
    Parse `VBoxManage guestproperty get <vm> /VirtualBox/GuestAdd/RunLevel`
    stdout. Returns the integer run level, or None if the property has
    no value yet -- VBoxManage prints "No value set!" before Guest
    Additions has written anything at all, which is the "Unknown" state
    that precedes run level 0 (None).
    """
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Value:"):
            value_str = stripped.removeprefix("Value:").strip()
            try:
                return int(value_str)
            except ValueError:
                return None
    return None


def monitor_runlevel(
    vm: str,
    interval: float,
    timeout: float,
    logger: logging.Logger,
    on_event: RunLevelEventCallback | None = None,
) -> tuple[float | None, int]:
    """
    Poll the RunLevel guest property every `interval` seconds until it
    reaches Desktop (3) or `timeout` seconds have elapsed.

    Returns (elapsed_seconds_at_desktop, poll_count) on success, or
    (None, poll_count) if the timeout was hit first.

    Calls on_event(elapsed, message) only on a transition (i.e. when the
    parsed level differs from the previous poll), with a message of the
    form "RunLevel = 2" -- matching the format boot_readiness_trace.py
    merges into its combined timeline. RunLevel is cheap to poll and
    rarely flaps, so only transitions are interesting there; every poll
    (transition or not) is still written to the DEBUG-level file log.
    """
    start = time.monotonic()
    previous_name = "Unknown"
    attempt = 0

    while True:
        elapsed = time.monotonic() - start
        if elapsed > timeout:
            logger.warning(
                "TIMEOUT after %.2fs -- run level never reached Desktop (3); last seen: %s",
                elapsed, previous_name,
            )
            return None, attempt

        attempt += 1
        result = run_vboxmanage(
            ["guestproperty", "get", vm, "/VirtualBox/GuestAdd/RunLevel"], timeout=15.0
        )
        level = _parse_runlevel(result.stdout)
        current_name = RUN_LEVEL_NAMES.get(level, "Unknown") if level is not None else "Unknown"

        logger.debug(
            "attempt=%d elapsed=%.2fs return_code=%d stdout=%r stderr=%r parsed_level=%s",
            attempt, elapsed, result.return_code,
            result.stdout.strip(), result.stderr.strip(), current_name,
        )

        if current_name != previous_name:
            logger.info("TRANSITION elapsed=%.2fs %s -> %s", elapsed, previous_name, current_name)
            if on_event is not None:
                on_event(elapsed, f"RunLevel = {level if level is not None else current_name}")
            previous_name = current_name

        if level == 3:
            logger.info("Run level reached Desktop (3) after %.2fs (%d polls)", elapsed, attempt)
            return elapsed, attempt

        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", default="ADAM_WIN10_OFFICE", help="VM name (default: ADAM_WIN10_OFFICE)")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between polls (default: 1.0)")
    parser.add_argument("--timeout", type=float, default=180.0, help="Give up after this many seconds (default: 180.0)")
    args = parser.parse_args()

    logger, log_path = setup_logging("guest_runlevel_monitor")
    logger.info(
        "Starting RunLevel monitor: vm=%s interval=%.2fs timeout=%.2fs",
        args.vm, args.interval, args.timeout,
    )

    elapsed, attempts = monitor_runlevel(args.vm, args.interval, args.timeout, logger)

    if elapsed is not None:
        print(f"Guest Additions reached Desktop run level after {elapsed:.2f} seconds ({attempts} polls).")
    else:
        print(f"TIMED OUT after {args.timeout:.2f} seconds -- Desktop run level never reached.")
    print(f"Full log: {log_path}")


if __name__ == "__main__":
    main()
