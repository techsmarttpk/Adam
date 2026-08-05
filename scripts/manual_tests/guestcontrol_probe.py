"""
scripts/manual_tests/guestcontrol_probe.py

Purpose: measure exactly when GuestControl (guestcontrol run) becomes
usable against a running VM, by repeatedly attempting a trivial
`cmd.exe /c echo READY` and logging every attempt until the first
success.

This deliberately mirrors -- but does NOT call -- the real
wait_for_guest_ready() in adam/sandbox/vbox/client.py. It exists so we
can keep investigating GuestControl timing without touching production
code or its retry/timeout logic.

Known trap this script avoids repeating (see adam/sandbox/vbox/client.py
history): the per-attempt VBoxManage timeout must be independent from
the polling interval, or a probe that's merely slow (not hung) gets
killed and misreported as "not ready." PROBE_TIMEOUT_SECONDS below is
deliberately generous and decoupled from --interval.

Run standalone:
    python -m scripts.manual_tests.guestcontrol_probe --vm ADAM_WIN10_OFFICE \\
        --username Admin --password windows10
"""

from __future__ import annotations

import argparse
import logging
import time
from typing import Callable

from scripts.manual_tests.logging_utils import setup_logging
from scripts.manual_tests.vbox_cli import VBoxCommandResult, run_vboxmanage

# Per-attempt VBoxManage timeout, independent of --interval. See module
# docstring -- conflating these two was a real bug in the production
# wait_for_guest_ready() before it was fixed there.
PROBE_TIMEOUT_SECONDS = 20.0

# Called with (elapsed_seconds, message) once per ATTEMPT, success or
# failure -- unlike guest_runlevel_monitor's on_event, which only fires
# on transitions. Every attempt here is meaningful for the merged
# timeline in boot_readiness_trace.py.
GuestControlEventCallback = Callable[[float, str], None]


def _classify(result: VBoxCommandResult) -> str:
    """
    Turn one guestcontrol attempt's result into a short, human-readable
    classification matching the two known VBoxManage failure stages
    (CreateSession vs. WaitForArray) plus success, for use in both
    regular logging and the merged timeline boot_readiness_trace.py
    builds.
    """
    if result.return_code == 0:
        return "GuestControl SUCCESS"
    stderr = result.stderr
    if "Guest Additions are not installed or not ready" in stderr:
        return "GuestControl: Guest Additions not ready"
    if "guest execution service is not ready" in stderr.lower():
        return "GuestControl: execution service not ready"
    if result.return_code == -1:
        return "GuestControl: probe timed out (killed)"
    return f"GuestControl: error (return_code={result.return_code})"


def probe_guestcontrol(
    vm: str,
    username: str,
    password: str,
    interval: float,
    timeout: float,
    logger: logging.Logger,
    on_event: GuestControlEventCallback | None = None,
) -> tuple[float | None, int]:
    """
    Repeatedly attempt `guestcontrol run ... echo READY` every
    `interval` seconds until it succeeds or `timeout` seconds have
    elapsed.

    Returns (elapsed_seconds_at_success, attempt_count) on success, or
    (None, attempt_count) if the overall timeout was hit first.

    Calls on_event(elapsed, message) once per attempt with a short
    classification string (see _classify), regardless of outcome -- the
    caller decides what to do with that (log it, merge it into a
    combined timeline, etc).
    """
    start = time.monotonic()
    attempt = 0

    while True:
        elapsed = time.monotonic() - start
        if elapsed > timeout:
            logger.warning("TIMEOUT after %.2fs -- GuestControl never succeeded", elapsed)
            return None, attempt

        attempt += 1
        probe_start = time.monotonic()
        result = run_vboxmanage(
            [
                "guestcontrol", vm, "run",
                "--username", username,
                "--password", password,
                "--exe", "cmd.exe",
                "--wait-stdout",
                "--wait-stderr",
                "--",
                "cmd.exe", "/c", "echo", "READY",
            ],
            timeout=PROBE_TIMEOUT_SECONDS,
        )
        probe_duration = time.monotonic() - probe_start
        classification = _classify(result)

        logger.debug(
            "attempt=%d elapsed=%.2fs probe_duration=%.2fs return_code=%d stdout=%r stderr=%r -- %s",
            attempt, elapsed, probe_duration, result.return_code,
            result.stdout.strip(), result.stderr.strip(), classification,
        )

        if on_event is not None:
            on_event(elapsed, classification)

        if result.return_code == 0:
            if "READY" not in result.stdout:
                logger.warning(
                    "return_code=0 but 'READY' not found in stdout (%r) -- treating as success anyway",
                    result.stdout.strip(),
                )
            logger.info("GuestControl succeeded after %.2fs (%d attempts)", elapsed, attempt)
            return elapsed, attempt

        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", default="ADAM_WIN10_OFFICE")
    parser.add_argument("--username", default="Admin")
    parser.add_argument("--password", default="windows10")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between attempts (default: 2.0)")
    parser.add_argument("--timeout", type=float, default=180.0, help="Give up after this many seconds (default: 180.0)")
    args = parser.parse_args()

    logger, log_path = setup_logging("guestcontrol_probe")
    logger.info(
        "Starting GuestControl probe: vm=%s interval=%.2fs timeout=%.2fs",
        args.vm, args.interval, args.timeout,
    )

    elapsed, attempts = probe_guestcontrol(
        args.vm, args.username, args.password, args.interval, args.timeout, logger
    )

    if elapsed is not None:
        print(f"GuestControl became available after {elapsed:.2f} seconds ({attempts} attempts).")
    else:
        print(f"TIMED OUT after {args.timeout:.2f} seconds -- GuestControl never became available.")
    print(f"Full log: {log_path}")


if __name__ == "__main__":
    main()
