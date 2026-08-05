"""
scripts/manual_tests/waitrunlevel_monitor.py

Purpose: measure GuestControl readiness using VirtualBox's own dedicated
blocking primitive -- `VBoxManage guestcontrol <vm> waitrunlevel
userland` -- instead of polling by attempting real process execution
(that's what guestcontrol_probe.py does). This lets us compare the two
approaches directly: does `waitrunlevel userland` report ready at the
same moment guestcontrol_probe.py's first successful `run` happens, or
earlier/later? If waitrunlevel is reliably earlier and just as
accurate, it's a strictly cheaper readiness signal than probing with a
real process launch.

Only one VBoxManage call is made; it blocks (up to --timeout) inside
VBoxManage itself, so there is no polling loop in this script.

Run standalone:
    python -m scripts.manual_tests.waitrunlevel_monitor --vm ADAM_WIN10_OFFICE
"""

from __future__ import annotations

import argparse
import logging

from scripts.manual_tests.logging_utils import setup_logging
from scripts.manual_tests.vbox_cli import run_vboxmanage


def wait_for_runlevel(
    vm: str,
    level: str,
    timeout: float,
    logger: logging.Logger,
) -> bool:
    """
    Call `VBoxManage guestcontrol <vm> waitrunlevel --timeout=<ms> <level>`
    and log the outcome. Returns True if VBoxManage reported success
    (return_code == 0), False otherwise (including if it timed out).

    Note: VBoxManage's own --timeout option is in milliseconds; the
    subprocess-level timeout passed to run_vboxmanage() is set a little
    larger so our own subprocess.run() doesn't kill the call before
    VBoxManage has had a chance to return control on its own timeout.
    """
    timeout_ms = int(timeout * 1000)
    logger.info("Calling waitrunlevel: vm=%s level=%s timeout=%.2fs", vm, level, timeout)

    result = run_vboxmanage(
        ["guestcontrol", vm, "waitrunlevel", f"--timeout={timeout_ms}", level],
        timeout=timeout + 10.0,
    )

    logger.info(
        "waitrunlevel finished: duration=%.2fs return_code=%d stdout=%r stderr=%r",
        result.duration_ms / 1000.0, result.return_code,
        result.stdout.strip(), result.stderr.strip(),
    )

    return result.return_code == 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", default="ADAM_WIN10_OFFICE")
    parser.add_argument(
        "--level", default="userland", choices=["system", "userland", "desktop"],
        help="Run level to wait for (default: userland -- the level GuestControl process execution needs)",
    )
    parser.add_argument("--timeout", type=float, default=180.0)
    args = parser.parse_args()

    logger, log_path = setup_logging("waitrunlevel_monitor")

    succeeded = wait_for_runlevel(args.vm, args.level, args.timeout, logger)

    if succeeded:
        print(f"waitrunlevel {args.level} succeeded. See log for exact duration: {log_path}")
    else:
        print(f"waitrunlevel {args.level} did NOT succeed within {args.timeout:.2f}s. See log: {log_path}")


if __name__ == "__main__":
    main()
