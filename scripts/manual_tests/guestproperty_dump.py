"""
scripts/manual_tests/guestproperty_dump.py

Purpose: dump every VirtualBox guest property for a VM to a timestamped
text file, for manual inspection (Guest Additions version, OS info,
network state, logged-in users, or anything else VirtualBox happens to
be tracking) without having to remember individual property names.
"""

from __future__ import annotations

import argparse

from scripts.manual_tests.logging_utils import LOGS_DIR, setup_logging, timestamp_tag
from scripts.manual_tests.vbox_cli import run_vboxmanage


def dump_guestproperties(vm: str) -> tuple[int, str]:
    """
    Run `VBoxManage guestproperty enumerate <vm>` and save the raw
    stdout to logs/manual_tests/guestproperties_<timestamp>.txt.

    Returns (property_count, output_file_path). property_count is a
    rough count of "Name:" lines in the output (0 if the command
    failed or the VM has no properties yet).
    """
    logger, _ = setup_logging(
        "guestproperty_dump", log_file_name=f"guestproperty_dump_{timestamp_tag()}.log"
    )

    result = run_vboxmanage(["guestproperty", "enumerate", vm], timeout=30.0)
    logger.info(
        "guestproperty enumerate: return_code=%d duration_ms=%.1f stderr=%r",
        result.return_code, result.duration_ms, result.stderr.strip(),
    )

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = LOGS_DIR / f"guestproperties_{timestamp_tag()}.txt"
    output_path.write_text(result.stdout, encoding="utf-8")

    property_count = sum(1 for line in result.stdout.splitlines() if line.strip().startswith("Name:"))
    logger.info("Wrote %d properties to %s", property_count, output_path)

    return property_count, str(output_path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", default="ADAM_WIN10_OFFICE")
    args = parser.parse_args()

    count, output_path = dump_guestproperties(args.vm)
    print(f"Dumped {count} guest properties to: {output_path}")


if __name__ == "__main__":
    main()
