"""
scripts/manual_test_guest_execution.py

Manual smoke test for Milestone 2 -- VirtualBoxClient's guestcontrol-based
guest execution methods (run_in_guest, wait_for_guest_ready, copy_to_guest).

This is a TEMPORARY BRIDGE (see client.py module docstring): these methods
use VBoxManage's built-in guestcontrol, not the HTTP-based custom agent
ARCHITECTURE.md section 15.3 actually commits to. Requires Guest Additions
installed and running in the ADAM_WIN10_OFFICE guest, and the local guest
account below.

Not an automated test -- no assertions that fail the process. Prints what
happened at each step, same convention as manual_test_vbox_client.py, so a
human can read VirtualBox's actual behaviour for the required edge cases:
incorrect credentials and an execution timeout.

Usage:
    python scripts/manual_test_guest_execution.py
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from adam.common.config import get_settings
from adam.sandbox.vbox.client import VirtualBoxClient
from adam.sandbox.vbox.models import VMOperationResult

# Test-script detail only, not sandbox configuration -- stays local.
GUEST_TARGET_PATH = "C:\\Users\\Admin\\Desktop\\adam_test.txt"


def _banner(title: str) -> None:
    print(f"\n--- {title} ---")


def _show(result: VMOperationResult) -> None:
    print(f"success={result.success} return_code={result.return_code} duration_ms={result.duration_ms:.1f}")
    if result.termination_reason:
        print(f"termination_reason: {result.termination_reason}")
    if result.stdout.strip():
        print(f"stdout: {result.stdout.strip()[:300]}")
    if result.stderr.strip():
        print(f"stderr: {result.stderr.strip()[:300]}")


async def main() -> None:
    # Milestone 4: vm_name / credentials come from Configuration now
    # (config/default.toml + .env), not hardcoded module constants.
    sandbox_settings = get_settings().sandbox
    VM_NAME = sandbox_settings.vm_name
    GUEST_USERNAME = sandbox_settings.guest_username
    GUEST_PASSWORD = sandbox_settings.guest_password

    client = VirtualBoxClient()

    _banner("ensure VM is running")
    state = await client.get_state(VM_NAME)
    print(f"current state: {state}")
    if state != "running":
        _show(await client.start(VM_NAME, headless=True))
        _show(await client.wait_for_state(VM_NAME, "running", timeout=30.0))

    _banner("1. wait_for_guest_ready()")
    ready = await client.wait_for_guest_ready(
        VM_NAME,
        guest_username=GUEST_USERNAME,
        guest_password=GUEST_PASSWORD,
        timeout=90.0,
    )
    _show(ready)
    if not ready.success:
        print(
            "Guest Additions never became ready -- stopping here. Check that "
            "VBoxService is running inside the guest and that the 'clean' "
            "snapshot was taken AFTER Guest Additions were installed."
        )
        return

    _banner("2. run_in_guest: cmd.exe /c echo hello")
    _show(
        await client.run_in_guest(
            VM_NAME,
            guest_username=GUEST_USERNAME,
            guest_password=GUEST_PASSWORD,
            executable_path="cmd.exe",
            arguments=["/c", "echo hello"],
            timeout=15.0,
        )
    )

    _banner("3. run_in_guest: cmd.exe /c whoami")
    _show(
        await client.run_in_guest(
            VM_NAME,
            guest_username=GUEST_USERNAME,
            guest_password=GUEST_PASSWORD,
            executable_path="cmd.exe",
            arguments=["/c", "whoami"],
            timeout=15.0,
        )
    )

    _banner("4. copy_to_guest: small text file")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("hello from the ADAM host\n")
        host_path = f.name
    _show(
        await client.copy_to_guest(
            VM_NAME,
            guest_username=GUEST_USERNAME,
            guest_password=GUEST_PASSWORD,
            host_source_path=host_path,
            guest_target_path=GUEST_TARGET_PATH,
            timeout=30.0,
        )
    )
    Path(host_path).unlink(missing_ok=True)

    _banner("4b. confirm the copied file landed, by reading it back")
    _show(
        await client.run_in_guest(
            VM_NAME,
            guest_username=GUEST_USERNAME,
            guest_password=GUEST_PASSWORD,
            executable_path="cmd.exe",
            arguments=["/c", "type", GUEST_TARGET_PATH],
            timeout=15.0,
        )
    )

    _banner("6. EDGE CASE: incorrect credentials")
    _show(
        await client.run_in_guest(
            VM_NAME,
            guest_username=GUEST_USERNAME,
            guest_password="definitely-wrong-password",
            executable_path="cmd.exe",
            arguments=["/c", "echo should not run"],
            timeout=15.0,
        )
    )  # expect success=False, an authentication/logon failure in stderr

    _banner("7. EDGE CASE: execution timeout")
    # cmd.exe has no built-in sleep; Windows' own `timeout` command refuses to
    # run non-interactively under guestcontrol ("Input redirection is not
    # supported"), so `ping` is the standard stand-in for a long-running,
    # non-interactive command: -n 31 takes ~30 seconds.
    result = await client.run_in_guest(
        VM_NAME,
        guest_username=GUEST_USERNAME,
        guest_password=GUEST_PASSWORD,
        executable_path="cmd.exe",
        arguments=["/c", "ping", "-n", "31", "127.0.0.1"],
        timeout=5.0,
    )
    _show(result)  # expect success=False, "timed out after 5.0s" at ~5s, not ~30s


if __name__ == "__main__":
    asyncio.run(main())
