"""
scripts/manual_test_vbox_client.py

Manual smoke test for adam.sandbox.vbox.client.VirtualBoxClient.

Run this directly against a real VirtualBox installation and the
ADAM_WIN10_OFFICE VM. It is not an automated test -- there is no pytest,
no assertions that fail the process. It prints what happened at each step
so a human can read VirtualBox's actual reported behaviour, including the
edge cases we specifically want documented now rather than discovered
during Milestone 2 integration:

  - start() when the VM is already running
  - stop() when the VM is already powered off
  - restoring a snapshot that does not exist
  - listing snapshots for a VM name that does not exist
  - an invalid VBoxManage path

Assumes a "clean" snapshot already exists for ADAM_WIN10_OFFICE and that
the VM starts this script powered off (a warning is printed, not enforced,
if it doesn't).

Usage:
    python scripts/manual_test_vbox_client.py
"""

from __future__ import annotations

import asyncio

from adam.common.config import get_settings
from adam.sandbox.vbox.client import VBoxCommandError, VirtualBoxClient
from adam.sandbox.vbox.models import VMOperationResult


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
    # Milestone 4: vm_name / snapshot_name come from Configuration now
    # (config/default.toml), not hardcoded module constants.
    sandbox_settings = get_settings().sandbox
    VM_NAME = sandbox_settings.vm_name
    SNAPSHOT_NAME = sandbox_settings.snapshot_name

    client = VirtualBoxClient()

    _banner("get_version()")
    print(await client.get_version())

    _banner("vm_exists() - real VM")
    print(await client.vm_exists(VM_NAME))

    _banner("vm_exists() - nonexistent VM")
    print(await client.vm_exists("NOT_A_REAL_VM"))

    _banner("get_state() before start")
    state = await client.get_state(VM_NAME)
    print(state)
    if state != "poweroff":
        print(f"WARNING: VM is not powered off (state={state}). Later steps assume it starts poweroff.")

    _banner("list_snapshots()")
    for snapshot in await client.list_snapshots(VM_NAME):
        print(snapshot)

    _banner("snapshot_exists('clean')")
    print(await client.snapshot_exists(VM_NAME, SNAPSHOT_NAME))

    _banner("start()")
    _show(await client.start(VM_NAME, headless=True))

    _banner("EDGE CASE: start() again while already running")
    _show(await client.start(VM_NAME, headless=True))  # expect success=False

    _banner("wait_for_state('running', timeout=30)")
    _show(await client.wait_for_state(VM_NAME, "running", timeout=30.0))

    _banner("EDGE CASE: restore_snapshot() while VM is running")
    _show(await client.restore_snapshot(VM_NAME, SNAPSHOT_NAME))  # expect success=False

    _banner("stop(mode='acpi')")
    _show(await client.stop(VM_NAME, mode="acpi"))

    _banner("wait_for_state('poweroff', timeout=30) after ACPI")
    acpi_result = await client.wait_for_state(VM_NAME, "poweroff", timeout=30.0)
    _show(acpi_result)

    if not acpi_result.success:
        _banner("ACPI shutdown did not land in time -- falling back to poweroff")
        _show(await client.stop(VM_NAME, mode="poweroff"))
        _show(await client.wait_for_state(VM_NAME, "poweroff", timeout=15.0))

    _banner("EDGE CASE: stop() again while already powered off")
    _show(await client.stop(VM_NAME, mode="poweroff"))  # expect success=False

    _banner("EDGE CASE: restore_snapshot() with a snapshot that does not exist")
    _show(await client.restore_snapshot(VM_NAME, "definitely-not-a-real-snapshot"))  # expect success=False

    _banner("restore_snapshot('clean') -- real restore, VM now powered off")
    _show(await client.restore_snapshot(VM_NAME, SNAPSHOT_NAME))

    _banner("get_state() after restore")
    print(await client.get_state(VM_NAME))

    _banner("EDGE CASE: list_snapshots() on an invalid VM name")
    try:
        await client.list_snapshots("NOT_A_REAL_VM")
        print("did NOT raise -- investigate, this was expected to fail")
    except VBoxCommandError as exc:
        print(f"raised as expected: {exc}")

    _banner("EDGE CASE: invalid VBoxManage path")
    bad_client = VirtualBoxClient(vboxmanage_path="/definitely/not/a/real/vboxmanage")
    try:
        await bad_client.get_version()
        print("did NOT raise -- investigate, this was expected to fail")
    except VBoxCommandError as exc:
        print(f"raised as expected: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
