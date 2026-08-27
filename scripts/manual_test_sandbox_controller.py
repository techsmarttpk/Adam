"""
scripts/manual_test_sandbox_controller.py

Manual smoke test for SandboxController, the FSM wrapping VirtualBoxClient
(ARCHITECTURE.md section 5.2).

As of Milestone 4, vm_name / snapshot_name / timeouts / guest credentials
come from adam.common.config.get_settings() instead of hardcoded module
constants -- see config/default.toml and .env.example.

As of the ISandboxController reconciliation (docs/remaining-work-plan.md,
Immediate #2), detonate() takes a SampleRef and returns None instead of a
(guest_target_path, arguments, timeout) -> VMOperationResult shape -- it now
runs exactly the file arm() copied to the guest, with no separate command.
That means the "sample" arm() delivers must itself be a real, directly
runnable Windows executable, not an arbitrary payload invoked by a separate
cmd.exe call the way the pre-Phase-2 version of this script did. See
_locate_smoke_sample() below. The VMOperationResult that used to be
detonate()'s return value is now read from controller.last_detonation_result
immediately afterwards.

Not an automated test -- no assertions that fail the process. Prints
controller.state and each VMOperationResult so a human can confirm the
transitions actually happen in order against the real VM, and that the
edge cases behave as designed:

  - illegal transition (detonate before prepare)
  - detonate twice without re-arming
  - prepare() failure (bad snapshot name) -> FAILED, then teardown from FAILED
  - a "sample" that crashes on exit -> state must be COMPLETED, not FAILED
  - idempotent teardown
  - teardown with no prior prepare()

Usage:
    python -m scripts.manual_test_sandbox_controller
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import shutil
import sys

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from adam.common.config import get_settings
from adam.contracts.session import SampleRef
from adam.sandbox.controller import SandboxController
from adam.sandbox.state import SandboxOperationError, SandboxStateError
from adam.sandbox.vbox.client import VirtualBoxClient
from adam.sandbox.vbox.models import VMOperationResult

# Test-script detail only, not sandbox configuration -- stays local.
GUEST_TARGET_PATH = "C:\\ADAM\\adam_smoke_sample.exe"


def _banner(title: str) -> None:
    print(f"\n--- {title} ---")


def _show(result: VMOperationResult | None) -> None:
    if result is None:
        print("no detonation result recorded")
        return
    print(f"success={result.success} return_code={result.return_code} duration_ms={result.duration_ms:.1f}")
    if result.termination_reason:
        print(f"termination_reason: {result.termination_reason}")
    if result.stdout.strip():
        print(f"stdout: {result.stdout.strip()[:300]}")
    if result.stderr.strip():
        print(f"stderr: {result.stderr.strip()[:300]}")


def _locate_smoke_sample() -> str:
    """
    A real, directly-runnable executable to stand in for a 'sample'.
    Prioritizes a guest-compatible sample from samples/ (or tests/fixtures/)
    to avoid OS-build coupling issues when running on a guest with a different
    Windows version than the host.
    """
    candidates = [
        _PROJECT_ROOT / "samples" / "smoke_sample.exe",
        _PROJECT_ROOT / "samples" / "guest_whoami.exe",
        _PROJECT_ROOT / "tests" / "fixtures" / "smoke_sample.exe",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)

    path = shutil.which("whoami.exe") or shutil.which("whoami")
    if path is None:
        raise RuntimeError(
            "whoami.exe not found on PATH and no sample in samples/."
        )
    return path


def _sample_ref(host_path: str) -> SampleRef:
    """Builds a real SampleRef (genuine sha256/md5/size) from a host file."""
    data = Path(host_path).read_bytes()
    return SampleRef(
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        filename=Path(host_path).name,
        size_bytes=len(data),
        file_type="PE32 executable",
    )


from adam.sandbox.guest.http_channel import HTTPGuestChannel


def _new_controller(snapshot_name: str | None = None) -> SandboxController:
    settings = get_settings()
    sandbox_settings = settings.sandbox
    client = VirtualBoxClient()
    channel = None
    if settings.guest_backend == "http":
        channel = HTTPGuestChannel(
            base_url=settings.http_guest.base_url,
            capture_dir=settings.http_guest.capture_dir,
            procmon_path=settings.http_guest.procmon_path,
            tshark_path=settings.http_guest.tshark_path,
            sysmon_log=settings.http_guest.sysmon_log,
            tshark_interface=settings.http_guest.tshark_interface,
            auth_token=getattr(settings.http_guest, "auth_token", "Adam_Sandbox_SecOps_2026!"),
            guest_ready_timeout_s=sandbox_settings.guest_ready_timeout_s,
        )
    return SandboxController(
        client,
        sandbox_settings.vm_name,
        snapshot_name=snapshot_name if snapshot_name is not None else sandbox_settings.snapshot_name,
        guest_username=sandbox_settings.guest_username,
        guest_password=sandbox_settings.guest_password,
        boot_timeout=sandbox_settings.boot_timeout_s,
        guest_ready_timeout=sandbox_settings.guest_ready_timeout_s,
        guest_channel=channel,
    )


async def main() -> None:
    host_sample_path = _locate_smoke_sample()
    sample = _sample_ref(host_sample_path)
    print(f"using host sample: {host_sample_path} (sha256={sample.sha256[:12]}...)")

    # ---- 1. happy path ----
    _banner("1. happy path: prepare -> arm -> detonate -> teardown")
    ctrl = _new_controller()
    print(f"initial state: {ctrl.state}")

    await ctrl.prepare()
    print(f"after prepare(): {ctrl.state}")

    await ctrl.arm(host_sample_path, GUEST_TARGET_PATH)
    print(f"after arm(): {ctrl.state}")

    await ctrl.detonate(sample)
    print(f"after detonate(): {ctrl.state}")
    _show(ctrl.last_detonation_result)

    await ctrl.teardown()
    print(f"after teardown(): {ctrl.state}")

    # ---- 2. illegal transition ----
    _banner("2. EDGE CASE: detonate() before prepare()")
    ctrl2 = _new_controller()
    try:
        await ctrl2.detonate(sample)
        print("did NOT raise -- investigate")
    except SandboxStateError as e:
        print(f"raised as expected: {e}")

    # ---- 3. double detonate without re-arm ----
    _banner("3. EDGE CASE: detonate() twice without re-arming")
    ctrl3 = _new_controller()
    await ctrl3.prepare()
    await ctrl3.arm(host_sample_path, GUEST_TARGET_PATH)
    await ctrl3.detonate(sample)
    print(f"first detonate: state={ctrl3.state}")
    _show(ctrl3.last_detonation_result)
    try:
        await ctrl3.detonate(sample)
        print("did NOT raise -- investigate")
    except SandboxStateError as e:
        print(f"raised as expected: {e}")
    await ctrl3.teardown()

    # ---- 4. prepare() failure -> FAILED, then teardown from FAILED ----
    _banner("4. EDGE CASE: prepare() with a bad snapshot name")
    ctrl4 = _new_controller(snapshot_name="definitely-not-a-real-snapshot")
    try:
        await ctrl4.prepare()
        print("did NOT raise -- investigate")
    except SandboxOperationError as e:
        print(f"raised as expected, state={ctrl4.state}: {e}")
    await ctrl4.teardown()
    print(f"teardown() from FAILED -> state={ctrl4.state}")

    # ---- 5. detonate() reaches COMPLETED regardless of the sample's own exit behavior ----
    _banner("5. EDGE CASE: detonate() state is COMPLETED, not FAILED, even if the sample's own exit looks crash-like")
    ctrl5 = _new_controller()
    await ctrl5.prepare()
    await ctrl5.arm(host_sample_path, GUEST_TARGET_PATH)
    await ctrl5.detonate(sample)
    print(f"after detonate(): state={ctrl5.state} (must be COMPLETED, not FAILED)")
    _show(ctrl5.last_detonation_result)
    await ctrl5.teardown()

    # ---- 6. idempotent teardown ----
    _banner("6. idempotent teardown (call twice)")
    ctrl6 = _new_controller()
    await ctrl6.teardown()
    print(f"first teardown(): {ctrl6.state}")
    await ctrl6.teardown()
    print(f"second teardown(): {ctrl6.state}")

    # ---- 7. teardown with no prior prepare ----
    _banner("7. teardown() with no prior prepare()")
    ctrl7 = _new_controller()
    print(f"initial state: {ctrl7.state}")
    await ctrl7.teardown()
    print(f"after teardown(): {ctrl7.state}")


if __name__ == "__main__":
    asyncio.run(main())
