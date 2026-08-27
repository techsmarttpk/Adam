"""
scripts/reliability_check.py

N-run reliability harness for the SandboxController happy-path scenario:
    prepare() -> arm() -> detonate() -> teardown()

Each run records: pass/fail, return_code, termination_reason, and duration.
At the end a summary table is printed and any inconsistency in return_code or
termination_reason across runs is flagged -- that inconsistency is itself the
signal worth catching (per the crash-code investigation).

Usage:
    python -m scripts.reliability_check             # default N=5
    python -m scripts.reliability_check --runs 10   # custom N
    python scripts/reliability_check.py --runs 3

The script imports the same helpers (_new_controller, _locate_smoke_sample,
_sample_ref) that manual_test_sandbox_controller.py uses so the two stay in
lock-step on configuration. It only exercises the happy path -- edge-case
scenarios are not repeated here because each one consumes a full VM snapshot
restore cycle.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from adam.common.config import get_settings
from adam.contracts.session import SampleRef
from adam.sandbox.controller import SandboxController
from adam.sandbox.guest.http_channel import HTTPGuestChannel
from adam.sandbox.vbox.client import VirtualBoxClient
from adam.sandbox.vbox.models import VMOperationResult

import shutil


# ---------------------------------------------------------------------------
# Shared helpers (mirrors manual_test_sandbox_controller.py)
# ---------------------------------------------------------------------------

GUEST_TARGET_PATH = "C:\\ADAM\\adam_smoke_sample.exe"


def _locate_smoke_sample() -> str:
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
    data = Path(host_path).read_bytes()
    return SampleRef(
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        filename=Path(host_path).name,
        size_bytes=len(data),
        file_type="PE32 executable",
    )


def _new_controller() -> SandboxController:
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
            auth_token=getattr(
                settings.http_guest, "auth_token", "Adam_Sandbox_SecOps_2026!"
            ),
            guest_ready_timeout_s=sandbox_settings.guest_ready_timeout_s,
        )
    return SandboxController(
        client,
        sandbox_settings.vm_name,
        snapshot_name=sandbox_settings.snapshot_name,
        guest_username=sandbox_settings.guest_username,
        guest_password=sandbox_settings.guest_password,
        boot_timeout=sandbox_settings.boot_timeout_s,
        guest_ready_timeout=sandbox_settings.guest_ready_timeout_s,
        guest_channel=channel,
    )


# ---------------------------------------------------------------------------
# Per-run result record
# ---------------------------------------------------------------------------

@dataclass
class RunResult:
    run_number: int
    passed: bool           # True iff no exception AND return_code == 0 AND success == True
    return_code: Optional[int]   # None if detonation result unavailable / exception
    success_flag: Optional[bool] # VMOperationResult.success; None on exception
    termination_reason: Optional[str]
    retries: int
    duration_s: float
    error: Optional[str]   # exception message if the run itself threw


# ---------------------------------------------------------------------------
# Single happy-path run
# ---------------------------------------------------------------------------

async def _run_happy_path(
    host_sample_path: str,
    sample: SampleRef,
    run_number: int,
    verbose: bool,
) -> RunResult:
    t0 = time.perf_counter()
    ctrl = _new_controller()
    error: Optional[str] = None
    result: Optional[VMOperationResult] = None
    retries = 0

    try:
        await ctrl.prepare()
        if verbose:
            print(f"  [run {run_number}] after prepare(): {ctrl.state}")

        await ctrl.arm(host_sample_path, GUEST_TARGET_PATH)
        if verbose:
            print(f"  [run {run_number}] after arm(): {ctrl.state}")

        await ctrl.detonate(sample)
        if verbose:
            print(f"  [run {run_number}] after detonate(): {ctrl.state}")
        result = ctrl.last_detonation_result

    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        if verbose:
            print(f"  [run {run_number}] EXCEPTION during run: {error}")
    finally:
        if ctrl.guest_channel and hasattr(ctrl.guest_channel, "retry_count"):
            retries = ctrl.guest_channel.retry_count
        try:
            await ctrl.teardown()
            if verbose:
                print(f"  [run {run_number}] after teardown(): {ctrl.state}")
        except Exception as teardown_exc:
            if verbose:
                print(f"  [run {run_number}] teardown() raised: {teardown_exc}")

    duration_s = time.perf_counter() - t0

    if error is not None:
        return RunResult(
            run_number=run_number,
            passed=False,
            return_code=None,
            success_flag=None,
            termination_reason=None,
            retries=retries,
            duration_s=duration_s,
            error=error,
        )

    rc = result.return_code if result is not None else None
    sf = result.success if result is not None else None
    tr = result.termination_reason if result is not None else None
    passed = (error is None) and (rc == 0) and (sf is True)

    return RunResult(
        run_number=run_number,
        passed=passed,
        return_code=rc,
        success_flag=sf,
        termination_reason=tr,
        retries=retries,
        duration_s=duration_s,
        error=None,
    )


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------

async def _main(n_runs: int, verbose: bool) -> int:
    host_sample_path = _locate_smoke_sample()
    sample = _sample_ref(host_sample_path)
    print(
        f"reliability_check.py — N={n_runs} runs\n"
        f"sample : {host_sample_path} (sha256={sample.sha256[:12]}...)\n"
        f"{'=' * 70}"
    )

    results: list[RunResult] = []
    for i in range(1, n_runs + 1):
        print(f"\n[RUN {i}/{n_runs}] starting...")
        r = await _run_happy_path(host_sample_path, sample, i, verbose=verbose)
        status = "PASS" if r.passed else "FAIL"
        print(
            f"[RUN {i}/{n_runs}] {status}  "
            f"rc={r.return_code}  "
            f"success={r.success_flag}  "
            f"term={r.termination_reason!r}  "
            f"retries={r.retries}  "
            f"duration={r.duration_s:.1f}s"
            + (f"  error={r.error}" if r.error else "")
        )
        results.append(r)

    # ---- Summary table ----
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")
    print(
        f"{'Run':<5} {'Status':<7} {'RC':<6} {'Success':<9} "
        f"{'Retries':<8} {'TermReason':<30} {'Duration':>10}"
    )
    print(f"{'-' * 80}")
    for r in results:
        rc_str    = str(r.return_code) if r.return_code is not None else "N/A"
        sf_str    = str(r.success_flag) if r.success_flag is not None else "N/A"
        tr_str    = str(r.termination_reason) if r.termination_reason else "None"
        status    = "PASS" if r.passed else "FAIL"
        dur_str   = f"{r.duration_s:.1f}s"
        print(
            f"{r.run_number:<5} {status:<7} {rc_str:<6} {sf_str:<9} "
            f"{r.retries:<8} {tr_str:<30} {dur_str:>10}"
        )
    print(f"{'-' * 80}")

    passed_count = sum(1 for r in results if r.passed)
    rc_values    = set(r.return_code for r in results)
    tr_values    = set(r.termination_reason for r in results)

    print(f"\nTotal  : {n_runs}")
    print(f"Passed : {passed_count}/{n_runs}  (return_code==0 AND success==True)")
    print(f"Failed : {n_runs - passed_count}/{n_runs}")

    # ---- Inconsistency detection ----
    inconsistent = False
    if len(rc_values) > 1:
        inconsistent = True
        print(
            f"\n  INCONSISTENCY DETECTED -- return_code varied across runs: "
            f"{sorted(str(v) for v in rc_values)}"
        )
    if len(tr_values) > 1:
        inconsistent = True
        print(
            f"\n  INCONSISTENCY DETECTED -- termination_reason varied across runs: "
            f"{sorted(str(v) for v in tr_values)}"
        )
    if not inconsistent:
        print(
            f"\n  Consistent: all runs returned rc={next(iter(rc_values))!r}, "
            f"termination_reason={next(iter(tr_values))!r}"
        )

    print(f"{'=' * 80}")

    # Exit 0 only if every run passed AND results were consistent
    return 0 if (passed_count == n_runs and not inconsistent) else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the SandboxController happy-path scenario N times and "
            "report pass/fail consistency."
        )
    )
    parser.add_argument(
        "--runs",
        "-n",
        type=int,
        default=5,
        metavar="N",
        help="Number of full happy-path cycles to run (default: 5)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print per-run state transitions in addition to the summary",
    )
    args = parser.parse_args()

    if args.runs < 1:
        print("ERROR: --runs must be >= 1", file=sys.stderr)
        sys.exit(2)

    exit_code = asyncio.run(_main(args.runs, args.verbose))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
