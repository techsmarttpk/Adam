"""
scripts/manual_tests/vbox_cli.py

Reusable VBoxManage subprocess wrapper for the standalone diagnostic
scripts under scripts/manual_tests/.

Scope note (read before touching anything else in this folder): this
module is intentionally independent of adam.sandbox.vbox.client.
VirtualBoxClient. It exists ONLY to support ad hoc, throwaway
infrastructure investigation (Guest Additions / GuestControl readiness,
boot timing, service state) and must never be imported by, or depend
on, production code -- SandboxController, VirtualBoxClient, or
wait_for_guest_ready() in particular. Keeping it separate means these
debugging tools can be hacked on freely with zero risk of affecting the
real sandbox implementation.

Every script in this folder must build its VBoxManage commands through
run_vboxmanage() below rather than calling subprocess directly, so
there is exactly one place that knows how to invoke VBoxManage and
time/capture the result.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VBoxCommandResult:
    """
    Result of a single VBoxManage invocation.

    command       -- the full command line that was executed, joined
                      with spaces, for logging/reproduction.
    return_code   -- process exit code. -1 is used (by convention in
                      this module) to mean "timed out and was killed",
                      since VBoxManage itself never returns -1.
    stdout/stderr -- captured text output (decoded, not bytes).
    duration_ms   -- wall-clock time for the call, in milliseconds.
    """

    command: str
    return_code: int
    stdout: str
    stderr: str
    duration_ms: float


def run_vboxmanage(args: list[str], *, timeout: float | None = None) -> VBoxCommandResult:
    """
    Run `VBoxManage <args>` via subprocess.run() and return a
    VBoxCommandResult describing what happened.

    This is deliberately synchronous (subprocess.run, not asyncio) --
    every diagnostic script either calls it from a plain blocking loop,
    or (in boot_readiness_trace.py) from its own thread via
    asyncio.to_thread(), so the blocking call never stalls anyone else's
    event loop.

    Does NOT raise on a non-zero VBoxManage exit code -- that is
    exactly the condition these scripts exist to observe and log. If
    the call exceeds `timeout` seconds, the child process is killed and
    a VBoxCommandResult with return_code=-1 is returned instead of
    letting subprocess.TimeoutExpired propagate, so callers can treat
    "timed out" as just another outcome to log rather than an
    exception they need to handle specially.

    Only a failure to launch VBoxManage itself (e.g. it isn't on PATH)
    propagates as FileNotFoundError.
    """
    full_command = ["VBoxManage", *args]
    command_str = " ".join(full_command)

    start = time.monotonic()
    try:
        completed = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = (time.monotonic() - start) * 1000.0
        leftover_stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace")
        leftover_stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace")
        return VBoxCommandResult(
            command=command_str,
            return_code=-1,
            stdout=leftover_stdout,
            stderr=f"TIMED OUT after {timeout}s and was killed. {leftover_stderr}".strip(),
            duration_ms=duration_ms,
        )

    duration_ms = (time.monotonic() - start) * 1000.0
    return VBoxCommandResult(
        command=command_str,
        return_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_ms=duration_ms,
    )
