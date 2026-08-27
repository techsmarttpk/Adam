"""
adam/cli/run.py

`adam run <sample_path>` -- ARCHITECTURE.md Phase 8. Thin Typer command
wrapping adam.orchestrator.runner.Runner.run() with CLI concerns: argument
parsing, Ctrl-C -> graceful cancellation, config-validation-failure -> a
clean error message and non-zero exit (not a raw traceback), and an exit
code reflecting the resulting AnalysisSession.status.

Exit codes:
  0   COMPLETED -- full success.
  1   PARTIAL   -- something failed mid-session; raw.jsonl has whatever
                   was captured before that point.
  2   FAILED    -- refused to start, or failed before any telemetry could
                   be captured. Also used for configuration-validation
                   failures caught before a session is even attempted
                   (ARCHITECTURE.md section 14.2's "refuse to start"), and
                   for a missing sample file.
  130 ABORTED   -- Ctrl-C / cancelled. 130 matches the POSIX convention for
                   "terminated by SIGINT" (128 + signal number 2) -- a
                   widely recognised convention beyond POSIX shells, used
                   here even though this project also targets Windows.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from collections.abc import Coroutine
from pathlib import Path
from typing import Any, Optional

import typer
from pydantic import ValidationError
from rich.console import Console

from adam.contracts.enums import SessionStatus
from adam.contracts.session import AnalysisSession
from adam.orchestrator.runner import Runner

console = Console()

_EXIT_CODES: dict[SessionStatus, int] = {
    SessionStatus.COMPLETED: 0,
    SessionStatus.PARTIAL: 1,
    SessionStatus.FAILED: 2,
    SessionStatus.ABORTED: 130,
}


def _run_with_graceful_cancellation(coro: "Coroutine[Any, Any, AnalysisSession]") -> AnalysisSession:
    """
    Runs `coro` to completion, installing a SIGINT handler that cancels the
    underlying task rather than letting Python's default KeyboardInterrupt
    propagate and potentially skip SessionOrchestrator's own cleanup.

    signal.signal() (not asyncio's loop.add_signal_handler()) is used
    specifically because add_signal_handler() is not implemented on
    Windows' event loop -- this project's actual host platform for the CLI
    process -- while signal.signal() works cross-platform, including
    Windows.

    SessionOrchestrator.run_session() (adam/orchestrator/session.py) is
    documented to catch its own CancelledError internally and return a
    normal AnalysisSession(status=ABORTED) rather than propagate it -- so
    `await task` below completes normally even after task.cancel(), and
    this function has no separate CancelledError handling of its own to do.

    Verified latency characteristic, disclosed: cancellation is guaranteed
    to eventually take effect and cleanup is guaranteed to run (proven via
    both a same-process self-signal test exercising this exact function
    and adam/orchestrator/session.py's own task.cancel() test), but it is
    NOT guaranteed to be near-instantaneous while a VBoxManage subprocess
    call is in flight. asyncio's task cancellation only interrupts a
    suspended `await` at that await's own next resumption point; a
    currently in-flight `asyncio.create_subprocess_exec()`/wait() call
    inside VirtualBoxClient does not appear to hand control back to the
    event loop until that specific subprocess call resolves. Measured in
    this project's own offline verification: cancelling mid-`prepare()`
    (which chains three sequential VBoxManage calls) took as long as all
    three remaining calls to actually resolve into ABORTED, rather than
    interrupting the first one immediately. The guarantee this project
    actually requires -- "the VM must still be restored" -- still holds
    either way, since teardown() runs unconditionally once run_session()
    unwinds; only the responsiveness of Ctrl-C during a slow/hung
    individual VBoxManage call is affected, not correctness. Improving that
    responsiveness would mean threading cancellation into
    VirtualBoxClient's own subprocess handling (Milestone 1/2 code, out of
    this phase's file scope) -- tracked as a follow-up, not fixed here.
    """

    async def _runner() -> AnalysisSession:
        task: "asyncio.Task[AnalysisSession]" = asyncio.ensure_future(coro)

        def _on_sigint(signum: int, frame: Any) -> None:
            task.cancel()

        try:
            previous_handler = signal.signal(signal.SIGINT, _on_sigint)
        except (ValueError, OSError):
            # Not the main thread, or signal handling unsupported in this
            # environment -- degrade to default Ctrl-C behavior rather
            # than crash; run() still proceeds without graceful-cancel
            # wiring in that case.
            previous_handler = None

        try:
            return await task
        finally:
            if previous_handler is not None:
                signal.signal(signal.SIGINT, previous_handler)

    return asyncio.run(_runner())


def run(
    sample_path: str = typer.Argument(..., help="Path to the sample to detonate."),
    sysmon_evtx_path: Optional[str] = typer.Option(  # noqa: UP007 -- typer needs Optional[X], not X | None, pre-3.10-style unions
        None,
        help=(
            "Testing-only override: a host-accessible Sysmon EVTX file to tail instead of "
            "GuestAgent's automatic capture/export for this source. Normal execution should "
            "not need this -- see adam/orchestrator/runner.py."
        ),
    ),
    procmon_csv_path: Optional[str] = typer.Option(
        None,
        help=(
            "Testing-only override: a host-accessible ProcMon CSV export (with a 'Date & Time' "
            "column) to tail instead of GuestAgent's automatic capture/export for this source. "
            "Normal execution should not need this."
        ),
    ),
    network_ek_json_path: Optional[str] = typer.Option(
        None,
        help=(
            "Testing-only override: a host-accessible 'tshark -T ek' export to tail instead of "
            "GuestAgent's automatic capture/export for this source. Normal execution should not "
            "need this."
        ),
    ),
    artifacts_dir: str = typer.Option("artifacts", help="Root directory for artifacts/<session_id>/raw.jsonl."),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help=(
            "Enable DEBUG-level logging, including GuestAgent's full per-command diagnostics "
            "(exact executable/arguments/command line/timeout/return code/stdout/stderr/duration "
            "for every guestcontrol call). Off by default -- see "
            "adam/sandbox/guest/agent/agent.py's module docstring, DIAGNOSTICS section."
        ),
    ),
    gui: bool = typer.Option(
        False,
        "--gui",
        help="Start the VirtualBox VM with a visible GUI window. Default is headless.",
    ),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        "-p",
        help="Hardware profile ID to apply to the sandbox (e.g. bare_control, developer_decoy, enterprise_office_decoy).",
    ),
) -> None:
    """Run one full, unattended analysis session against SAMPLE_PATH."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        # Silence third-party libraries that spam DEBUG regardless of root level.
        # Evtx.Evtx emits one DEBUG line per EVTX record (~1000 lines/session).
        # httpcore/httpx emit per-request/connection DEBUG lines.
        # These are only useful when debugging transport or parser issues;
        # --verbose restores them via the root DEBUG level set above.
        logging.getLogger("Evtx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        # [VERIFY] markers in wiring.py are temporary instrumentation that
        # emit one INFO line per raw/semantic/policy event (~1208 lines/session).
        # Promote to DEBUG so they're hidden at the default INFO level;
        # --verbose shows them. Remove this override once the live-run audit
        # is complete and the [VERIFY] markers are deleted from wiring.py.
        logging.getLogger("adam.pipeline.wiring").setLevel(logging.WARNING)

    if not Path(sample_path).is_file():
        console.print(f"[red]error:[/red] sample not found: {sample_path}")
        raise typer.Exit(code=2)

    runner = Runner()

    try:
        coro = runner.run(
            sample_path,
            vm_profile=profile,
            sysmon_evtx_path=sysmon_evtx_path,
            procmon_csv_path=procmon_csv_path,
            network_ek_json_path=network_ek_json_path,
            artifacts_dir=artifacts_dir,
            headless=not gui,
        )
        session = _run_with_graceful_cancellation(coro)
    except ValidationError as exc:
        # ARCHITECTURE.md section 14.2: "refuse to start" -- fail fast on
        # invalid/missing configuration with a specific, readable error,
        # not a buried stack trace.
        console.print("[red]error:[/red] invalid configuration -- refusing to start:")
        console.print(str(exc))
        raise typer.Exit(code=2) from None

    console.print(
        f"session {session.session_id}: [bold]{session.status.value}[/bold] "
        f"({session.metrics.raw_events} raw events captured)"
    )
    if session.error:
        console.print(f"  detail: {session.error}")
    console.print(f"  artifacts: {artifacts_dir}/{session.session_id}/raw.jsonl")

    raise typer.Exit(code=_EXIT_CODES[session.status])
