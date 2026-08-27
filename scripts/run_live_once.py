"""
scripts/run_live_once.py

One-shot live session runner identical to what execute_live_session() in
frontend/app.py calls.  Used to verify the 60s timeout fix resolves the
dashboard TIMEOUT failures without needing the browser subagent.

Usage:
    python -m scripts.run_live_once
"""
from __future__ import annotations

import asyncio
import logging
import sys

async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    from adam.common.config import get_settings
    from adam.orchestrator.runner import Runner
    from scripts.reliability_check import _locate_smoke_sample

    settings = get_settings()
    sample_path = _locate_smoke_sample()
    print(f"[run_live_once] sample={sample_path}", flush=True)

    runner = Runner(settings)
    session = await runner.run(sample_path, headless=True)

    print(f"[run_live_once] SESSION_ID={session.session_id}", flush=True)
    print(f"[run_live_once] STATUS={session.status}", flush=True)
    print(f"[run_live_once] ARM={session.arm}", flush=True)
    if runner._engine_handles:
        print(
            f"engine metrics: decisions_total={runner._engine_handles.decisions_total} "
            f"decisions_executed={runner._engine_handles.decisions_executed} "
            f"mutations_applied={runner._engine_handles.mutations_applied}",
            flush=True,
        )


if __name__ == "__main__":
    asyncio.run(main())
