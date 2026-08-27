"""
scripts/test_run_async_bridge.py

Executes execute_live_session() strictly routed through frontend.app.run_async()
to verify that Streamlit's async bridge does not introduce any delays, lockups,
or regressions to the mutation pipeline.
"""
import sys
import os
import logging
from pathlib import Path

# Add workspace root
sys.path.insert(0, os.path.abspath("."))

from frontend.app import run_async, execute_live_session
from scripts.reliability_check import _locate_smoke_sample
from adam.api.deps import init_dependencies, deps, shutdown_dependencies

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

def main():
    sample_path = _locate_smoke_sample()
    print(f"[test_run_async_bridge] sample_path={sample_path}", flush=True)
    print(f"[test_run_async_bridge] invoking execute_live_session via run_async()...", flush=True)

    session_id, session = run_async(
        execute_live_session(
            sample_input=sample_path,
            profile_name="bare_control",
            deception_enabled=True,
            status_container=None,
        )
    )

    print(f"[test_run_async_bridge] COMPLETE: session_id={session_id} status={session.status} arm={session.arm}", flush=True)

    # Retrieve mutations applied
    async def get_metrics():
        await init_dependencies()
        try:
            mutations = await deps.mutation_repo.get_by_session(session_id)
            decisions = await deps.decision_repo.get_by_session(session_id)
            applied_count = len([m for m in mutations if (getattr(m.status, "value", str(m.status)) == "APPLIED" or getattr(m, "returncode", None) == 0)])
            return len(decisions), applied_count, mutations
        finally:
            await shutdown_dependencies()

    decisions_total, mutations_applied, mutations_list = run_async(get_metrics())

    print(
        f"engine metrics: decisions_total={decisions_total} "
        f"decisions_executed={len(mutations_list)} "
        f"mutations_applied={mutations_applied}",
        flush=True,
    )
    for m in mutations_list:
        print(f"  [Mutation] id={m.mutation_id} type={m.mutation_type} status={m.status} returncode={getattr(m, 'returncode', None)}", flush=True)

if __name__ == "__main__":
    main()
