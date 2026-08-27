"""
adam/cli/main.py

Top-level Typer app -- `adam <command>`. Currently registers only `run`
(Phase 8). `replay` (adam/cli/replay.py) is Dev B's file per
ARCHITECTURE.md section 10.1 and is not registered here; it is expected to
add its own command to this app in its own PR once it exists.

Invocation, until real packaging exists (pyproject.toml is tracked
technical debt in docs/implementation-audit.md):

    python -m adam.cli.main run <sample_path>

not yet an installed `adam` console script.
"""

from __future__ import annotations

import typer

from adam.cli.run import run as run_command
from adam.cli.replay import replay_main as replay_command
from adam.cli.benchmark import benchmark_app

app = typer.Typer(help="ADAM -- Adaptive Deception Sandbox for Advanced Malware Analysis.")
app.command(name="run")(run_command)
app.command(name="replay")(replay_command)
app.add_typer(benchmark_app, name="benchmark")


@app.callback()
def _main_callback() -> None:
    """
    No-op top-level callback. Typer/Click collapses a Typer app into a
    single bare command (dropping the `run` subcommand name entirely) when
    it has exactly one registered command and no registered callback --
    registering this callback is what keeps `adam run <sample_path>` a
    real, explicit subcommand instead of silently becoming just
    `adam <sample_path>`, which matters once `adam replay` (Dev B's
    adam/cli/replay.py, ARCHITECTURE.md section 10.1) is added alongside it.
    """


if __name__ == "__main__":
    app()
