"""
scripts/manual_tests/logging_utils.py

Shared logging setup for the standalone VirtualBox diagnostic scripts
under scripts/manual_tests/. Every script here logs full detail (every
attempt, every transition) via `logging` to both stderr and a
timestamped file under logs/manual_tests/, and prints only a short,
final human-readable summary via plain print() once it's done -- never
the other way around.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

# scripts/manual_tests/logging_utils.py -> parents[0]=manual_tests,
# parents[1]=scripts, parents[2]=project root.
LOGS_DIR = Path(__file__).resolve().parents[2] / "logs" / "manual_tests"


def timestamp_tag() -> str:
    """UTC timestamp suitable for use in a filename, e.g. 20260726T142233Z."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def setup_logging(script_name: str, *, log_file_name: str | None = None) -> tuple[logging.Logger, Path]:
    """
    Configure a logger named `script_name` that writes DEBUG-and-up to a
    timestamped file under logs/manual_tests/, and INFO-and-up to
    stderr so a human watching the terminal sees transitions/summaries
    without being flooded by every single poll attempt.

    Returns (logger, log_file_path) so the caller can mention the log
    file's location in its final summary.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    file_name = log_file_name or f"{script_name}_{timestamp_tag()}.log"
    log_path = LOGS_DIR / file_name

    logger = logging.getLogger(script_name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Guard against duplicate handlers if setup_logging() is somehow
    # called more than once for the same logger name in one process.
    if not logger.handlers:
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
            datefmt="%H:%M:%S",
        )

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setLevel(logging.INFO)
        stream_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

    return logger, log_path
