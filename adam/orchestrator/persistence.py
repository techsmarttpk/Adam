"""
adam/orchestrator/persistence.py

RawEventWriter -- appends RawEvent records to artifacts/<session_id>/raw.jsonl.
ARCHITECTURE.md ADR-005 ("Raw events to JSONL, not SQLite"): raw.jsonl is the
authoritative, durable record of a session's telemetry, independent of
EventBus's lossy, drop-under-backpressure delivery to live subscribers
(section 8.2/8.3). SessionOrchestrator writes directly to this from its
per-collector pump loop -- not via a bus subscription -- specifically so a
slow or overflowing bus subscriber can never cause an event to go
unrecorded here. See adam/orchestrator/session.py's module docstring for
where this fits in the session lifecycle.

Blocking file I/O is offloaded to a thread via asyncio.to_thread(), the
same pattern scripts/manual_tests/boot_readiness_trace.py established for
running blocking work without blocking the event loop.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TextIO

from pydantic import BaseModel

from adam.contracts.raw_event import RawEvent


class RawEventWriter:
    """
    One instance per session. Call open() before write(); close() is
    idempotent and safe to call even if open() was never called or itself
    failed, matching this project's teardown()-is-always-safe convention
    (ARCHITECTURE.md section 14.4).
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._file: TextIO | None = None
        self._count = 0

    @property
    def path(self) -> Path:
        return self._path

    @property
    def count(self) -> int:
        """Number of RawEvents successfully written so far."""
        return self._count

    async def open(self) -> None:
        """Creates the parent directory (artifacts/<session_id>/) if needed and opens the file for append."""
        await asyncio.to_thread(self._open_sync)

    def _open_sync(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self._path, "a", encoding="utf-8")

    async def write(self, event: RawEvent) -> None:
        """Appends one RawEvent as a single JSONL line and flushes immediately (durability over throughput at this scale)."""
        if self._file is None:
            raise RuntimeError("RawEventWriter.write() called before open()")
        await asyncio.to_thread(self._write_sync, event)

    def _write_sync(self, event: RawEvent) -> None:
        assert self._file is not None
        self._file.write(event.model_dump_json())
        self._file.write("\n")
        self._file.flush()
        self._count += 1

    async def close(self) -> None:
        await asyncio.to_thread(self._close_sync)

    def _close_sync(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None


class JsonlWriter:
    """
    Generic, one-shot JSONL writer for any Pydantic model -- used for the
    Fusion/Policy/Deception pipeline's `semantic_events.jsonl`/
    `decisions.jsonl`/`mutations.jsonl` artifacts (adam/orchestrator/
    pipeline.py). Deliberately separate from `RawEventWriter` above rather
    than a generalisation of it: `RawEventWriter` is durability-critical,
    append-as-you-go, per-event-flushed (ADR-005) infrastructure that
    existing callers/tests depend on byte-for-byte; this class is a small,
    additive convenience for writing an already-complete, in-memory list
    once batch pipeline processing finishes, and changes nothing about the
    existing class's behavior or callers.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    async def write_all(self, records: list[BaseModel]) -> None:
        """Creates the parent directory if needed and writes every record as one JSONL line, overwriting any prior file."""
        await asyncio.to_thread(self._write_all_sync, records)

    def _write_all_sync(self, records: list[BaseModel]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(record.model_dump_json())
                handle.write("\n")
