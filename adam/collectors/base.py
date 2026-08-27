"""
adam/collectors/base.py

BaseCollector -- ARCHITECTURE.md section 5.3, docs/dev-a-environment-and-
roadmap.md Phase 7. Shared `ICollector` scaffolding every concrete collector
(SysmonCollector, ProcmonCollector, NetworkCollector, AgentCollector) is
built on: the start()/stop()/iter_events() lifecycle, an internal bounded
buffer, and the tail-loop bookkeeping every "watch a growing log source"
collector needs regardless of what it's tailing.

Design note -- collectors do not publish to the bus themselves. The
roadmap's Phase 7 spec is explicit: "each collector's iter_events() yields
RawEvents that get published onto the bus by a thin wrapper in the
orchestrator (Phase 8), not by the collector itself calling bus.publish()
directly, so collectors stay unit-testable without a live bus." BaseCollector
therefore has no EventBus dependency at all -- it is a pure async iterator
of RawEvent, fully testable in isolation (see the offline verification for
this file, which never imports adam.common.bus).

Must not (section 5.3): correlate across sources. A collector sees only its
own source; each concrete collector's normalise-into-RawEvent step is
strictly local to the record it just read. Cross-source correlation is
Fusion's job (section 5.4), not this package's.

Concrete collectors extend BaseCollector by implementing `_run()`: a
coroutine that reads from the real source (a file tail, a pipe, an EVTX
poll loop, whatever) and calls `self._emit(event)` for each `RawEvent` it
produces. BaseCollector handles the start()/stop() task lifecycle,
`_emit()`'s bounded-queue backpressure (drop-oldest, not block -- consistent
with the bus's own "drop rather than block" philosophy, ARCHITECTURE.md
section 8.3, applied here at the collector's own internal buffer), and
`iter_events()`'s draining loop.
"""

from __future__ import annotations

import abc
import asyncio
import logging
from collections.abc import AsyncIterator

from adam.contracts.raw_event import RawEvent

logger = logging.getLogger(__name__)


class BaseCollector(abc.ABC):
    """
    Shared `ICollector` (adam.contracts.interfaces.ICollector) scaffolding.
    Concrete subclasses implement `_run()` and `source_name`; everything
    else (task lifecycle, buffering, draining) is handled here.
    """

    def __init__(self, *, buffer_size: int = 1000) -> None:
        self._buffer: asyncio.Queue[RawEvent] = asyncio.Queue(maxsize=buffer_size)
        self._task: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()
        self.dropped = 0
        self.emitted = 0

    @property
    @abc.abstractmethod
    def source_name(self) -> str:
        """Short identifier for logging, e.g. 'sysmon', 'procmon', 'network'."""
        ...

    @abc.abstractmethod
    async def _run(self) -> None:
        """
        Subclass hook: reads from the real source until stop() is
        requested, calling self._emit(event) for each RawEvent produced.
        Must return (not raise) when self._stop_requested() is True --
        BaseCollector does not forcibly cancel this coroutine on stop();
        see stop()'s docstring for why.
        """
        ...

    def _stop_requested(self) -> bool:
        """Subclasses' _run() loops should check this each iteration and exit cleanly when True."""
        return self._stopped.is_set()

    def _emit(self, event: RawEvent) -> None:
        """
        Called by a subclass's _run() for each RawEvent it produces.
        Non-blocking: a full buffer drops the OLDEST queued event to make
        room for this one, rather than dropping the new event or blocking
        the tail loop. This differs deliberately from EventBus's "drop the
        new message" policy (adam/common/bus.py) -- here, the newest
        telemetry is more valuable than a stale queued one for a
        real-time source a caller isn't draining fast enough, whereas the
        bus's per-subscriber queues have no such asymmetry between
        messages. Both are "drop rather than block" in spirit (section
        8.3); the direction of the drop is the one place they differ, and
        that difference is deliberate, not an inconsistency.
        """
        while True:
            try:
                self._buffer.put_nowait(event)
                self.emitted += 1
                return
            except asyncio.QueueFull:
                try:
                    self._buffer.get_nowait()
                    self.dropped += 1
                    logger.warning(
                        "collector=%s buffer full, dropped oldest event (total_dropped=%d)",
                        self.source_name,
                        self.dropped,
                    )
                except asyncio.QueueEmpty:
                    # Raced with iter_events() draining the last item --
                    # buffer has room again, loop back to put_nowait().
                    continue

    def ingest(self, event: RawEvent) -> None:
        """
        Public method to ingest a live RawEvent directly into this collector's
        event queue, allowing live HTTP agent telemetry streams to share the same
        processing pipeline as file-tailing collectors.
        """
        self._emit(event)

    def ingest_batch(self, events: list[RawEvent]) -> None:
        """Ingest a batch of live RawEvents."""
        for event in events:
            self._emit(event)

    async def start(self) -> None:
        """
        ICollector.start(). Idempotent: calling start() while already
        running is a no-op rather than spawning a second _run() task.
        """
        if self._task is not None and not self._task.done():
            return
        self._stopped.clear()
        self._task = asyncio.create_task(self._run_guarded(), name=f"adam.collector.{self.source_name}")

    async def _run_guarded(self) -> None:
        """
        Wraps _run() so a subclass's tail-loop exception is logged rather
        than left as an unretrieved exception on the task (which asyncio
        would otherwise only surface as a warning at garbage-collection
        time, easy to miss). Matches this project's established handler-
        isolation philosophy (ARCHITECTURE.md section 14.3): one source
        dying must not silently vanish.
        """
        try:
            await self._run()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("collector=%s _run() raised -- collector stopped", self.source_name)
        finally:
            # _run() can finish on its own (e.g. a finite source that reads
            # to EOF) without stop() ever being called explicitly.
            # iter_events() needs a single, reliable "no more events are
            # coming" signal regardless of which way this happened, so it
            # is set here unconditionally, not only in stop().
            self._stopped.set()

    async def stop(self) -> None:
        """
        ICollector.stop(). Signals _run() to exit via self._stopped (so a
        well-behaved subclass gets a chance to close file handles / flush
        state cleanly) and then awaits the task with a bounded grace
        period; only cancels if the subclass doesn't exit on its own in
        time. Idempotent and safe to call from a `finally` block, matching
        this project's established teardown() convention
        (ARCHITECTURE.md section 14.4).
        """
        self._stopped.set()
        if self._task is None:
            return
        try:
            await asyncio.wait_for(asyncio.shield(self._task), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning(
                "collector=%s did not exit within 5s of stop(), cancelling", self.source_name
            )
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        except asyncio.CancelledError:
            pass
        finally:
            self._task = None

    async def iter_events(self) -> AsyncIterator[RawEvent]:
        """
        ICollector.iter_events(). Yields buffered RawEvents as they arrive.
        Exits when the collector is stopped AND the buffer has been fully
        drained -- a caller draining this after stop() still sees every
        event that was emitted before the stop, none are silently lost by
        exiting early.
        """
        while True:
            if self._stopped.is_set() and self._buffer.empty():
                return
            try:
                event = await asyncio.wait_for(self._buffer.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue
            yield event
