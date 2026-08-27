"""
adam/collectors/sysmon.py

SysmonCollector -- ARCHITECTURE.md section 5.3 / docs/dev-a-environment-
and-roadmap.md Phase 7. Tails a Sysmon Event Log (EVTX) file for new
records and turns each one into a RawEvent via
adam.collectors.parsers.evtx.parse_sysmon_event_xml().

Tailing strategy: EVTX is a binary, append-only, chunked file format --
there is no equivalent of a text log's "seek to last read byte offset and
read forward" for it, because a new record can span/complete a chunk in a
way that isn't a simple byte-append boundary. Instead, this collector
re-reads the file's full current record set on each poll and tracks the
highest `EventRecordID` (a real Sysmon field: a monotonically increasing,
per-log-channel record sequence number) already emitted, skipping anything
at or below it. This trades some re-parsing work per poll (bounded by the
file's current total record count, not by how much is new) for correctness
without needing internal knowledge of EVTX's chunk/record binary layout.
`--interval` is deliberately decoupled from the source's actual delivery
timing, same reasoning as `guestcontrol_probe.py`'s `PROBE_TIMEOUT_SECONDS`
in scripts/manual_tests/ -- see that module for the real bug this pattern
was written to avoid repeating.

Latency budget (ARCHITECTURE.md section 3.4): "Collector -> bus <= 150ms,
Sysmon ETW tail, batched at 100ms." This collector's default poll interval
(0.1s) matches that 100ms batching figure directly.

Not independently offline-testable end-to-end (no real .evtx file or live
Sysmon install in this environment) -- see adam/collectors/parsers/evtx.py's
module docstring for the same limitation on `iter_evtx_records()`. What IS
tested offline here: the polling/dedup/state-tracking logic in `_run()`,
via a fake `_read_current_records()` override that returns synthetic
(source_event_id, xml) pairs instead of touching a real file, exactly the
same fake-the-I/O-boundary pattern used for VirtualBoxClient and
EventBus's handler isolation earlier in this project.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from xml.etree import ElementTree

from adam.collectors.base import BaseCollector
from adam.collectors.parsers.evtx import SysmonParseError, iter_evtx_records, parse_sysmon_event_xml
from adam.contracts.raw_event import RawEvent

logger = logging.getLogger(__name__)


class SysmonCollector(BaseCollector):
    """
    Tails `evtx_path` for new Sysmon records and emits them as RawEvent.
    See module docstring for the polling/dedup strategy.
    """

    def __init__(
        self,
        evtx_path: str,
        *,
        session_id: str,
        poll_interval: float = 0.1,
        buffer_size: int = 10000,
    ) -> None:
        super().__init__(buffer_size=buffer_size)
        self._evtx_path = evtx_path
        self._session_id = session_id
        self._poll_interval = poll_interval
        self._last_record_id: int | None = None

    @property
    def source_name(self) -> str:
        return "sysmon"

    def _read_current_records(self) -> Iterable[str]:
        """
        Returns the raw XML of every record currently in the EVTX file, in
        file order. Split out as its own method (rather than inlined in
        _run()) specifically so tests can override just the I/O boundary --
        see module docstring.
        """
        return iter_evtx_records(self._evtx_path)

    def _record_id_of(self, xml_text: str) -> int | None:
        """
        Cheap peek at a record's EventRecordID without fully parsing it into
        a RawEvent, so already-seen records can be skipped before paying
        the cost of parse_sysmon_event_xml(). Falls back to None (never
        skip) if the XML is malformed enough that even this fails --
        parse_sysmon_event_xml() will raise SysmonParseError on it properly
        in that case, logged and skipped by _run(), same as any other
        malformed record.
        """
        try:
            ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
            root = ElementTree.fromstring(xml_text)
            system = root.find(f"{ns}System")
            if system is None:
                return None
            record_id_el = system.find(f"{ns}EventRecordID")
            if record_id_el is None or record_id_el.text is None:
                return None
            return int(record_id_el.text.strip())
        except (ElementTree.ParseError, ValueError):
            return None

    async def _run(self) -> None:
        while True:
            if self._stop_requested():
                return

            try:
                records = list(self._read_current_records())
            except OSError as exc:
                logger.warning("source=%s cannot read %s: %s", self.source_name, self._evtx_path, exc)
                await asyncio.sleep(self._poll_interval)
                continue

            highest_seen = self._last_record_id
            emitted_since_yield = 0
            for xml_text in records:
                record_id = self._record_id_of(xml_text)
                if record_id is not None and self._last_record_id is not None and record_id <= self._last_record_id:
                    continue  # already emitted in a previous poll

                event: RawEvent | None = None
                try:
                    event = parse_sysmon_event_xml(
                        xml_text, session_id=self._session_id, raw_ref=self._evtx_path
                    )
                except SysmonParseError as exc:
                    logger.warning("source=%s skipping malformed record: %s", self.source_name, exc)

                if event is not None:
                    self._emit(event)
                    emitted_since_yield += 1
                    if emitted_since_yield >= 10:
                        await asyncio.sleep(0)  # cooperative yield point to let pump tasks run
                        emitted_since_yield = 0

                if record_id is not None and (highest_seen is None or record_id > highest_seen):
                    highest_seen = record_id

            self._last_record_id = highest_seen
            await asyncio.sleep(self._poll_interval)
