"""
adam/collectors/procmon.py

ProcmonCollector -- ARCHITECTURE.md section 5.3 / docs/dev-a-environment-
and-roadmap.md Phase 7. Tails a growing ProcMon CSV export file and turns
each new row into a RawEvent via
adam.collectors.parsers.pml.parse_procmon_csv_row().

Tailing strategy: unlike EVTX (see sysmon.py's module docstring for why
that format needs a full re-read-and-dedup approach), a CSV export is a
plain append-only text file, so this collector uses a real byte-offset
tail: it remembers the file position after the last complete line it
processed and reads only new bytes on each poll. A trailing, not-yet-
newline-terminated line (ProcMon can be flushing a row mid-write when this
collector polls) is buffered and prepended to the next poll's read rather
than parsed prematurely or dropped.

Header handling: the first line of a fresh ProcMon CSV export is its
header row (column names), not a data row. This collector reads it once on
the first poll that sees any content, validates it against
adam.collectors.parsers.pml.EXPECTED_HEADER, and does not treat it as a
RawEvent. See module docstring on pml.py for the required "Date & Time"
column configuration this validation enforces.

Latency budget (ARCHITECTURE.md section 3.4) does not name a ProcMon-
specific figure the way it does for Sysmon ("ETW tail, batched at 100ms");
this collector's default poll interval matches Sysmon's for consistency
(0.1s), adjustable via the constructor if ProcMon's own buffering behavior
turns out to need something different once measured against a real capture
(section 3.4's manual testing step 2, not yet performed -- see the audit).
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging

from adam.collectors.base import BaseCollector
from adam.collectors.parsers.pml import EXPECTED_HEADER, ProcmonParseError, parse_procmon_csv_row

logger = logging.getLogger(__name__)


class ProcmonCollector(BaseCollector):
    """
    Tails `csv_path` (a ProcMon CSV export, growing as ProcMon continues to
    capture) for new rows and emits them as RawEvent. See module docstring
    for the byte-offset tail strategy and header-validation behavior.
    """

    def __init__(
        self,
        csv_path: str,
        *,
        session_id: str,
        poll_interval: float = 0.1,
        buffer_size: int = 1000,
    ) -> None:
        super().__init__(buffer_size=buffer_size)
        self._csv_path = csv_path
        self._session_id = session_id
        self._poll_interval = poll_interval
        self._read_offset = 0
        self._pending_partial_line = ""
        self._header_validated = False
        self._sequence = 0

    @property
    def source_name(self) -> str:
        return "procmon"

    def _read_new_bytes(self) -> str:
        """
        Reads everything appended to the file since the last call, advancing
        self._read_offset. Split out as its own method purely so tests can
        override just the I/O boundary -- same pattern as
        SysmonCollector._read_current_records().
        """
        with open(self._csv_path, encoding="utf-8", newline="") as f:
            f.seek(self._read_offset)
            data = f.read()
            self._read_offset = f.tell()
        return data

    def _validate_header(self, header_line: str) -> bool:
        """
        Parses `header_line` as a single CSV row and confirms it matches
        pml.EXPECTED_HEADER exactly. Logs a clear, specific warning (rather
        than failing every subsequent row one at a time) if the export is
        missing the required "Date & Time" column configuration -- see
        pml.py's module docstring.
        """
        try:
            fields = next(csv.reader(io.StringIO(header_line)))
        except StopIteration:
            return False
        if tuple(fields) != EXPECTED_HEADER:
            logger.warning(
                "source=%s CSV header does not match expected columns %s (got %s) -- "
                "see adam/collectors/parsers/pml.py's module docstring for the required "
                "ProcMon 'Date & Time' export configuration",
                self.source_name,
                EXPECTED_HEADER,
                tuple(fields),
            )
            return False
        return True

    async def _run(self) -> None:
        while True:
            if self._stop_requested():
                return

            try:
                chunk = self._read_new_bytes()
            except OSError as exc:
                logger.warning("source=%s cannot read %s: %s", self.source_name, self._csv_path, exc)
                await asyncio.sleep(self._poll_interval)
                continue

            if chunk:
                text = self._pending_partial_line + chunk
                lines = text.split("\n")
                # The last element is either an empty string (text ended in
                # a newline, nothing partial) or an incomplete line (no
                # trailing newline yet) -- buffer it for the next poll
                # rather than parsing a row that might still be mid-write.
                self._pending_partial_line = lines[-1]
                complete_lines = [line for line in lines[:-1] if line.strip()]

                for line in complete_lines:
                    if not self._header_validated:
                        self._header_validated = self._validate_header(line)
                        continue  # first non-empty line is always the header, never a data row

                    try:
                        row = next(csv.reader(io.StringIO(line)))
                        row_dict = dict(zip(EXPECTED_HEADER, row))
                    except StopIteration:
                        continue

                    try:
                        event = parse_procmon_csv_row(
                            row_dict,
                            session_id=self._session_id,
                            sequence=self._sequence,
                            raw_ref=self._csv_path,
                        )
                    except ProcmonParseError as exc:
                        logger.warning("source=%s skipping malformed row: %s", self.source_name, exc)
                        continue

                    self._sequence += 1
                    self._emit(event)

            await asyncio.sleep(self._poll_interval)
