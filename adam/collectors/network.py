"""
adam/collectors/network.py

NetworkCollector -- ARCHITECTURE.md section 5.3 / docs/dev-a-environment-
and-roadmap.md Phase 7. Tails a growing `tshark -T ek` newline-delimited
JSON export and turns each packet document line into a RawEvent via
adam.collectors.parsers.pcap.parse_tshark_ek_line().

Tailing strategy: `-T ek` is line-oriented (see pcap.py's module docstring
for why that format was chosen over plain `-T json`), so this collector
uses the same real byte-offset tail as ProcmonCollector -- read new bytes
since the last poll, split on newlines, buffer any trailing incomplete
line for the next poll. Unlike ProcMon's CSV, there is no header row to
validate here; every complete line is independently either an index-action
line (parse_tshark_ek_line() returns None, skipped) or a document line.
"""

from __future__ import annotations

import asyncio
import logging

from adam.collectors.base import BaseCollector
from adam.collectors.parsers.pcap import PcapParseError, parse_tshark_ek_line

logger = logging.getLogger(__name__)


class NetworkCollector(BaseCollector):
    """
    Tails `ek_json_path` (a `tshark -T ek -l` output file, growing as
    capture continues) for new lines and emits packet documents as
    RawEvent. See module docstring for the tail strategy.
    """

    def __init__(
        self,
        ek_json_path: str,
        *,
        session_id: str,
        poll_interval: float = 0.1,
        buffer_size: int = 1000,
    ) -> None:
        super().__init__(buffer_size=buffer_size)
        self._ek_json_path = ek_json_path
        self._session_id = session_id
        self._poll_interval = poll_interval
        self._read_offset = 0
        self._pending_partial_line = ""

    @property
    def source_name(self) -> str:
        return "network"

    def _read_new_bytes(self) -> str:
        """Same pattern as ProcmonCollector._read_new_bytes() -- split out for testability."""
        with open(self._ek_json_path, encoding="utf-8", newline="") as f:
            f.seek(self._read_offset)
            data = f.read()
            self._read_offset = f.tell()
        return data

    async def _run(self) -> None:
        while True:
            if self._stop_requested():
                return

            try:
                chunk = self._read_new_bytes()
            except OSError as exc:
                logger.warning("source=%s cannot read %s: %s", self.source_name, self._ek_json_path, exc)
                await asyncio.sleep(self._poll_interval)
                continue

            if chunk:
                text = self._pending_partial_line + chunk
                lines = text.split("\n")
                self._pending_partial_line = lines[-1]
                complete_lines = [line for line in lines[:-1] if line.strip()]

                for line in complete_lines:
                    try:
                        event = parse_tshark_ek_line(
                            line, session_id=self._session_id, raw_ref=self._ek_json_path
                        )
                    except PcapParseError as exc:
                        logger.warning("source=%s skipping malformed line: %s", self.source_name, exc)
                        continue

                    if event is not None:
                        self._emit(event)

            await asyncio.sleep(self._poll_interval)
