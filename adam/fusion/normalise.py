from __future__ import annotations

from pathlib import PureWindowsPath

from .models import RawEvent


class EventNormalizer:
    """
    Converts raw events from different telemetry sources
    into a canonical representation.
    """

    EVENT_MAP = {
        "ProcessCreate": "PROCESS_CREATE",
        "Process Create": "PROCESS_CREATE",
        "CreateProcess": "PROCESS_CREATE",

        "FileCreate": "FILE_CREATE",
        "File Create": "FILE_CREATE",

        "NetworkConnect": "NETWORK_CONNECT",
        "Network Connect": "NETWORK_CONNECT",
    }

    def normalize(self, event: RawEvent) -> RawEvent:

        event.source = event.source.strip().lower()

        event.event_type = self.EVENT_MAP.get(
            event.event_type,
            event.event_type.upper(),
        )

        if event.process_name:
            event.process_name = (
                PureWindowsPath(event.process_name)
                .name
                .lower()
            )

        if event.command_line:
            event.command_line = event.command_line.strip()

        event.process_name = event.process_name or None
        event.command_line = event.command_line or None

        return event
