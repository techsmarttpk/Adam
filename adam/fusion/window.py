from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta

from .models import RawEvent


class SlidingWindow:
    """
    Stores only the most recent events within a configurable time window.

    Older events are automatically discarded.
    """

    def __init__(self, window_seconds: int = 10):
        self.window = timedelta(seconds=window_seconds)
        self.events: deque[RawEvent] = deque()

    def add(self, event: RawEvent) -> None:
        """
        Add a new event and remove expired events.
        """

        self.events.append(event)
        self._expire(event.timestamp)

    def _expire(self, current_time: datetime) -> None:
        """
        Remove events older than the configured window.
        """

        while self.events:
            oldest = self.events[0]

            if current_time - oldest.timestamp <= self.window:
                break

            self.events.popleft()

    def get_events(self) -> list[RawEvent]:
        """
        Return all events currently inside the window.
        """

        return list(self.events)

    def clear(self) -> None:
        """
        Remove all stored events.
        """

        self.events.clear()

    def __len__(self) -> int:
        return len(self.events)