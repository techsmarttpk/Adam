from __future__ import annotations

from collections import defaultdict

from .models import RawEvent


class EventCorrelator:
    """
    Groups related events together for downstream detectors.

    Phase 1:
        - Correlation by Process ID
    """

    def correlate(
        self,
        events: list[RawEvent],
    ) -> list[list[RawEvent]]:
        """
        Correlate events into logical groups.

        Returns:
            List of event groups.
        """

        groups: dict[int, list[RawEvent]] = defaultdict(list)

        ungrouped: list[RawEvent] = []

        for event in events:

            if event.process_id is None:
                ungrouped.append(event)
                continue

            groups[event.process_id].append(event)

        result = list(groups.values())

        if ungrouped:
            result.append(ungrouped)

        return result