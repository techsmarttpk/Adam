from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import RawEvent, SemanticEvent


class BaseDetector(ABC):
    """
    Base class for all behavioral detectors.

    Every detector works on a correlated group of RawEvents.
    Shared scoring logic lives here so individual detectors only
    need to define their indicators and threshold.
    """

    STRONG_INDICATORS: list[str] = []
    MEDIUM_INDICATORS: list[str] = []
    WEAK_INDICATORS: list[str] = []

    SCORE_THRESHOLD: int = 5

    # -----------------------------------------------------
    # Shared Scoring Logic
    # -----------------------------------------------------

    def score_events(
        self,
        events: list[RawEvent],
    ) -> tuple[int, list[RawEvent]]:
        """
        Score a correlated event group.

        Returns:
            (score, matched_events)
        """

        matched: list[RawEvent] = []
        score = 0

        for event in events:

            process = (event.process_name or "").lower()

            payload = " ".join(
                str(value).lower()
                for value in event.payload.values()
            )

            command = event.payload.get(
                "command_line",
                ""
            ).lower()

            searchable = f"{process} {command} {payload}"

            event_score = 0

            if any(i in searchable for i in self.STRONG_INDICATORS):
                event_score = max(event_score, 5)

            if any(i in searchable for i in self.MEDIUM_INDICATORS):
                event_score = max(event_score, 3)

            if any(i in searchable for i in self.WEAK_INDICATORS):
                event_score = max(event_score, 2)

            if event_score:
                matched.append(event)
                score += event_score

        return score, matched

    # -----------------------------------------------------
    # Detector Interface
    # -----------------------------------------------------

    @abstractmethod
    def match(
        self,
        events: list[RawEvent],
    ) -> list[RawEvent] | None:
        """
        Return the subset of events responsible
        for the detection, or None.
        """
        pass

    @abstractmethod
    def build(
        self,
        matched: list[RawEvent],
    ) -> SemanticEvent:
        """
        Construct the SemanticEvent produced
        by this detector.
        """
        pass