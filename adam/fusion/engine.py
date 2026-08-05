from __future__ import annotations

import time
from datetime import datetime
from typing import Iterable

from .correlate import EventCorrelator
from .detectors.registry import DetectorRegistry
from .models import FusionResult, RawEvent
from .normalise import EventNormalizer
from .process_tree import ProcessTree
from .window import SlidingWindow


class EventFusionEngine:
    """
    Coordinates the complete Event Fusion pipeline.

    Pipeline

    RawEvent
        ↓
    Normalizer
        ↓
    Sliding Window
        ↓
    Process Tree
        ↓
    Correlator
        ↓
    Detector Registry
        ↓
    Semantic Events
        ↓
    Fusion Result
    """

    def __init__(self, window_seconds: int = 10):

        self.normalizer = EventNormalizer()
        self.window = SlidingWindow(window_seconds)
        self.process_tree = ProcessTree()
        self.correlator = EventCorrelator()
        self.registry = DetectorRegistry()

    def process(self, events: Iterable[RawEvent]) -> FusionResult:
        """
        Process a batch of events through the fusion pipeline.
        """

        start = time.perf_counter()

        normalized_events = []

        # ----------------------------
        # Normalize + Window + Process Tree
        # ----------------------------
        for event in events:

            normalized = self.normalizer.normalize(event)

            normalized_events.append(normalized)

            self.window.add(normalized)

            self.process_tree.update(normalized)

        # ----------------------------
        # Correlation
        # ----------------------------
        groups = self.correlator.correlate(
            self.window.get_events()
        )

        # ----------------------------
        # Detection
        # ----------------------------
        semantic_events = []

        for group in groups:

            for detector in self.registry:

                matched = detector.match(group)

                if matched:

                    semantic_events.append(
                        detector.build(matched)
                    )

        runtime_ms = (time.perf_counter() - start) * 1000

        return FusionResult(
            timestamp=datetime.now(),
            processed_events=len(normalized_events),
            normalized_events=len(normalized_events),
            correlated_groups=len(groups),
            detections=semantic_events,
            runtime_ms=runtime_ms,
        )