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
        self._emitted_signatures: set[tuple] = set()

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
        # Detection (with signature deduplication)
        # ----------------------------
        semantic_events = []

        for group in groups:

            for detector in self.registry:

                matched = detector.match(group)

                if matched:
                    # Construct an immutable signature of matched evidence
                    ev_sig = tuple(
                        (
                            getattr(e, "timestamp", None),
                            getattr(e, "process_name", None),
                            getattr(e, "process_id", None),
                            str(getattr(e, "payload", {}).get("command_line", "")),
                        )
                        for e in matched
                    )
                    sig = (detector.__class__.__name__, ev_sig)
                    if sig in self._emitted_signatures:
                        continue

                    self._emitted_signatures.add(sig)
                    # Limit memory of emitted signatures
                    if len(self._emitted_signatures) > 5000:
                        self._emitted_signatures.clear()

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