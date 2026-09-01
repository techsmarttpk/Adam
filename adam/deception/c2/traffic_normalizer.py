"""Beaconing Cadence Analyzer, Jitter Injection & Traffic Normalizer.

Analyzes timing intervals of malware outbound network traffic, identifies periodic beaconing,
and injects synthetic network jitter to observe malware reconnection / synchronization logic.
"""

from __future__ import annotations
import dataclasses
import math
import random
from typing import Dict, List, Optional, Tuple


@dataclasses.dataclass
class BeaconProfile:
    domain_or_ip: str
    sample_count: int
    mean_interval_s: float
    jitter_percentage: float
    is_beaconing_detected: bool
    confidence_score: float


class TrafficNormalizer:
    """Detects periodic C2 beaconing patterns and manipulates TCP transmission jitter."""

    def __init__(self, min_samples: int = 4) -> None:
        self.min_samples = min_samples
        self.flow_timestamps: Dict[str, List[float]] = {}  # endpoint -> list of timestamps in seconds

    def record_packet(self, endpoint: str, timestamp_s: float) -> None:
        if endpoint not in self.flow_timestamps:
            self.flow_timestamps[endpoint] = []
        self.flow_timestamps[endpoint].append(timestamp_s)

    def analyze_beaconing_pattern(self, endpoint: str) -> Optional[BeaconProfile]:
        """Calculates periodicity and jitter for an outbound connection."""
        timestamps = self.flow_timestamps.get(endpoint, [])
        if len(timestamps) < self.min_samples:
            return None

        # Compute consecutive intervals
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        mean_interval = sum(intervals) / len(intervals)

        if mean_interval <= 0.001:
            return None

        # Calculate standard deviation
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        jitter = (std_dev / mean_interval) * 100.0

        # Periodic beaconing typically has low to moderate jitter (e.g. < 40%)
        is_beaconing = (jitter < 45.0) and (mean_interval > 0.5)
        confidence = max(0.0, min(1.0, 1.0 - (jitter / 100.0)))

        return BeaconProfile(
            domain_or_ip=endpoint,
            sample_count=len(timestamps),
            mean_interval_s=round(mean_interval, 3),
            jitter_percentage=round(jitter, 2),
            is_beaconing_detected=is_beaconing,
            confidence_score=round(confidence, 3),
        )

    def inject_synthetic_jitter(self, base_delay_s: float, jitter_factor: float = 0.25) -> float:
        """Calculate delayed response time to disrupt malware synchronization."""
        delta = base_delay_s * jitter_factor
        return max(0.01, base_delay_s + random.uniform(-delta, delta))
