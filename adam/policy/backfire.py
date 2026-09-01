"""Deception Backfire and Anti-Deception Detection Engine.

Explicitly detects when malware identifies synthetic tells, inconsistent artifacts,
or honeypots, leading to evasive deflection, sudden dormancy, or anti-analysis escalation.
"""

from __future__ import annotations
import dataclasses
import time
from typing import Dict, List, Optional, Set
from datetime import datetime

from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent


@dataclasses.dataclass
class BackfireIndicator:
    indicator_type: str  # SUDDEN_SLEEP_AFTER_MUTATION, PROCESS_TERMINATE_DEFLECTION, CANARY_AVOIDANCE, EVASION_ESCALATION
    confidence: float
    description: str
    triggering_mutation_id: Optional[str]
    timestamp_ns: int = dataclasses.field(default_factory=time.perf_counter_ns)


class DeceptionBackfireDetector:
    """Monitors telemetry immediately following a mutation to detect adversarial anti-deception."""

    def __init__(self) -> None:
        self.recorded_backfires: List[BackfireIndicator] = []
        self.active_mutation_id: Optional[str] = None
        self.active_mutation_time: Optional[datetime] = None
        self.post_mutation_event_count = 0

    def set_active_mutation(self, mutation_id: Optional[str], applied_at: Optional[datetime] = None) -> None:
        self.active_mutation_id = mutation_id
        self.active_mutation_time = applied_at
        self.post_mutation_event_count = 0

    def inspect_raw_event(self, event: RawEvent) -> Optional[BackfireIndicator]:
        """Inspects raw event for sudden anti-analysis deflection following mutation."""
        if not self.active_mutation_id or not self.active_mutation_time:
            return None

        self.post_mutation_event_count += 1
        elapsed_s = (event.occurred_at - self.active_mutation_time).total_seconds()

        if 0 <= elapsed_s <= 15.0:
            # Check 1: Sudden NtDelayExecution or long Sleep call
            op = str(event.attributes.get("operation") or event.attributes.get("details") or "").lower()
            if "sleep" in op or "delayexecution" in op:
                indicator = BackfireIndicator(
                    indicator_type="SUDDEN_SLEEP_AFTER_MUTATION",
                    confidence=0.85,
                    description=f"Malware initiated sleep/delay ({op}) {elapsed_s:.1f}s after mutation {self.active_mutation_id}.",
                    triggering_mutation_id=self.active_mutation_id,
                )
                self.recorded_backfires.append(indicator)
                return indicator

            # Check 2: Immediate self-termination / process exit
            if event.category.value == "PROCESS" and ("terminate" in op or "exit" in op):
                indicator = BackfireIndicator(
                    indicator_type="PROCESS_TERMINATE_DEFLECTION",
                    confidence=0.90,
                    description=f"Malware process self-terminated {elapsed_s:.1f}s after mutation {self.active_mutation_id}.",
                    triggering_mutation_id=self.active_mutation_id,
                )
                self.recorded_backfires.append(indicator)
                return indicator

        return None

    def inspect_semantic_event(self, event: SemanticEvent) -> Optional[BackfireIndicator]:
        """Inspects semantic event for anti-analysis escalation."""
        if not self.active_mutation_id or not self.active_mutation_time:
            return None

        elapsed_s = (event.window_end - self.active_mutation_time).total_seconds()
        if 0 <= elapsed_s <= 20.0 and event.intent.startswith("EVADE_"):
            indicator = BackfireIndicator(
                indicator_type="EVASION_ESCALATION",
                confidence=event.confidence,
                description=f"Malware triggered evasion tactic {event.intent} {elapsed_s:.1f}s after mutation {self.active_mutation_id}.",
                triggering_mutation_id=self.active_mutation_id,
            )
            self.recorded_backfires.append(indicator)
            return indicator

        return None

    def has_backfired_on_mutation(self, mutation_id: str) -> bool:
        return any(b.triggering_mutation_id == mutation_id for b in self.recorded_backfires)
