"""Deception Memory and Cross-Session Behavioral Learning Engine.

Maintains historical records of (Behavioral Fingerprint + Intent + Environment State -> Mutation -> Yield).
Allows the Policy Engine to query:
"When malware previously exhibited behavioral pattern X, which deception primitive yielded the highest behavioral expansion?"
"""

from __future__ import annotations
import dataclasses
import hashlib
import json
from typing import Dict, List, Optional, Tuple


@dataclasses.dataclass
class DeceptionMemoryEntry:
    fingerprint_hash: str
    intent: str
    mutation_action: str
    yield_score: float
    new_semantic_events_count: int
    new_iocs_count: int
    deception_detected: bool
    sample_family: str = "GENERIC"
    execution_count: int = 1


class DeceptionMemoryStore:
    """Persistent in-memory store tracking historical deception effectiveness."""

    def __init__(self) -> None:
        # Key: (fingerprint_hash, intent, mutation_action) -> DeceptionMemoryEntry
        self.memory: Dict[Tuple[str, str, str], DeceptionMemoryEntry] = {}

    @staticmethod
    def compute_behavioral_fingerprint(
        intents_sequence: List[str],
        accessed_categories: List[str],
        network_destinations_count: int,
    ) -> str:
        """Computes a deterministic behavioral fingerprint hash independent of raw sample SHA256."""
        # Top 5 unique ordered intents
        unique_intents = []
        for it in intents_sequence:
            if it not in unique_intents:
                unique_intents.append(it)
        sig_str = f"intents:{','.join(unique_intents[:5])}|cats:{','.join(sorted(set(accessed_categories)))}|net:{network_destinations_count}"
        return hashlib.sha256(sig_str.encode("utf-8")).hexdigest()[:16]

    def record_outcome(
        self,
        fingerprint_hash: str,
        intent: str,
        mutation_action: str,
        yield_score: float,
        new_semantic_events: int,
        new_iocs: int,
        deception_detected: bool,
        sample_family: str = "GENERIC",
    ) -> DeceptionMemoryEntry:
        """Records the observed outcome of a deception mutation."""
        key = (fingerprint_hash, intent, mutation_action)

        if key in self.memory:
            entry = self.memory[key]
            # Running average update
            entry.execution_count += 1
            n = entry.execution_count
            entry.yield_score = round(((entry.yield_score * (n - 1)) + yield_score) / n, 2)
            entry.new_semantic_events_count = int(((entry.new_semantic_events_count * (n - 1)) + new_semantic_events) / n)
            entry.new_iocs_count = int(((entry.new_iocs_count * (n - 1)) + new_iocs) / n)
            entry.deception_detected = entry.deception_detected or deception_detected
            return entry

        entry = DeceptionMemoryEntry(
            fingerprint_hash=fingerprint_hash,
            intent=intent,
            mutation_action=mutation_action,
            yield_score=yield_score,
            new_semantic_events_count=new_semantic_events,
            new_iocs_count=new_iocs,
            deception_detected=deception_detected,
            sample_family=sample_family,
            execution_count=1,
        )
        self.memory[key] = entry
        return entry

    def rank_candidate_mutations(
        self,
        fingerprint_hash: str,
        intent: str,
        candidate_actions: List[str],
    ) -> List[Tuple[str, float]]:
        """Ranks candidate mutations by historical expected yield.

        Returns list of (action, expected_yield_score) sorted descending.
        """
        ranked = []
        for action in candidate_actions:
            key = (fingerprint_hash, intent, action)
            if key in self.memory:
                entry = self.memory[key]
                # Penalize if previously detected
                penalty = 0.5 if entry.deception_detected else 1.0
                ranked.append((action, entry.yield_score * penalty))
            else:
                # Default prior
                ranked.append((action, 50.0))

        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked
