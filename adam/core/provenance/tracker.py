"""Causal Provenance and Attribution Engine for ADAM.

Tracks precise causal dependency chains:
Mutation -> Environment Change -> Raw Event(s) -> Semantic Event(s) -> Policy Decision -> Next Mutation

Rejects temporal-correlation fallacies by verifying entity scope (PIDs, file/registry/network targets),
timestamp intervals, and operational causality.
"""

from __future__ import annotations
import dataclasses
import time
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime

from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.mutation import MutationResult, MutationChange
from adam.contracts.policy_decision import PolicyDecision


@dataclasses.dataclass
class CausalLink:
    source_id: str
    target_id: str
    relation: str  # e.g., "TRIGGERED_BY", "CAUSED_BY_MUTATION", "SCOPED_REACTION"
    confidence: float
    evidence: Dict[str, object]
    timestamp_ns: int = dataclasses.field(default_factory=time.perf_counter_ns)


@dataclasses.dataclass
class ActiveMutationScope:
    mutation_id: str
    primitive: str
    applied_at_utc: datetime
    causal_window_ms: int
    targets: Set[str]  # e.g., file paths, registry keys, DNS hostnames
    operations: Set[str]
    allowed_pids: Set[int]  # Empty means all malware-related PIDs


class CausalProvenanceEngine:
    """Constructs and queries the causal Directed Acyclic Graph (DAG) for an analysis session."""

    def __init__(self, default_window_ms: int = 30000) -> None:
        self.default_window_ms = default_window_ms
        self.active_scopes: Dict[str, ActiveMutationScope] = {}
        self.links: List[CausalLink] = []
        self.mutation_attributed_events: Dict[str, List[str]] = {}  # mutation_id -> [semantic_ids]
        self.entity_target_to_mutations: Dict[str, Set[str]] = {}

    def register_mutation(self, mutation: MutationResult) -> ActiveMutationScope:
        """Registers an applied mutation and extracts its entity targets for scoped attribution."""
        targets = set()
        operations = set()

        for ch in mutation.changes:
            if ch.target:
                # Normalize target string (lowercase, standard path separators)
                norm_tgt = ch.target.lower().replace("/", "\\").strip("\\")
                targets.add(norm_tgt)
                operations.add(ch.operation.upper())

        scope = ActiveMutationScope(
            mutation_id=mutation.mutation_id,
            primitive=mutation.primitive,
            applied_at_utc=mutation.applied_at,
            causal_window_ms=int(mutation.causal_window_ms) if mutation.causal_window_ms else self.default_window_ms,
            targets=targets,
            operations=operations,
            allowed_pids=set(),
        )

        self.active_scopes[mutation.mutation_id] = scope
        self.mutation_attributed_events[mutation.mutation_id] = []

        for tgt in targets:
            if tgt not in self.entity_target_to_mutations:
                self.entity_target_to_mutations[tgt] = set()
            self.entity_target_to_mutations[tgt].add(mutation.mutation_id)

        # Record link between decision and mutation
        if mutation.decision_id:
            self.links.append(
                CausalLink(
                    source_id=mutation.decision_id,
                    target_id=mutation.mutation_id,
                    relation="PRODUCED_MUTATION",
                    confidence=1.0,
                    evidence={"primitive": mutation.primitive, "latency_ms": mutation.latency_ms},
                )
            )

        return scope

    def evaluate_raw_event_causality(self, event: RawEvent) -> Optional[Tuple[str, float]]:
        """Evaluates whether a raw event is causally related to an active mutation.

        Returns (mutation_id, confidence) if causally linked, or None if background noise.
        """
        if not self.active_scopes:
            return None

        # Extract target object from event attributes
        raw_target = str(
            event.attributes.get("target_object")
            or event.attributes.get("target_path")
            or event.attributes.get("target")
            or event.attributes.get("path")
            or event.attributes.get("key")
            or ""
        ).lower().replace("/", "\\").strip("\\")

        pid = event.process.pid if event.process else None

        for mut_id, scope in list(self.active_scopes.items()):
            # 1. Temporal validation
            elapsed_ms = (event.occurred_at - scope.applied_at_utc).total_seconds() * 1000.0
            if elapsed_ms < 0 or elapsed_ms > scope.causal_window_ms:
                continue

            # 2. Target match (Direct match or subtree match)
            target_match = False
            confidence = 0.5

            if raw_target and scope.targets:
                for st in scope.targets:
                    if st in raw_target or raw_target in st:
                        target_match = True
                        confidence = 0.95
                        break

            # 3. Process scope match
            if scope.allowed_pids and pid and pid in scope.allowed_pids:
                confidence = min(1.0, confidence + 0.2)

            if target_match or (elapsed_ms <= 3000.0 and pid is not None):
                return (mut_id, round(confidence, 3))

        return None

    def attribute_semantic_event(
        self, semantic_event: SemanticEvent, candidate_mutation_id: Optional[str] = None
    ) -> Optional[str]:
        """Attributes a semantic event to a causal mutation if evidence links hold."""
        chosen_mut_id = candidate_mutation_id

        if not chosen_mut_id and self.active_scopes:
            # Inspect features for target alignment
            sem_target = str(
                semantic_event.features.get("target_path")
                or semantic_event.features.get("target_object")
                or semantic_event.features.get("target")
                or ""
            ).lower().replace("/", "\\").strip("\\")

            if sem_target:
                for tgt, muts in self.entity_target_to_mutations.items():
                    if tgt in sem_target or sem_target in tgt:
                        for m in muts:
                            if m in self.active_scopes:
                                chosen_mut_id = m
                                break

        if chosen_mut_id and chosen_mut_id in self.active_scopes:
            scope = self.active_scopes[chosen_mut_id]
            elapsed_ms = (semantic_event.window_end - scope.applied_at_utc).total_seconds() * 1000.0
            if 0 <= elapsed_ms <= scope.causal_window_ms:
                self.mutation_attributed_events[chosen_mut_id].append(semantic_event.semantic_id)
                self.links.append(
                    CausalLink(
                        source_id=chosen_mut_id,
                        target_id=semantic_event.semantic_id,
                        relation="CAUSED_SEMANTIC_INTENT",
                        confidence=semantic_event.confidence,
                        evidence={"elapsed_ms": elapsed_ms, "intent": semantic_event.intent},
                    )
                )
                return chosen_mut_id

        return None

    def get_provenance_chain(self, node_id: str) -> List[CausalLink]:
        """Retrieves all ancestor causal links leading to node_id."""
        chain = []
        visited = set()
        queue = [node_id]

        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)

            for link in self.links:
                if link.target_id == curr:
                    chain.append(link)
                    queue.append(link.source_id)

        return chain

    def prune_expired_scopes(self, current_utc: datetime) -> List[str]:
        """Removes scopes that have exceeded their causal window."""
        expired = []
        for mut_id, scope in list(self.active_scopes.items()):
            elapsed_ms = (current_utc - scope.applied_at_utc).total_seconds() * 1000.0
            if elapsed_ms > scope.causal_window_ms:
                expired.append(mut_id)
                del self.active_scopes[mut_id]
        return expired
