"""Dual-Stream Reinforcement Learning Policy for Autonomous Malware Sandboxing.

Combines:
1. Immediate Tactical Stream: Reactive anti-evasion, vCPU stability, and containment.
2. Strategic Cognitive Stream: Long-term moving target defense planning to force
   dormant malware to reveal hidden stages, unpack payloads, and contact C2 servers.
"""

from __future__ import annotations
import dataclasses
import math
import random
from typing import Dict, List, Optional, Tuple

from adam.policy.drl.gym_env import ActionType


@dataclasses.dataclass
class PolicyAction:
    action_type: ActionType
    stream_source: str  # IMMEDIATE_TACTICAL or STRATEGIC_COGNITIVE
    confidence: float
    tactical_urgency: float
    strategic_value: float
    rationale: str


class DualStreamPolicy:
    """Orchestrates immediate anti-evasion containment and strategic AMTD payload forcing."""

    def __init__(self, action_dim: int = 9, seed: Optional[int] = None) -> None:
        self.action_dim = action_dim
        self.rng = random.Random(seed)
        self.decision_history: List[PolicyAction] = []
        self.dormancy_counter = 0

    def select_action(
        self,
        state_embedding: List[float],
        execution_phase: str = "EXECUTION",
        is_evasion_detected: bool = False,
        is_sample_dormant: bool = False,
    ) -> PolicyAction:
        """Arbitrates between Immediate Tactical Stream and Strategic Cognitive Stream."""
        if is_sample_dormant:
            self.dormancy_counter += 1
        else:
            self.dormancy_counter = 0

        # 1. IMMEDIATE STREAM: High priority if evasion or dormancy detected
        if is_evasion_detected:
            # Immediate tactical countermeasure: normalize timing or spoof decoys
            action = PolicyAction(
                action_type=ActionType.TRIGGER_USER_SIMULATION,
                stream_source="IMMEDIATE_TACTICAL",
                confidence=0.95,
                tactical_urgency=0.9,
                strategic_value=0.3,
                rationale="Anti-evasion triggered: Injecting realistic user activity to defeat idle checks.",
            )
            self.decision_history.append(action)
            return action

        if self.dormancy_counter >= 3:
            # Dormancy breaker: forced kernel mutation / dynamic mitigation toggle
            chosen_action = self.rng.choice([
                ActionType.RANDOMIZE_SYSCALLS,
                ActionType.TOGGLE_SPECTRE_MITIGATION,
                ActionType.ENABLE_C2_SINKHOLE,
            ])
            action = PolicyAction(
                action_type=chosen_action,
                stream_source="IMMEDIATE_TACTICAL",
                confidence=0.88,
                tactical_urgency=0.85,
                strategic_value=0.75,
                rationale=f"Dormancy counter {self.dormancy_counter}: Forcing state transition via {chosen_action.name}.",
            )
            self.decision_history.append(action)
            return action

        # 2. STRATEGIC STREAM: Multi-step AMTD planning based on state embedding
        # Compute heuristic Q-values from state embedding
        q_values = [0.0] * self.action_dim
        for i in range(self.action_dim):
            # Inner product with learnable weight projection (simulated)
            weight = (math.sin((i + 1) * sum(state_embedding)) + 1.0) / 2.0
            q_values[i] = weight

        # Prioritize informative actions based on execution phase
        if execution_phase == "INITIAL_DETONATION":
            q_values[ActionType.TRIGGER_USER_SIMULATION] += 0.4
            q_values[ActionType.ROTATE_SYNTHETIC_DECOYS] += 0.3
        elif execution_phase == "UNPACKING":
            q_values[ActionType.ACTIVATE_EPT_SHADOW_HOOK] += 0.5
            q_values[ActionType.SHUFFLE_KERNEL_MEMORY] += 0.4
        elif execution_phase == "C2_INTERACTION":
            q_values[ActionType.ENABLE_C2_SINKHOLE] += 0.6

        best_action_idx = max(range(self.action_dim), key=lambda idx: q_values[idx])
        chosen_action = ActionType(best_action_idx)

        action = PolicyAction(
            action_type=chosen_action,
            stream_source="STRATEGIC_COGNITIVE",
            confidence=round(max(q_values) / (sum(q_values) + 1e-5), 3),
            tactical_urgency=0.2,
            strategic_value=round(q_values[best_action_idx], 3),
            rationale=f"Strategic AMTD planning selected {chosen_action.name} for phase {execution_phase}.",
        )
        self.decision_history.append(action)
        return action
