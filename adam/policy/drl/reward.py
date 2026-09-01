"""Quality-Aware Reward Function with Anti-Reward Hacking Gating.

Calculates Reinforcement Learning rewards for AMTD sandbox orchestration:
- Rewards behavioral novelty and forensic intelligence disclosure (C2 / unpacked stages).
- Imposes temporal execution penalties (gamma^t) to prevent stall loops.
- Enforces milestone-based gating before granting high-tier mutation points.
- Penalizes sandbox detection and guest OS instability.
"""

from __future__ import annotations
import dataclasses
import enum
from typing import Dict, List, Set


class ExecutionMilestone(enum.Enum):
    PROCESS_CREATION = "PROCESS_CREATION"
    MEMORY_INJECTION = "MEMORY_INJECTION"
    PAYLOAD_DECRYPTION = "PAYLOAD_DECRYPTION"
    PERSISTENCE_ATTEMPT = "PERSISTENCE_ATTEMPT"
    NETWORK_SOCKET_BIND = "NETWORK_SOCKET_BIND"
    C2_BEACON_TRANSMIT = "C2_BEACON_TRANSMIT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"


@dataclasses.dataclass
class RewardBreakdown:
    total_reward: float
    novelty_component: float
    disclosure_component: float
    milestone_bonus: float
    time_penalty: float
    stability_penalty: float
    milestones_unlocked: List[str]


class QualityAwareRewardShaper:
    """Computes shaped rewards for the Dual-Stream Reinforcement Learning Policy."""

    def __init__(self, time_discount_gamma: float = 0.98) -> None:
        self.gamma = time_discount_gamma
        self.step_count = 0
        self.seen_behavior_signatures: Set[str] = set()
        self.achieved_milestones: Set[ExecutionMilestone] = set()
        self.discovered_iocs: Set[str] = set()

    def reset(self) -> None:
        self.step_count = 0
        self.seen_behavior_signatures.clear()
        self.achieved_milestones.clear()
        self.discovered_iocs.clear()

    def record_milestone(self, milestone: ExecutionMilestone) -> bool:
        """Unlock milestone if newly reached."""
        if milestone not in self.achieved_milestones:
            self.achieved_milestones.add(milestone)
            return True
        return False

    def compute_step_reward(
        self,
        new_behaviors: List[str],
        new_iocs: List[str],
        mutation_applied: bool,
        guest_crashed: bool = False,
        malware_dormant: bool = False,
    ) -> RewardBreakdown:
        """Compute the net reward for a single DRL decision step."""
        self.step_count += 1

        # 1. Temporal penalty to prevent reward hacking / infinite waiting
        # Discount factor increases penalty as time steps elapse without milestones
        temporal_penalty = -0.05 * (self.step_count ** 0.5)

        if guest_crashed:
            return RewardBreakdown(
                total_reward=-50.0,
                novelty_component=0.0,
                disclosure_component=0.0,
                milestone_bonus=0.0,
                time_penalty=temporal_penalty,
                stability_penalty=-50.0,
                milestones_unlocked=[m.value for m in self.achieved_milestones],
            )

        # 2. Novelty calculation
        novelty_score = 0.0
        for b in new_behaviors:
            if b not in self.seen_behavior_signatures:
                self.seen_behavior_signatures.add(b)
                # Milestone gating: higher novelty rewards only if initial milestone reached
                multiplier = 2.0 if len(self.achieved_milestones) >= 2 else 1.0
                novelty_score += 5.0 * multiplier

        # 3. Infrastructure & Forensic Disclosure
        disclosure_score = 0.0
        for ioc in new_iocs:
            if ioc not in self.discovered_iocs:
                self.discovered_iocs.add(ioc)
                disclosure_score += 15.0  # High reward for new C2 endpoint or dropped stage

        # 4. Milestone Bonus
        milestone_bonus = len(self.achieved_milestones) * 3.0

        # 5. Stability & Anti-Evasion Penalties
        stability_penalty = 0.0
        if malware_dormant:
            stability_penalty -= 5.0

        # Prevent trivial mutation spamming: if mutation applied with zero new behavior or milestone
        if mutation_applied and novelty_score == 0.0 and disclosure_score == 0.0:
            stability_penalty -= 1.0

        total = round(
            novelty_score + disclosure_score + milestone_bonus + temporal_penalty + stability_penalty,
            3,
        )

        return RewardBreakdown(
            total_reward=total,
            novelty_component=novelty_score,
            disclosure_component=disclosure_score,
            milestone_bonus=milestone_bonus,
            time_penalty=round(temporal_penalty, 3),
            stability_penalty=stability_penalty,
            milestones_unlocked=[m.value for m in self.achieved_milestones],
        )
