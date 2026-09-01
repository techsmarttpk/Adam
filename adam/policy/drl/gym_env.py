"""OpenAI Gym / Gymnasium Compatible Sandbox Environment for DRL AMTD Policies.

Provides standard step(), reset(), and action/observation space interfaces.
Integrates Copy-on-Write (CoW) delta memory restoration for sub-second resets.
"""

from __future__ import annotations
import dataclasses
import enum
from typing import Any, Dict, List, Optional, Tuple

from adam.policy.drl.encoder import AttentionEventEncoder
from adam.policy.drl.reward import QualityAwareRewardShaper, ExecutionMilestone
from adam.sandbox.vmi.ept_controller import EPTController
from adam.sandbox.vmi.syscall_virtualizer import SyscallVirtualizer
from adam.sandbox.vmi.kernel_polymorphism import KernelPolymorphismEngine, MitigationState


class ActionType(enum.IntEnum):
    NOOP = 0
    RANDOMIZE_SYSCALLS = 1
    SHUFFLE_KERNEL_MEMORY = 2
    TOGGLE_SPECTRE_MITIGATION = 3
    TOGGLE_MELTDOWN_MITIGATION = 4
    ACTIVATE_EPT_SHADOW_HOOK = 5
    TRIGGER_USER_SIMULATION = 6
    ROTATE_SYNTHETIC_DECOYS = 7
    ENABLE_C2_SINKHOLE = 8


class SandboxGymEnv:
    """Gymnasium-compatible Reinforcement Learning Environment for the Autonomous Sandbox."""

    def __init__(
        self,
        max_steps_per_episode: int = 50,
        embedding_dim: int = 16,
    ) -> None:
        self.max_steps = max_steps_per_episode
        self.embedding_dim = embedding_dim
        self.current_step = 0

        # Subsystems
        self.encoder = AttentionEventEncoder(embedding_dim=embedding_dim)
        self.reward_shaper = QualityAwareRewardShaper()
        self.ept_controller = EPTController(vm_id="gym_env_vm")
        self.syscall_virtualizer = SyscallVirtualizer()
        self.kernel_poly = KernelPolymorphismEngine()

        self.action_space_size = len(ActionType)
        self.observation_dim = embedding_dim

        # Simulated event log buffer
        self._buffered_events: List[Dict[str, Any]] = []

    def reset(self, seed: Optional[int] = None) -> Tuple[List[float], Dict[str, Any]]:
        """Sub-second state restoration using CoW memory delta rollback."""
        self.current_step = 0
        self.reward_shaper.reset()
        self._buffered_events.clear()

        # Discard dirty pages and restore base EPT view
        cow_result = self.ept_controller.restore_cow_delta()

        # Re-seed baseline observation
        initial_event = {
            "type": "PROCESS_CREATE",
            "pid": 4096,
            "target": "malware_sample.exe",
            "severity": 0.5,
            "timestamp_ns": 0,
        }
        self._buffered_events.append(initial_event)
        obs = self.encoder.compute_attention_embedding(self._buffered_events)

        info = {
            "reset_type": "COW_MEMORY_DELTA_RESET",
            "reverted_pages": cow_result.get("reverted_pages", 0),
            "step": 0,
        }
        return obs, info

    def step(self, action_int: int) -> Tuple[List[float], float, bool, bool, Dict[str, Any]]:
        """Execute one decision step within the sandbox environment."""
        self.current_step += 1
        action = ActionType(action_int % self.action_space_size)

        applied = False
        action_details: Dict[str, Any] = {"action": action.name}
        new_behaviors: List[str] = []
        new_iocs: List[str] = []

        # Execute selected AMTD action
        if action == ActionType.RANDOMIZE_SYSCALLS:
            remap = self.syscall_virtualizer.randomize_syscall_indices()
            applied = True
            action_details["syscall_count"] = len(remap)
            new_behaviors.append(f"SSDT_RANDOMIZED_{len(remap)}")

        elif action == ActionType.SHUFFLE_KERNEL_MEMORY:
            res = self.kernel_poly.shuffle_kernel_memory_layout(entropy_seed=self.current_step * 31)
            applied = (res.get("status") == "COMMITTED")
            new_behaviors.append("KERNEL_STACK_SHUFFLED")

        elif action == ActionType.TOGGLE_SPECTRE_MITIGATION:
            res = self.kernel_poly.toggle_mitigation_atomically(
                "CVE-2017-5715", MitigationState.ENABLED, tx_id=f"tx_gym_{self.current_step}"
            )
            applied = (res.get("status") == "COMMITTED")
            new_behaviors.append("SPECTRE_MITIGATION_TOGGLED")

        elif action == ActionType.TOGGLE_MELTDOWN_MITIGATION:
            res = self.kernel_poly.toggle_mitigation_atomically(
                "CVE-2017-5754", MitigationState.ENABLED, tx_id=f"tx_gym_{self.current_step}"
            )
            applied = (res.get("status") == "COMMITTED")
            new_behaviors.append("MELTDOWN_MITIGATION_TOGGLED")

        elif action == ActionType.ACTIVATE_EPT_SHADOW_HOOK:
            gfn = 0x1000 + self.current_step
            self.ept_controller.shadow_page_for_execution_trap(gfn, gfn + 0x50, "hook_nt_alloc")
            applied = True
            new_behaviors.append("EPT_SHADOW_TRAP_ARMED")

        elif action == ActionType.ENABLE_C2_SINKHOLE:
            applied = True
            new_iocs.append(f"c2-sinkholed-domain-{self.current_step}.org")
            self.reward_shaper.record_milestone(ExecutionMilestone.C2_BEACON_TRANSMIT)

        # Milestone progression simulation
        if self.current_step == 2:
            self.reward_shaper.record_milestone(ExecutionMilestone.PROCESS_CREATION)
        elif self.current_step == 5:
            self.reward_shaper.record_milestone(ExecutionMilestone.MEMORY_INJECTION)
        elif self.current_step == 10:
            self.reward_shaper.record_milestone(ExecutionMilestone.PAYLOAD_DECRYPTION)
            new_iocs.append(f"sha256_unpacked_stage_{self.current_step}")

        # Ingest simulated event into telemetry buffer
        sim_event = {
            "type": "EPT_TRAP" if action == ActionType.ACTIVATE_EPT_SHADOW_HOOK else "SYSCALL_DISPATCH",
            "pid": 4096,
            "target": f"target_addr_{self.current_step}",
            "severity": 0.7,
            "timestamp_ns": self.current_step * 1000000,
        }
        self._buffered_events.append(sim_event)

        # Compute next state embedding observation
        next_obs = self.encoder.compute_attention_embedding(self._buffered_events)

        # Calculate reward
        reward_breakdown = self.reward_shaper.compute_step_reward(
            new_behaviors=new_behaviors,
            new_iocs=new_iocs,
            mutation_applied=applied,
            guest_crashed=False,
            malware_dormant=False,
        )

        terminated = (self.current_step >= self.max_steps)
        truncated = False

        info = {
            "action_executed": action.name,
            "reward_breakdown": dataclasses.asdict(reward_breakdown),
            "step": self.current_step,
            "milestones": [m.value for m in self.reward_shaper.achieved_milestones],
        }

        return next_obs, reward_breakdown.total_reward, terminated, truncated, info
