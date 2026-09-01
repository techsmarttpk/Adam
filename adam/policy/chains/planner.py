"""Deception Chain Planner and Multi-Step Stateful Lure Orchestrator.

Enables multi-step sequential deception trees:
e.g. RECON_DOMAIN_CONTROLLER -> SPAWN_FAKE_DC -> FAKE_LDAP_RESPONSE -> MOUNT_FAKE_SHARE -> PLANT_CANARY_DOCUMENTS

Prevents endless recursion with maximum sequence depth and cycle detection.
"""

from __future__ import annotations
import dataclasses
from typing import Dict, List, Optional, Set, Tuple


@dataclasses.dataclass
class DeceptionChainNode:
    step_index: int
    trigger_intent: str
    action_to_apply: str
    expected_followup_intent: str
    description: str


@dataclasses.dataclass
class ActiveChainState:
    chain_name: str
    current_step_index: int
    max_steps: int
    completed_actions: List[str]
    is_completed: bool = False
    is_broken: bool = False


class DeceptionChainPlanner:
    """Manages multi-step sequential deception strategies."""

    BUILTIN_CHAINS = {
        "DOMAIN_LATERAL_TRAP": [
            DeceptionChainNode(
                step_index=0,
                trigger_intent="RECON_DOMAIN_CONTROLLER",
                action_to_apply="SPAWN_FAKE_DC_ARTIFACTS",
                expected_followup_intent="LATERAL_SMB_ENUM",
                description="Synthesize fake Domain Controller to draw lateral movement attempts.",
            ),
            DeceptionChainNode(
                step_index=1,
                trigger_intent="LATERAL_SMB_ENUM",
                action_to_apply="MOUNT_FAKE_NETWORK_SHARE",
                expected_followup_intent="CRED_CONFIG_FILE_HARVEST",
                description="Mount simulated network share with accessible permissions.",
            ),
            DeceptionChainNode(
                step_index=2,
                trigger_intent="CRED_CONFIG_FILE_HARVEST",
                action_to_apply="PLANT_DECOY_DOCUMENTS",
                expected_followup_intent="C2_BEACON",
                description="Plant honeypot financial files and canary tokens in mounted share.",
            ),
        ]
    }

    def __init__(self) -> None:
        self.active_chains: Dict[str, ActiveChainState] = {}

    def get_next_chain_action(self, current_intent: str) -> Optional[Tuple[str, str]]:
        """Checks if current intent progresses an active chain or starts a new multi-step chain.

        Returns (chain_name, action_to_apply) or None.
        """
        # Check active chains for advancement
        for chain_name, chain_state in list(self.active_chains.items()):
            if chain_state.is_completed or chain_state.is_broken:
                continue

            nodes = self.BUILTIN_CHAINS.get(chain_name, [])
            curr_idx = chain_state.current_step_index

            if curr_idx < len(nodes):
                expected_node = nodes[curr_idx]
                if expected_node.trigger_intent == current_intent:
                    chain_state.completed_actions.append(expected_node.action_to_apply)
                    chain_state.current_step_index += 1
                    if chain_state.current_step_index >= len(nodes):
                        chain_state.is_completed = True
                    return (chain_name, expected_node.action_to_apply)

        # Check if current intent can initiate a new chain
        for chain_name, nodes in self.BUILTIN_CHAINS.items():
            if nodes and nodes[0].trigger_intent == current_intent:
                self.active_chains[chain_name] = ActiveChainState(
                    chain_name=chain_name,
                    current_step_index=1,
                    max_steps=len(nodes),
                    completed_actions=[nodes[0].action_to_apply],
                    is_completed=(len(nodes) == 1),
                )
                return (chain_name, nodes[0].action_to_apply)

        return None
