"""Unit tests for Deep Reinforcement Learning (DRL) Orchestration Layer."""

import pytest
from adam.policy.drl.encoder import AttentionEventEncoder, TelemetryFilter
from adam.policy.drl.reward import QualityAwareRewardShaper, ExecutionMilestone
from adam.policy.drl.gym_env import SandboxGymEnv, ActionType
from adam.policy.drl.dual_stream import DualStreamPolicy


def test_telemetry_filter_event_deduplication():
    filt = TelemetryFilter(window_size=10)
    # Burst of 100 identical events
    for _ in range(100):
        filt.ingest_event("REG_QUERY", 1000, "HKLM\\Software", 0.1, 1000)

    window = filt.get_window_tokens()
    # Should collapse into 1 token with repeat_count = 100
    assert len(window) == 1
    assert window[0].repeat_count == 100


def test_attention_encoder_output_dimensions():
    encoder = AttentionEventEncoder(embedding_dim=16)
    events = [
        {"type": "PROCESS_CREATE", "pid": 100, "target": "cmd.exe", "severity": 0.5, "timestamp_ns": 100},
        {"type": "MEM_INJECT_RWX", "pid": 100, "target": "0x40000", "severity": 0.9, "timestamp_ns": 200},
    ]
    emb = encoder.compute_attention_embedding(events)
    assert len(emb) == 16
    assert any(v != 0.0 for v in emb)


def test_quality_aware_reward_shaper_milestones_and_penalties():
    shaper = QualityAwareRewardShaper()

    # Step 1: Discover new behavior without milestone
    r1 = shaper.compute_step_reward(
        new_behaviors=["PROCESS_CREATED"],
        new_iocs=[],
        mutation_applied=True,
    )
    assert r1.novelty_component > 0
    assert r1.total_reward > 0

    # Step 2: Unlock milestone & IOC
    shaper.record_milestone(ExecutionMilestone.PAYLOAD_DECRYPTION)
    r2 = shaper.compute_step_reward(
        new_behaviors=["UNPACKED_STAGE2"],
        new_iocs=["192.168.1.100"],
        mutation_applied=True,
    )
    assert r2.disclosure_component == 15.0
    assert r2.milestone_bonus > 0


def test_sandbox_gym_env_step_and_cow_reset():
    env = SandboxGymEnv(max_steps_per_episode=10, embedding_dim=16)
    obs, info = env.reset()
    assert len(obs) == 16
    assert info["reset_type"] == "COW_MEMORY_DELTA_RESET"

    # Step action
    next_obs, reward, terminated, truncated, step_info = env.step(int(ActionType.RANDOMIZE_SYSCALLS))
    assert len(next_obs) == 16
    assert step_info["action_executed"] == "RANDOMIZE_SYSCALLS"
    assert step_info["step"] == 1
    assert not terminated


def test_dual_stream_policy_arbitration():
    policy = DualStreamPolicy(seed=42)
    dummy_state = [0.1] * 16

    # Test strategic selection
    action_strat = policy.select_action(dummy_state, execution_phase="EXECUTION")
    assert action_strat.stream_source == "STRATEGIC_COGNITIVE"

    # Test tactical evasion override
    action_tact = policy.select_action(dummy_state, is_evasion_detected=True)
    assert action_tact.stream_source == "IMMEDIATE_TACTICAL"
    assert action_tact.action_type == ActionType.TRIGGER_USER_SIMULATION
