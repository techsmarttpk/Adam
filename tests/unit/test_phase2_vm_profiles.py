"""
tests/unit/test_phase2_vm_profiles.py

Acceptance tests for Phase 2 (VM Hardware Profiles):
1. Validation of all profiles in config/vm_profiles/ against VMProfile contract.
2. Hardware profile application modifying CPU, RAM, and isolated network.
3. Pre-session persona lure application invoking deception primitives before detonation.
4. Profile swappability per session via SessionConfig.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from adam.contracts.profile import VMProfile
from adam.contracts.session import AnalysisSession, SampleRef, SessionConfig
from adam.contracts.enums import Arm, NetworkMode, SessionStatus
from adam.sandbox.vbox.profile_applier import (
    load_profile,
    apply_profile_hardware,
    apply_profile_persona,
    PROFILE_DIR,
)
from adam.sandbox.vbox.client import VirtualBoxClient
from adam.sandbox.vbox.models import VMOperationResult


class MockVBoxClient(VirtualBoxClient):
    def __init__(self) -> None:
        super().__init__(vboxmanage_path="VBoxManageMock")
        self.calls: list[tuple[str, ...]] = []

    async def _run(self, *args: str, timeout: float | None = None) -> VMOperationResult:
        self.calls.append(args)
        return VMOperationResult(
            success=True,
            command=("VBoxManage", *args),
            duration_ms=2.0,
            return_code=0,
            stdout="OK",
            stderr="",
        )


class MockChannel:
    def __init__(self) -> None:
        self.mutations: list[tuple[str, str, str, object]] = []

    async def apply_mutation(self, kind: str, target: str, operation: str, value: object) -> None:
        self.mutations.append((kind, target, operation, value))


@pytest.mark.asyncio
async def test_vm_profiles_load_and_validate():
    profiles = [
        "win10_x64_enterprise_office_decoy",
        "win10_x64_developer_decoy",
        "win10_x64_bare_control",
    ]

    for p_id in profiles:
        prof = load_profile(p_id)
        assert prof.profile_id == p_id
        assert prof.hardware.cpu_count >= 1
        assert prof.hardware.memory_mb >= 1024
        assert prof.network_mode == "host-only-isolated"
        assert prof.guest_agent.install_path != ""


@pytest.mark.asyncio
async def test_apply_profile_hardware():
    client = MockVBoxClient()
    prof = load_profile("win10_x64_developer_decoy")
    assert prof.hardware.cpu_count == 4
    assert prof.hardware.memory_mb == 8192

    await apply_profile_hardware(client, "ADAM_DEV_VM", prof)

    # Verify hardware configuration commands executed
    cpu_call = any("--cpus" in call and "4" in call for call in client.calls)
    mem_call = any("--memory" in call and "8192" in call for call in client.calls)
    nic_call = any("hostonly" in call for call in client.calls)

    assert cpu_call, "CPU configuration should be applied"
    assert mem_call, "Memory configuration should be applied"
    assert nic_call, "Isolated host-only network should be applied"


@pytest.mark.asyncio
async def test_apply_profile_persona_lures():
    channel = MockChannel()
    prof = load_profile("win10_x64_enterprise_office_decoy")
    assert prof.decoy_persona.fake_user_documents is True
    assert prof.decoy_persona.fake_browser_history is True

    applied = await apply_profile_persona(channel, prof)
    assert "PLANT_DECOY_DOCUMENTS" in applied
    assert "INJECT_FAKE_BROWSER_CREDS" in applied
    assert any(item.startswith("HOSTNAME:") for item in applied)

    # Verify mutation calls reached guest channel
    assert len(channel.mutations) > 0


@pytest.mark.asyncio
async def test_profile_swappable_in_session_config():
    config_office = SessionConfig(
        deception_enabled=True,
        policy_ruleset="default",
        vm_profile="win10_x64_enterprise_office_decoy",
        timeout_seconds=60,
        network_mode=NetworkMode.HOST_ONLY,
    )
    assert config_office.vm_profile == "win10_x64_enterprise_office_decoy"

    config_dev = SessionConfig(
        deception_enabled=True,
        policy_ruleset="default",
        vm_profile="win10_x64_developer_decoy",
        timeout_seconds=60,
        network_mode=NetworkMode.HOST_ONLY,
    )
    assert config_dev.vm_profile == "win10_x64_developer_decoy"
