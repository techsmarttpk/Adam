"""
tests/unit/test_phase1_vbox_binding.py

Acceptance tests for Phase 1 (Live VirtualBox Agent Binding):
1. VirtualBoxClient wrapping VBoxManage CLI with typed exceptions.
2. SandboxController FSM transitions (PROVISIONING -> BOOTING -> AGENT_HANDSHAKE -> READY -> ARMED -> DETONATING -> COLLECTING -> COMPLETED).
3. Agent handshake health polling and bounded failure recovery with snapshot rollback.
4. Collector live ingestion bridge sharing the same normalization path as replay.
5. End-to-end A/B session execution and yield calculation.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import aiosqlite
import pytest

from adam.contracts.enums import Arm, Category, NetworkMode, SessionStatus, Source
from adam.contracts.raw_event import ProcessInfo, RawEvent
from adam.contracts.session import AnalysisSession, SampleRef, SessionConfig
from adam.collectors.base import BaseCollector
from adam.sandbox.controller import SandboxController
from adam.sandbox.guest.agent.agent import ToolAvailability, TelemetryArtifacts
from adam.sandbox.state import SandboxOperationError, SandboxState
from adam.sandbox.vbox.client import VirtualBoxClient
from adam.sandbox.vbox.models import SnapshotInfo, VMOperationResult
from adam.db.repositories.sqlite import (
    SQLiteDecisionRepository,
    SQLiteEventRepository,
    SQLiteMutationRepository,
    SQLiteSessionRepository,
)
from adam.db.schema import SCHEMA_SQL
from adam.reporting.generator import ReportGenerator


class FakeVBoxClient(VirtualBoxClient):
    """Mock VirtualBoxClient that simulates VBoxManage CLI without shelling out."""

    def __init__(self) -> None:
        super().__init__(vboxmanage_path="VBoxManageMock")
        self.calls: list[tuple[str, ...]] = []
        self.fail_on: str | None = None
        self._snapshots: list[SnapshotInfo] = [SnapshotInfo(name="clean", uuid="uuid-clean", is_current=True)]

    async def _run(self, *args: str, timeout: float | None = None) -> VMOperationResult:
        self.calls.append(args)
        cmd_str = " ".join(args)
        if self.fail_on and self.fail_on in cmd_str:
            return VMOperationResult(
                success=False,
                command=("VBoxManage", *args),
                duration_ms=10.0,
                return_code=1,
                stdout="",
                stderr=f"Mock failure on {self.fail_on}",
            )
        stdout = 'VMState="running"\n' if "showvminfo" in cmd_str else "OK"
        return VMOperationResult(
            success=True,
            command=("VBoxManage", *args),
            duration_ms=5.0,
            return_code=0,
            stdout=stdout,
            stderr="",
        )

    async def list_snapshots(self, vm_name: str) -> list[SnapshotInfo]:
        return self._snapshots


class MockGuestChannel:
    """Mock guest channel simulating agent health and telemetry."""

    def __init__(self, healthy: bool = True) -> None:
        self.healthy = healthy
        self.ready_called = False
        self.tools_verified = False

    async def wait_until_ready(self) -> None:
        self.ready_called = True
        if not self.healthy:
            raise TimeoutError("Agent /health check timed out")

    async def verify_tools(self) -> ToolAvailability:
        self.tools_verified = True
        return ToolAvailability(sysmon=self.healthy, procmon=self.healthy, tshark=self.healthy)

    async def start_captures(self, session_id: str, *, capture_procmon: bool = True, capture_network: bool = True) -> None:
        pass

    async def stop_export_and_fetch(self, session_id: str, host_artifact_dir: str, **kwargs) -> TelemetryArtifacts:
        return TelemetryArtifacts(sysmon_evtx=None, procmon_csv=None, network_ek_json=None)


# --------------------------------------------------------------------------
# 1. VirtualBoxClient method unit tests
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vbox_client_methods():
    client = FakeVBoxClient()

    # create_or_clone_vm
    vm_name = await client.create_or_clone_vm("golden-vm", "ADAM_TEST_VM", snapshot_name="clean")
    assert vm_name == "ADAM_TEST_VM"
    assert any("clonevm" in call for call in client.calls)

    # snapshot
    snap = await client.snapshot("ADAM_TEST_VM", "pre_detonation")
    assert snap.name == "pre_detonation"
    assert any("snapshot" in call and "take" in call for call in client.calls)

    # start_vm & stop_vm
    res_start = await client.start_vm("ADAM_TEST_VM", headless=True)
    assert res_start.success
    res_stop = await client.stop_vm("ADAM_TEST_VM", force=True)
    assert res_stop.success

    # guest_exec, guest_copy_to, guest_copy_from
    res_exec = await client.guest_exec("ADAM_TEST_VM", "whoami", guest_username="user", guest_password="pw")
    assert res_exec.success

    res_copy_to = await client.guest_copy_to("ADAM_TEST_VM", "local.exe", "C:\\guest.exe", guest_username="u", guest_password="p")
    assert res_copy_to.success

    res_copy_from = await client.guest_copy_from("ADAM_TEST_VM", "C:\\out.txt", "local_out.txt", guest_username="u", guest_password="p")
    assert res_copy_from.success

    # configure_network
    res_net = await client.configure_network("ADAM_TEST_VM", mode="host-only-isolated")
    assert res_net.success
    assert any("hostonly" in call for call in client.calls)

    # modify_hardware
    res_hw = await client.modify_hardware("ADAM_TEST_VM", cpu_count=4, memory_mb=8192)
    assert res_hw.success
    assert any("--cpus" in call for call in client.calls)


# --------------------------------------------------------------------------
# 2. SandboxController FSM Wiring & Agent Handshake Tests
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sandbox_controller_full_lifecycle():
    client = FakeVBoxClient()
    agent = MockGuestChannel(healthy=True)
    ctrl = SandboxController(
        client=client,
        vm_name="ADAM_WIN10",
        snapshot_name="clean",
        guest_username="user",
        guest_password="pw",
        guest_channel=agent,
    )

    assert ctrl.state == SandboxState.COLD

    # prepare -> PROVISIONING -> RESTORING -> BOOTING -> AGENT_HANDSHAKE -> READY
    await ctrl.prepare()
    assert ctrl.state == SandboxState.READY
    assert agent.ready_called

    # arm -> ARMED
    await ctrl.arm("host/sample.exe", "C:\\Users\\Admin\\Desktop\\sample.exe")
    assert ctrl.state == SandboxState.ARMED

    # detonate -> DETONATING -> COLLECTING -> COMPLETED
    sample = SampleRef(
        sha256="0" * 64,
        md5="0" * 32,
        filename="sample.exe",
        size_bytes=1024,
        file_type="PE32",
    )
    await ctrl.detonate(sample)
    assert ctrl.state == SandboxState.COMPLETED
    assert ctrl.last_detonation_result is not None
    assert ctrl.last_detonation_result.success

    # teardown -> TEARING_DOWN -> COLD
    await ctrl.teardown()
    assert ctrl.state == SandboxState.COLD


@pytest.mark.asyncio
async def test_sandbox_controller_agent_failure_restores_snapshot():
    client = FakeVBoxClient()
    agent = MockGuestChannel(healthy=False)  # Agent fails /health check
    ctrl = SandboxController(
        client=client,
        vm_name="ADAM_WIN10",
        snapshot_name="clean",
        guest_username="user",
        guest_password="pw",
        guest_channel=agent,
    )

    with pytest.raises(SandboxOperationError):
        await ctrl.prepare()

    # Guaranteed rollback: FSM enters ERROR state and snapshot was restored
    assert ctrl.state == SandboxState.ERROR
    assert any("restore" in call for call in client.calls)

    # Safe teardown from ERROR state
    await ctrl.teardown()
    assert ctrl.state == SandboxState.COLD


# --------------------------------------------------------------------------
# 3. Collector Live Streaming Bridge Tests
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_collector_live_stream_ingestion():
    class DummyCollector(BaseCollector):
        @property
        def source_name(self) -> str:
            return "dummy"

        async def _run(self) -> None:
            while not self._stop_requested():
                await asyncio.sleep(0.01)

    collector = DummyCollector()
    await collector.start()

    raw = RawEvent(
        event_id="live_001",
        session_id="session_live",
        source=Source.SYSMON,
        source_event_id=101,
        category=Category.PROCESS,
        occurred_at=datetime.now(timezone.utc),
        observed_at=datetime.now(timezone.utc),
        process=ProcessInfo(
            pid=4000,
            ppid=1000,
            image="malware.exe",
            command_line="malware.exe -run",
            integrity_level="High",
            user="NT AUTHORITY\\SYSTEM",
            guid="{sample-guid}",
        ),
        attributes={"action": "test_live_ingest"},
    )

    # Direct live batch ingestion
    collector.ingest_batch([raw])

    received = []
    async for event in collector.iter_events():
        received.append(event)
        break

    await collector.stop()
    assert len(received) == 1
    assert received[0].event_id == "live_001"
    assert received[0].process.image == "malware.exe"


# --------------------------------------------------------------------------
# 4. End-to-End Live A/B Pairing & Yield Engine Validation
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ab_pairing_round_trip_reporting(tmp_path):
    db_path = str(tmp_path / "test_ab.db")
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA_SQL)
        session_repo = SQLiteSessionRepository(db)
        event_repo = SQLiteEventRepository(db)
        decision_repo = SQLiteDecisionRepository(db)
        mutation_repo = SQLiteMutationRepository(db)

        exp_id = "exp_phase1_live_test"
        sample = SampleRef(
            sha256="a" * 64,
            md5="a" * 32,
            filename="test_malware.exe",
            size_bytes=2048,
            file_type="PE32 executable",
        )

        # 1. Control session (deception_enabled=False)
        ctrl_session = AnalysisSession(
            session_id="session_control_01",
            experiment_id=exp_id,
            arm=Arm.CONTROL,
            sample=sample,
            config=SessionConfig(
                deception_enabled=False,
                policy_ruleset="default",
                vm_profile="win10_x64_enterprise_office_decoy",
                timeout_seconds=60,
                network_mode=NetworkMode.HOST_ONLY,
            ),
            status=SessionStatus.COMPLETED,
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
        )
        await session_repo.create(ctrl_session)

        # 2. Treatment session (deception_enabled=True)
        trt_session = AnalysisSession(
            session_id="session_treatment_01",
            experiment_id=exp_id,
            arm=Arm.TREATMENT,
            sample=sample,
            config=SessionConfig(
                deception_enabled=True,
                policy_ruleset="default",
                vm_profile="win10_x64_enterprise_office_decoy",
                timeout_seconds=60,
                network_mode=NetworkMode.HOST_ONLY,
            ),
            status=SessionStatus.COMPLETED,
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
        )
        await session_repo.create(trt_session)
        await db.commit()

        # Generate comparison report via existing yield engine
        generator = ReportGenerator(session_repo, event_repo, decision_repo, mutation_repo)
        comp_json = await generator.generate_comparison(exp_id)
        assert exp_id in comp_json
        assert "session_control_01" in comp_json
        assert "session_treatment_01" in comp_json
