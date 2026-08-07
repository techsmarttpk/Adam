"""
tests/integration/test_live_pipeline.py
Tests the LiveOrchestrator and LiveFusionBridge end-to-end.
"""

import asyncio
import os
import uuid
from pathlib import Path
from datetime import datetime, timezone

import pytest
from adam.pipeline.live import LiveOrchestrator
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.raw_event import RawEvent, ProcessInfo
from adam.contracts.envelope import Envelope
from adam.contracts.enums import Source, Category
from adam.common.bus import EventBus

BASE_DIR = Path(__file__).resolve().parent.parent.parent
RULES_PATH = BASE_DIR / "rules" / "default"

@pytest.mark.asyncio
async def test_live_orchestrator_initialization(tmp_path):
    sysmon_file = tmp_path / "sysmon.evtx"
    sysmon_file.touch()
    
    orchestrator = LiveOrchestrator(
        sysmon_path=str(sysmon_file),
        procmon_path="",
        network_path="",
        rules_path=str(RULES_PATH)
    )
    
    assert orchestrator.sysmon is not None
    assert orchestrator.procmon is None
    assert orchestrator.network is None
    
    await orchestrator.start()
    await asyncio.sleep(0.1)
    await orchestrator.stop()


@pytest.mark.asyncio
async def test_live_fusion_bridge():
    bus = EventBus()
    from adam.pipeline.live import LiveFusionBridge
    bridge = LiveFusionBridge(bus, "test_session")
    
    raw = RawEvent(
        event_id="test_ev_001",
        session_id="test_session",
        source=Source.SYSMON,
        source_event_id=1,
        category=Category.PROCESS,
        occurred_at=datetime.now(timezone.utc),
        observed_at=datetime.now(timezone.utc),
        process=ProcessInfo(
            pid=1234,
            ppid=1,
            image="cmd.exe",
            command_line="cmd.exe /c whoami",
            integrity_level="Medium",
            user="TEST\\user",
            guid="{test-guid}"
        ),
        attributes={"command_line": "cmd.exe /c whoami"}
    )
    env = Envelope[RawEvent](
        message_id=str(uuid.uuid4()),
        message_type="RawEvent",
        session_id="test_session",
        correlation_id=str(uuid.uuid4()),
        emitted_at=datetime.now(timezone.utc),
        emitter="sysmon",
        payload=raw
    )
    
    received = []
    async def handler(e: Envelope[SemanticEvent]):
        received.append(e)
    
    bus.subscribe(SemanticEvent, handler, name="test_sub")
    await bus.start()
    
    await bridge.handle_raw_event(env)
    assert len(bridge.buffer) == 1
    
    await bridge.flush()
    assert len(bridge.buffer) == 0
    
    await asyncio.sleep(0.1)
    await bus.drain(0.5)
