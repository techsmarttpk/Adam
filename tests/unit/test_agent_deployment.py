import pytest
import os
import hashlib
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from adam.sandbox.agent_deployment import AgentDeploymentManager
from adam.common.config import SandboxSettings

@pytest.fixture
def mock_settings():
    return SandboxSettings(
        hostfwd_port_host=8443,
        boot_timeout_s=10,
        use_virtio_serial=True
    )

@pytest.fixture
def deployment_mgr(mock_settings, tmp_path):
    # Create temporary host agent script
    agent_file = tmp_path / "adam_agent.ps1"
    agent_file.write_text('$agentVersion = "1.4.7"\nWrite-Output "Test Agent"', encoding="utf-8")
    
    mgr = AgentDeploymentManager(mock_settings)
    mgr.source_path = str(agent_file)
    return mgr

def test_calculate_host_hash_and_version(deployment_mgr):
    h = deployment_mgr.calculate_host_hash()
    assert len(h) == 64
    assert deployment_mgr.get_host_version() == "1.4.7"

@pytest.mark.asyncio
async def test_get_status_guest_unreachable(deployment_mgr):
    with patch.object(deployment_mgr, "query_guest_status", new_callable=AsyncMock) as mock_q:
        mock_q.return_value = {"reachable": False, "status": "unreachable", "guest_sha256": ""}
        status = await deployment_mgr.get_status()
        assert status["sync_status"] == "GUEST_UNREACHABLE"
        assert status["host"]["version"] == "1.4.7"

@pytest.mark.asyncio
async def test_ensure_agent_current_skipped_when_matching(deployment_mgr):
    host_hash = deployment_mgr.calculate_host_hash()
    with patch.object(deployment_mgr, "query_guest_status", new_callable=AsyncMock) as mock_q:
        mock_q.return_value = {
            "reachable": True,
            "status": "alive",
            "guest_version": "1.4.7",
            "guest_sha256": host_hash,
            "guest_pid": 1234,
            "guest_instance_count": 1
        }
        res = await deployment_mgr.ensure_agent_current()
        assert res["status"] == "SKIPPED"
        assert res["message"] == "Agent is already current"

@pytest.mark.asyncio
async def test_deployment_workflow_on_hash_mismatch(deployment_mgr):
    host_hash = deployment_mgr.calculate_host_hash()
    old_guest_hash = "old_hash_00000000000000000000000000000000000000000000000000000000"
    
    with patch.object(deployment_mgr, "query_guest_status", new_callable=AsyncMock) as mock_q, \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        
        # Initial query returns mismatch, subsequent query returns updated hash
        mock_q.side_effect = [
            {"reachable": True, "status": "alive", "guest_version": "1.4.6", "guest_sha256": old_guest_hash},
            {"reachable": True, "status": "alive", "guest_version": "1.4.7", "guest_sha256": host_hash}
        ]

        mock_update_resp = MagicMock()
        mock_update_resp.status_code = 200
        mock_update_resp.json.return_value = {"status": "staged", "sha256": host_hash}

        mock_restart_resp = MagicMock()
        mock_restart_resp.status_code = 200
        mock_restart_resp.json.return_value = {"status": "restarting", "pid": 5678}

        mock_post.side_effect = [mock_update_resp, mock_restart_resp]

        res = await deployment_mgr.ensure_agent_current()
        assert res["status"] == "SUCCESS"
        assert res["host_sha256"] == host_hash
        assert res["guest_sha256"] == host_hash
