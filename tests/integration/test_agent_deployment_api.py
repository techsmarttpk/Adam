import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch, MagicMock
from adam.api.main import app
import adam.api.deps as deps

@pytest.mark.asyncio
async def test_agent_deployment_api_status_and_deploy():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Test GET /api/v1/agent/status
        with patch.object(deps.agent_deployment_manager, "get_status", new_callable=AsyncMock) as mock_status:
            mock_status.return_value = {
                "sync_status": "CURRENT",
                "host": {"version": "1.4.7", "sha256": "abcdef123456"},
                "guest": {"reachable": True, "version": "1.4.7", "sha256": "abcdef123456", "status": "alive"}
            }
            res = await client.get("/api/v1/agent/status")
            assert res.status_code == 200
            data = res.json()
            assert data["sync_status"] == "CURRENT"
            assert data["host"]["version"] == "1.4.7"

        # 2. Test POST /api/v1/agent/deploy
        with patch.object(deps.agent_deployment_manager, "deploy_agent", new_callable=AsyncMock) as mock_deploy:
            mock_deploy.return_value = {
                "status": "SUCCESS",
                "message": "Guest agent successfully updated and verified.",
                "duration_seconds": 1.25,
                "host_sha256": "abcdef123456",
                "guest_sha256": "abcdef123456"
            }
            res_deploy = await client.post("/api/v1/agent/deploy", json={"session_id": "sess_continuous_live"})
            assert res_deploy.status_code == 200
            deploy_data = res_deploy.json()
            assert deploy_data["status"] == "SUCCESS"
