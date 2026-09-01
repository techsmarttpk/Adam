import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone

from adam.api.main import app
import adam.api.deps as deps
from adam.contracts.enums import PolicyVerdict

@pytest.mark.asyncio
async def test_mutation_test_harness_api_flow():
    # Setup test transport with live dependencies
    await deps.db_conn.connect()
    await deps.db_writer.start()
    await deps.event_bus.start()
    from adam.api.main import live_pipeline, agent_collector
    await live_pipeline.start()
    await agent_collector.start()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Fetch commands
        res_cmd = await client.get("/api/v1/mutation-tests/commands")
        assert res_cmd.status_code == 200
        cmd_data = res_cmd.json()
        assert "commands" in cmd_data
        assert len(cmd_data["commands"]) > 0

        # 2. Inject test session
        test_session_id = f"sess_api_test_{int(datetime.now().timestamp())}"
        res_inj = await client.post(
            "/api/v1/mutation-tests/inject",
            json={"session_id": test_session_id}
        )
        assert res_inj.status_code == 200
        inj_data = res_inj.json()
        assert inj_data["mutation_test_mode"] is True
        assert inj_data["session_id"] == test_session_id

        # 3. Execute test stimulus command: high_recon_dc
        res_exec = await client.post(
            f"/api/v1/mutation-tests/{test_session_id}/execute",
            json={"command_id": "high_recon_dc"}
        )
        assert res_exec.status_code == 200
        exec_data = res_exec.json()
        assert exec_data["status"] == "dispatched"
        assert exec_data["expected_intent"] == "RECON_DOMAIN_CONTROLLER"

        # Drain bus to allow full closed loop to complete
        await deps.event_bus.drain(timeout=2.0)
        await asyncio.sleep(0.5)

        # 4. Check validation results
        res_results = await client.get(f"/api/v1/mutation-tests/{test_session_id}/results")
        assert res_results.status_code == 200
        results_data = res_results.json()
        assert results_data["session_id"] == test_session_id
        assert results_data["verdict"] in ("PASS", "PARTIAL")
        assert results_data["observed"]["intent"] == "RECON_DOMAIN_CONTROLLER"

        # 5. Check mutations endpoint
        res_mut = await client.get(f"/api/v1/mutation-tests/{test_session_id}/mutations")
        assert res_mut.status_code == 200
        mut_list = res_mut.json()
        assert len(mut_list) >= 1
        assert mut_list[0]["primitive"] == "SPAWN_FAKE_DC_ARTIFACTS"
        assert "explanation" in mut_list[0]
        assert "Domain Controller" in mut_list[0]["explanation"]["artifacts"]

        # 6. Stop test session
        res_stop = await client.post(f"/api/v1/mutation-tests/{test_session_id}/stop")
        assert res_stop.status_code == 200
        assert res_stop.json()["status"] == "stopped"

    await live_pipeline.stop()
    await agent_collector.stop()
    await deps.event_bus.stop()
    await deps.db_writer.stop()
    await deps.db_conn.disconnect()
