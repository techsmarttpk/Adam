import httpx
import asyncio

from adam.api.main import app
from adam.api.deps import init_dependencies, shutdown_dependencies

async def test_ab():
    await init_dependencies()
    
    from adam.api.main import store_event
    from adam.contracts.semantic_event import SemanticEvent
    from adam.contracts.policy_decision import PolicyDecision
    from adam.contracts.mutation import MutationResult
    from adam.api.deps import deps
    
    deps.bus.subscribe(SemanticEvent, store_event, name="api_events_test")
    deps.bus.subscribe(PolicyDecision, store_event, name="api_decisions_test")
    deps.bus.subscribe(MutationResult, store_event, name="api_mutations_test")
    
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            with open("demo.raw.jsonl", "rb") as f:
                print("Running experiment...")
                resp = await client.post("/api/v1/experiments/run", files={"file": ("demo.raw.jsonl", f, "application/json")})
                
            print("Experiment run response:", resp.status_code, resp.text)
            if resp.status_code != 200:
                return
                
            data = resp.json()
            exp_id = data["experiment_id"]
            ctrl_id = data["control_session"]
            trt_id = data["treatment_session"]
            
            # Give it a second to process
            await asyncio.sleep(2.0)
            
            print("\nFetching CONTROL session events...")
            c_resp_ev = await client.get(f"/api/v1/sessions/{ctrl_id}/events")
            events = c_resp_ev.json()
            print(f"CONTROL events: {len(events)}")
            
            print("\nFetching CONTROL session mutations...")
            c_resp = await client.get(f"/api/v1/sessions/{ctrl_id}/mutations")
            mutations = c_resp.json()
            print(f"CONTROL mutations: {len(mutations)}")
            
            r_ctrl_dec = await client.get(f"/api/v1/sessions/{ctrl_id}/decisions")
            decisions_c = r_ctrl_dec.json()
            print(f"CONTROL decisions: {len(decisions_c)}")
            if len(decisions_c) > 0:
                print(f"Sample CONTROL decision: {decisions_c[0]}")

            print("\nFetching TREATMENT session mutations...")
            r_trt = await client.get(f"/api/v1/sessions/{trt_id}/mutations")
            mutations_t = r_trt.json()
            print(f"TREATMENT mutations: {len(mutations_t)}")

            r_trt_dec = await client.get(f"/api/v1/sessions/{trt_id}/decisions")
            decisions_t = r_trt_dec.json()
            print(f"TREATMENT decisions: {len(decisions_t)}")
            if len(decisions_t) > 0:
                print(f"Sample TREATMENT decision: {decisions_t[0]}")
            
            print("\nFetching comparison...")
            comp_resp = await client.get(f"/api/v1/experiments/{exp_id}/comparison")
            print("Comparison result:", comp_resp.json())
    finally:
        await shutdown_dependencies()

if __name__ == "__main__":
    asyncio.run(test_ab())
