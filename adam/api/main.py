"""
adam/api/main.py
FastAPI backend for ADAM Live Pipeline.
"""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from typing import Dict, List, Any
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, File, BackgroundTasks
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import hashlib
import random
from datetime import datetime, timezone

from adam.contracts.semantic_event import SemanticEvent, Actor, AttckRef
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult
from adam.contracts.envelope import Envelope
from adam.contracts.raw_event import RawEvent
from adam.pipeline.live import LiveOrchestrator
from adam.contracts.session import AnalysisSession, SampleRef, SessionConfig, SessionMetrics
from adam.contracts.enums import Arm, NetworkMode, SessionStatus, Verdict
from adam.fusion.log_generate import generate_attack_chain, generate_benign_events
from adam.fusion.engine import EventFusionEngine
from adam.policy.engine import PolicyEngine
from adam.policy.context import SessionContext
from adam.deception.engine import DeceptionEngine
from tests.unit.test_deception.test_engine import FakeGuestChannel
from demo.run_simulation import map_detection_to_intent

BASE_DIR = Path(__file__).resolve().parent.parent.parent
RULES_PATH = BASE_DIR / "rules" / "default"

# In-memory store for sessions
sessions_store: Dict[str, Any] = {}

# SSE Queues for connected clients
clients: List[asyncio.Queue] = []

orchestrator: LiveOrchestrator = None  # type: ignore

async def store_event(envelope: Envelope):
    sess_id = envelope.session_id
    if sess_id not in sessions_store:
        sessions_store[sess_id] = {"metadata": None, "events": [], "decisions": [], "mutations": []}
    
    msg_type = envelope.message_type
    payload_dict = envelope.payload.model_dump()
    payload_json = envelope.payload.model_dump_json()
    
    if msg_type == "SemanticEvent":
        sessions_store[sess_id]["events"].append(payload_dict)
    elif msg_type == "PolicyDecision":
        sessions_store[sess_id]["decisions"].append(payload_dict)
    elif msg_type == "MutationResult":
        sessions_store[sess_id]["mutations"].append(payload_dict)
        
    # Update metrics if metadata exists
    metadata = sessions_store[sess_id].get("metadata")
    if metadata:
        if msg_type == "SemanticEvent":
            metadata.metrics.semantic_events += 1
        elif msg_type == "PolicyDecision":
            metadata.metrics.decisions_total += 1
            if payload_dict.get("verdict") == "EXECUTE":
                metadata.metrics.decisions_executed += 1
        elif msg_type == "MutationResult":
            metadata.metrics.mutations_applied += 1
        
    # Broadcast to SSE
    sse_msg = f"event: {msg_type}\ndata: {payload_json}\n\n"
    for q in clients:
        await q.put(sse_msg)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # We initialize the dependencies from deps.py
    from adam.api.deps import init_dependencies, shutdown_dependencies, deps
    
    await init_dependencies()
    
    deps.bus.subscribe(SemanticEvent, store_event, name="api_events")
    deps.bus.subscribe(PolicyDecision, store_event, name="api_decisions")
    deps.bus.subscribe(MutationResult, store_event, name="api_mutations")
    
    yield
    
    await shutdown_dependencies()

app = FastAPI(title="ADAM Live API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/v1/sessions")
async def get_sessions():
    return {"sessions": list(sessions_store.keys())}

@app.get("/api/v1/sessions/{session_id}")
async def get_session(session_id: str):
    return sessions_store.get(session_id, {})

@app.get("/api/v1/sessions/{session_id}/events")
async def get_session_events(session_id: str):
    return sessions_store.get(session_id, {}).get("events", [])

@app.get("/api/v1/sessions/{session_id}/decisions")
async def get_session_decisions(session_id: str):
    return sessions_store.get(session_id, {}).get("decisions", [])

@app.get("/api/v1/sessions/{session_id}/mutations")
async def get_session_mutations(session_id: str):
    return sessions_store.get(session_id, {}).get("mutations", [])

from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

@app.get("/api/v1/sessions/{session_id}/report")
async def get_session_report(session_id: str, format: str = "json"):
    from adam.api.deps import deps
    if not deps.report_generator:
        return JSONResponse(content={"error": "Report generator not initialized"}, status_code=500)
    try:
        report = await deps.report_generator.generate(session_id, format)
        if format == "html":
            return HTMLResponse(content=report)
        elif format == "md":
            return PlainTextResponse(content=report, media_type="text/markdown")
        else:
            return JSONResponse(content=json.loads(report))
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=404)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

@app.get("/api/v1/experiments/{experiment_id}/comparison")
async def get_experiment_comparison(experiment_id: str):
    from adam.api.deps import deps
    if not deps.report_generator:
        return JSONResponse(content={"error": "Report generator not initialized"}, status_code=500)
    try:
        report = await deps.report_generator.generate_comparison(experiment_id)
        return JSONResponse(content=json.loads(report))
    except ValueError as e:
        return JSONResponse(content={"error": str(e)}, status_code=404)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

async def run_deterministic_simulation(session_id: str, seed: int):
    from adam.api.deps import deps
    import uuid
    metadata: AnalysisSession = sessions_store[session_id]["metadata"]
    
    # 1. Generate events deterministically
    random.seed(seed)
    start_time = datetime(2026, 8, 5, 9, 0, 0, tzinfo=timezone.utc)
    attack_events = []
    attack_events.extend(generate_attack_chain("WKSTN-666", "j.smith", start_time))
    benign_events = generate_benign_events(200, start_time)
    all_events = benign_events + attack_events
    all_events.sort(key=lambda x: datetime.fromisoformat(x["timestamp"].replace("Z", "+00:00")))
    
    metadata.metrics.raw_events = len(all_events)
    
    # 2. Publish as Envelope[RawEvent]
    for ev in all_events:
        try:
            ts = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
        except:
            ts = datetime.now(timezone.utc)
            
        from adam.contracts.raw_event import ProcessInfo
        
        proc = ProcessInfo(
            pid=ev.get("pid", 1000),
            ppid=ev.get("ppid", 1000),
            image=ev.get("image_path", f"C:\\Windows\\System32\\{ev.get('process_name', 'unknown.exe')}"),
            command_line=ev.get("command_line", ""),
            integrity_level="High",
            user=ev.get("user", "System"),
            guid=f"{{guid-{uuid.uuid4().hex[:8]}}}"
        )
        
        raw_event = RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:8]}",
            session_id=session_id,
            source="SYSMON",
            source_event_id=1,
            category="PROCESS",
            occurred_at=ts,
            observed_at=datetime.now(timezone.utc),
            process=proc,
            attributes=ev
        )
        
        env = Envelope[RawEvent](
            envelope_version="1.0",
            message_id=str(uuid.uuid4()),
            message_type="RawEvent",
            session_id=session_id,
            correlation_id=f"corr_{uuid.uuid4().hex[:8]}",
            emitted_at=datetime.now(timezone.utc),
            emitter="sim",
            payload=raw_event
        )
        await deps.bus.publish(env)
        await asyncio.sleep(0.01) # space out events
                
    # Mark as completed
    metadata.status = SessionStatus.COMPLETED
    metadata.ended_at = datetime.now(timezone.utc)
    await deps.session_repo.update(metadata)
    
    await deps.bus.publish(Envelope[dict](
        envelope_version="1.0",
        message_id=str(uuid.uuid4()),
        message_type="SessionCompleted",
        session_id=session_id,
        correlation_id=session_id,
        emitted_at=datetime.now(timezone.utc),
        emitter="Orchestrator",
        payload={}
    ))


@app.post("/api/v1/sessions/simulate")
async def simulate_session(
    background_tasks: BackgroundTasks, 
    file: UploadFile = File(...),
    deception_enabled: bool = True,
    experiment_id: str = None
):
    content = await file.read()
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    
    seed = int(sha256[:16], 16)
    import uuid
    session_id = f"sim_{uuid.uuid4().hex[:8]}"
    
    sample = SampleRef(
        sha256=sha256,
        md5=md5,
        filename=file.filename or "unknown",
        size_bytes=len(content),
        file_type="binary"
    )
    config = SessionConfig(
        deception_enabled=deception_enabled,
        policy_ruleset="default",
        vm_profile="windows-10",
        timeout_seconds=300,
        network_mode=NetworkMode.SIMULATED
    )
    metadata = AnalysisSession(
        session_id=session_id,
        experiment_id=experiment_id or "exp_demo_01",
        arm=Arm.TREATMENT if deception_enabled else Arm.CONTROL,
        sample=sample,
        config=config,
        status=SessionStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
        metrics=SessionMetrics()
    )
    
    sessions_store[session_id] = {
        "metadata": metadata,
        "events": [],
        "decisions": [],
        "mutations": []
    }
    
    from adam.api.deps import deps
    import asyncio
    
    async def create_and_run():
        await deps.session_repo.create(metadata)
        await run_deterministic_simulation(session_id, seed)

    background_tasks.add_task(create_and_run)
    return {"session_id": session_id, "status": "RUNNING"}

@app.post("/api/v1/experiments/run")
async def run_experiment(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    # Read file once
    content = await file.read()
    import uuid
    experiment_id = f"exp_{uuid.uuid4().hex[:8]}"
    
    # We will simulate the CONTROL session
    class MockFile:
        def __init__(self, filename, content):
            self.filename = filename
            self.content = content
        async def read(self):
            return self.content
            
    mock_file = MockFile(file.filename, content)
    
    # Create CONTROL session
    ctrl_res = await simulate_session(
        background_tasks, mock_file, deception_enabled=False, experiment_id=experiment_id
    )
    
    # Create TREATMENT session
    trt_res = await simulate_session(
        background_tasks, mock_file, deception_enabled=True, experiment_id=experiment_id
    )
    
    return {
        "experiment_id": experiment_id,
        "control_session": ctrl_res["session_id"],
        "treatment_session": trt_res["session_id"]
    }

@app.get("/api/v1/stream")
async def sse_stream(request: Request):
    q = asyncio.Queue()
    clients.append(q)
    
    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                msg = await q.get()
                yield msg
        finally:
            if q in clients:
                clients.remove(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

from adam.dashboard.router import dashboard_router
app.include_router(dashboard_router)
app.mount("/dashboard/static", StaticFiles(directory=Path(__file__).parent.parent / "dashboard" / "static"), name="static")
