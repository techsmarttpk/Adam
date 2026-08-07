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

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult
from adam.contracts.envelope import Envelope
from adam.pipeline.live import LiveOrchestrator

BASE_DIR = Path(__file__).resolve().parent.parent.parent
RULES_PATH = BASE_DIR / "rules" / "default"

# In-memory store for sessions
sessions_store: Dict[str, Dict[str, List[Any]]] = {}

# SSE Queues for connected clients
clients: List[asyncio.Queue] = []

orchestrator: LiveOrchestrator = None  # type: ignore

@asynccontextmanager
async def lifespan(app: FastAPI):
    global orchestrator
    
    sysmon_path = os.getenv("SYSMON_PATH", r"C:\VM_Logs\sysmon.evtx")
    procmon_path = os.getenv("PROCMON_PATH", r"C:\VM_Logs\procmon.csv")
    network_path = os.getenv("NETWORK_PATH", r"C:\VM_Logs\network.ek")
    
    # Touch files if they don't exist to avoid OS errors in file-tailing
    for path in [sysmon_path, procmon_path, network_path]:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if not os.path.exists(path):
                with open(path, "w") as f:
                    pass
        except Exception:
            pass

    orchestrator = LiveOrchestrator(
        sysmon_path=sysmon_path,
        procmon_path=procmon_path,
        network_path=network_path,
        rules_path=str(RULES_PATH)
    )
    
    # Subscribe to bus to populate store & SSE
    async def store_event(envelope: Envelope):
        sess_id = envelope.session_id
        if sess_id not in sessions_store:
            sessions_store[sess_id] = {"events": [], "decisions": [], "mutations": []}
        
        msg_type = envelope.message_type
        payload_dict = envelope.payload.model_dump()
        payload_json = envelope.payload.model_dump_json()
        
        if msg_type == "SemanticEvent":
            sessions_store[sess_id]["events"].append(payload_dict)
        elif msg_type == "PolicyDecision":
            sessions_store[sess_id]["decisions"].append(payload_dict)
        elif msg_type == "MutationResult":
            sessions_store[sess_id]["mutations"].append(payload_dict)
            
        # Broadcast to SSE
        sse_msg = f"event: {msg_type}\ndata: {payload_json}\n\n"
        for q in clients:
            await q.put(sse_msg)

    orchestrator.bus.subscribe(SemanticEvent, store_event, name="api_events")
    orchestrator.bus.subscribe(PolicyDecision, store_event, name="api_decisions")
    orchestrator.bus.subscribe(MutationResult, store_event, name="api_mutations")
    
    await orchestrator.start()
    yield
    await orchestrator.stop()

app = FastAPI(title="ADAM Live API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/sessions")
async def get_sessions():
    return {"sessions": list(sessions_store.keys())}

@app.get("/sessions/{session_id}/events")
async def get_session_events(session_id: str):
    return sessions_store.get(session_id, {}).get("events", [])

@app.get("/sessions/{session_id}/decisions")
async def get_session_decisions(session_id: str):
    return sessions_store.get(session_id, {}).get("decisions", [])

@app.get("/sessions/{session_id}/mutations")
async def get_session_mutations(session_id: str):
    return sessions_store.get(session_id, {}).get("mutations", [])

@app.get("/stream")
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
