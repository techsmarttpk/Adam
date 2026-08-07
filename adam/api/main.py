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
from fastapi.middleware.cors import CORSMiddleware
import hashlib
import random
from datetime import datetime, timezone

from adam.contracts.semantic_event import SemanticEvent, Actor, AttckRef
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult
from adam.contracts.envelope import Envelope
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    global orchestrator
    
    enable_live = os.getenv("ENABLE_LIVE_COLLECTORS", "0") == "1"
    
    if enable_live:
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
    else:
        sysmon_path = ""
        procmon_path = ""
        network_path = ""

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

@app.get("/sessions/{session_id}")
async def get_session(session_id: str):
    return sessions_store.get(session_id, {})

@app.get("/sessions/{session_id}/events")
async def get_session_events(session_id: str):
    return sessions_store.get(session_id, {}).get("events", [])

@app.get("/sessions/{session_id}/decisions")
async def get_session_decisions(session_id: str):
    return sessions_store.get(session_id, {}).get("decisions", [])

@app.get("/sessions/{session_id}/mutations")
async def get_session_mutations(session_id: str):
    return sessions_store.get(session_id, {}).get("mutations", [])

async def run_deterministic_simulation(session_id: str, seed: int):
    metadata: AnalysisSession = sessions_store[session_id]["metadata"]
    
    # 1. Generate events deterministically
    random.seed(seed)
    start_time = datetime(2026, 8, 5, 9, 0, 0, tzinfo=timezone.utc)
    attack_events = []
    # Using one attack host to keep it simple but identical to demo
    attack_events.extend(generate_attack_chain("WKSTN-666", "j.smith", start_time))
    benign_events = generate_benign_events(200, start_time)
    all_events = benign_events + attack_events
    random.shuffle(all_events)
    
    metadata.metrics.raw_events = len(all_events)
    
    # 2. Convert to list of RawEvent for Fusion Engine
    from adam.fusion.models import RawEvent as FusionRawEvent
    fusion_telemetry = []
    for ev in all_events:
        try:
            ts = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
        except:
            ts = datetime.now(timezone.utc)
        fusion_telemetry.append(FusionRawEvent(
            timestamp=ts,
            source="sim",
            event_type=ev.get("event_type", "unknown"),
            process_id=ev.get("pid"),
            parent_process_id=ev.get("ppid"),
            process_name=ev.get("process_name"),
            command_line=ev.get("command_line"),
            payload=ev
        ))
    
    # 3. Setup engines
    fusion_engine = EventFusionEngine()
    policy_engine = PolicyEngine(str(RULES_PATH))
    deception_engine = DeceptionEngine(FakeGuestChannel())
    session_context = SessionContext(session_id=session_id)
    
    # 4. Process Fusion
    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        fusion_result = fusion_engine.process(fusion_telemetry)
    
    semantic_events = []
    for idx, detection in enumerate(fusion_result.detections, start=1):
        intent, tactic, technique = map_detection_to_intent(detection)
        first_ev = detection.evidence[0] if detection.evidence else None
        pid = first_ev.process_id if (first_ev and first_ev.process_id) else 1000
        pname = first_ev.process_name if (first_ev and first_ev.process_name) else "unknown.exe"

        ts = detection.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        features = {"file_count": len(detection.evidence), "has_target": True}
        if intent == "RECON_DOMAIN_CONTROLLER":
            features["ldap_attempts"] = 3
            features["all_failed"] = True
        elif intent == "PERSIST_RUN_KEY":
            features["distinct_registry_keys"] = 6

        se = SemanticEvent(
            semantic_id=f"sem_{seed}_{idx:03d}",
            session_id=session_id,
            correlation_id=f"corr_{seed}_{idx:03d}",
            intent=intent,
            confidence=detection.confidence,
            severity=detection.severity,
            window_start=ts,
            window_end=ts,
            actor=Actor(pid=pid, image=f"C:\\Windows\\System32\\{pname}", guid=f"{{guid-{seed}-{idx:04d}}}"),
            evidence=[ev.process_name for ev in detection.evidence if ev.process_name],
            attck=AttckRef(tactic=tactic, technique=technique),
            detector=f"{detection.category}Detector@1.0",
            features=features,
        )
        semantic_events.append(se)

    # 5. Process Policy and Deception
    import uuid
    for event in semantic_events:
        env = Envelope[SemanticEvent](
            message_id=str(uuid.uuid4()),
            message_type="SemanticEvent",
            session_id=session_id,
            correlation_id=event.correlation_id,
            emitted_at=datetime.now(timezone.utc),
            emitter="LiveFusionBridge",
            payload=event
        )
        await orchestrator.bus.publish(env)
        await asyncio.sleep(0.01) # small delay for sse clients
        
        decisions = policy_engine.evaluate(event, session_context)
        for decision in decisions:
            d_env = Envelope[PolicyDecision](
                message_id=str(uuid.uuid4()),
                message_type="PolicyDecision",
                session_id=session_id,
                correlation_id=event.correlation_id,
                emitted_at=datetime.now(timezone.utc),
                emitter="PolicyEngine",
                payload=decision
            )
            await orchestrator.bus.publish(d_env)
            await asyncio.sleep(0.01)
            
            if decision.verdict == Verdict.EXECUTE:
                mutation_result = await deception_engine.execute_async(decision)
                m_env = Envelope[MutationResult](
                    message_id=str(uuid.uuid4()),
                    message_type="MutationResult",
                    session_id=session_id,
                    correlation_id=event.correlation_id,
                    emitted_at=datetime.now(timezone.utc),
                    emitter="DeceptionEngine",
                    payload=mutation_result
                )
                await orchestrator.bus.publish(m_env)
                await asyncio.sleep(0.01)
                
    metadata.status = SessionStatus.COMPLETED
    metadata.ended_at = datetime.now(timezone.utc)
    # Broadcast session completion event
    await orchestrator.bus.publish(Envelope[SemanticEvent](
        message_id=str(uuid.uuid4()),
        message_type="SessionCompleted",
        session_id=session_id,
        correlation_id=session_id,
        emitted_at=datetime.now(timezone.utc),
        emitter="Orchestrator",
        payload=semantic_events[0] if semantic_events else None # dummy payload
    ))


@app.post("/sessions/simulate")
async def simulate_session(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
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
        deception_enabled=True,
        policy_ruleset="default",
        vm_profile="windows-10",
        timeout_seconds=300,
        network_mode=NetworkMode.SIMULATED
    )
    metadata = AnalysisSession(
        session_id=session_id,
        experiment_id="exp_demo_01",
        arm=Arm.TREATMENT,
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
    
    background_tasks.add_task(run_deterministic_simulation, session_id, seed)
    return {"session_id": session_id, "status": "RUNNING"}

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
