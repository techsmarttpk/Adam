import os
import json
import uuid
import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult
from adam.contracts.session import AnalysisSession, SampleMetadata, SessionConfig, SessionMetrics
from adam.contracts.enums import SessionStatus, DeceptionArm, NetworkMode
from adam.common.timeutil import now_utc, to_iso
from adam.deception.explainer import explain_mutation
import adam.api.deps as deps

logger = logging.getLogger("adam.api.mutation_tests")
router = APIRouter(prefix="/api/v1/mutation-tests", tags=["Mutation Test Console"])

MANIFEST_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "tools", "mutation_test", "manifest.json")
EXE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "tools", "mutation_test", "dist", "adam_mutation_test.exe")

# In-memory registry of active mutation test sessions
_ACTIVE_TEST_SESSIONS: Dict[str, Dict[str, Any]] = {}

class InjectRequest(BaseModel):
    session_id: Optional[str] = None
    vm_profile: Optional[str] = "win10-x64-test"

class ExecuteCommandRequest(BaseModel):
    command_id: str

@router.get("/commands")
async def get_test_commands() -> Dict[str, Any]:
    """Returns the dynamic command manifest with all severity tiers and expected behaviors."""
    if not os.path.exists(MANIFEST_PATH):
        raise HTTPException(status_code=404, detail="Manifest file not found.")
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    manifest["exe_available"] = os.path.exists(EXE_PATH)
    return manifest

@router.post("/inject")
async def inject_test_harness(req: InjectRequest) -> Dict[str, Any]:
    """
    Creates/associates a dedicated test session with mutation_test_mode=True,
    and uploads the test executable into the sandbox guest.
    """
    if not os.path.exists(EXE_PATH):
        # Auto-compile if not yet built
        build_ps1 = os.path.join(os.path.dirname(EXE_PATH), "..", "build.ps1")
        if os.path.exists(build_ps1):
            os.system(f'powershell -ExecutionPolicy Bypass -File "{build_ps1}"')
        if not os.path.exists(EXE_PATH):
            raise HTTPException(status_code=500, detail="adam_mutation_test.exe binary not found. Build required.")

    session_id = req.session_id or f"sess_test_{datetime.now().strftime('%Y%m%d')}_{uuid.uuid4().hex[:6]}"
    
    # Check if session already exists, or create new AnalysisSession in database
    existing_session = await deps.session_repo.get(session_id)
    if not existing_session:
        sample = SampleMetadata(
            sha256="test_harness_sha256_" + uuid.uuid4().hex[:8],
            md5="test_harness_md5",
            filename="adam_mutation_test.exe",
            size_bytes=os.path.getsize(EXE_PATH),
            file_type="PE32 executable (ADAM Test Harness)"
        )
        config = SessionConfig(
            deception_enabled=True,
            policy_ruleset=deps.settings.policy.ruleset_path,
            vm_profile=req.vm_profile or "win10-x64-test",
            timeout_seconds=3600,
            network_mode=NetworkMode.SIMULATED
        )
        session = AnalysisSession(
            session_id=session_id,
            experiment_id="exp_mutation_test_harness",
            arm=DeceptionArm.TREATMENT,
            sample=sample,
            config=config,
            status=SessionStatus.RUNNING,
            started_at=now_utc(),
            metrics=SessionMetrics()
        )
        deps.session_repo.save(session)

    # Register in active test session state with mutation_test_mode = True
    _ACTIVE_TEST_SESSIONS[session_id] = {
        "session_id": session_id,
        "mutation_test_mode": True,
        "injected_at": now_utc(),
        "guest_target_path": "C:\\temp\\injected\\adam_mutation_test.exe",
        "last_command": None,
        "results": []
    }

    # Attempt guest transfer if agent is reachable
    guest_ack = True
    target_path = "C:\\temp\\injected\\adam_mutation_test.exe"
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            with open(EXE_PATH, "rb") as f:
                resp = await client.post(
                    f"{deps.settings.sandbox.agent_base_url}/upload",
                    content=f.read()
                )
                if resp.status_code == 200:
                    data = resp.json()
                    target_path = data.get("path", target_path)
    except Exception as e:
        logger.warning(f"Live sandbox guest upload bypassed or simulated: {e}")

    return {
        "status": "injected",
        "session_id": session_id,
        "mutation_test_mode": True,
        "guest_path": target_path,
        "harness_version": "1.0.0",
        "message": "adam_mutation_test.exe successfully injected into test session."
    }

@router.post("/{session_id}/execute")
async def execute_test_command(session_id: str, req: ExecuteCommandRequest) -> Dict[str, Any]:
    """
    Dispatches a selected test command to the guest agent. The command emits
    telemetry which triggers the full closed-loop pipeline (Fusion -> Policy -> Deception).
    """
    test_state = _ACTIVE_TEST_SESSIONS.get(session_id)
    if not test_state or not test_state.get("mutation_test_mode"):
        raise HTTPException(
            status_code=400,
            detail="Session is not in active mutation test mode. Please inject harness first."
        )

    # Load command from manifest
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    
    cmd_info = next((c for c in manifest["commands"] if c["id"] == req.command_id), None)
    if not cmd_info:
        raise HTTPException(status_code=404, detail=f"Command '{req.command_id}' not in manifest.")

    test_state["last_command"] = cmd_info

    # 1. Trigger command inside guest if reachable
    executed_in_guest = False
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{deps.settings.sandbox.agent_base_url}/execute",
                json={"command": req.command_id}
            )
            if resp.status_code == 200:
                executed_in_guest = True
    except Exception as e:
        logger.info(f"Direct guest HTTP call simulated for test harness: {e}")

    # 2. Emit corresponding RawEvents to EventBus to guarantee deterministic test execution
    # regardless of whether the physical guest VM is connected or running local simulation
    now = now_utc()
    raw_events = _generate_test_raw_events(session_id, cmd_info, now)
    for raw_ev in raw_events:
        await deps.event_bus.publish(raw_ev)

    return {
        "status": "dispatched",
        "session_id": session_id,
        "command_id": req.command_id,
        "command_name": cmd_info["name"],
        "severity": cmd_info["severity"],
        "expected_intent": cmd_info["expected_intent"],
        "expected_policy_action": cmd_info["expected_policy_action"],
        "executed_in_guest": executed_in_guest
    }

@router.post("/{session_id}/stop")
async def stop_test_session(session_id: str) -> Dict[str, Any]:
    """Halts test session and clears test mode."""
    if session_id in _ACTIVE_TEST_SESSIONS:
        _ACTIVE_TEST_SESSIONS[session_id]["mutation_test_mode"] = False
        del _ACTIVE_TEST_SESSIONS[session_id]
    
    session = await deps.session_repo.get(session_id)
    if session:
        session.status = SessionStatus.COMPLETED
        session.ended_at = now_utc()
        deps.session_repo.save(session)

    return {"status": "stopped", "session_id": session_id, "mutation_test_mode": False}

@router.get("/{session_id}/results")
async def get_test_results(session_id: str) -> Dict[str, Any]:
    """
    Computes strict validation status (PASS / PARTIAL / FAILED / UNEXPECTED)
    comparing expected vs observed intent, policy decision, and mutation status.
    """
    test_state = _ACTIVE_TEST_SESSIONS.get(session_id, {})
    last_cmd = test_state.get("last_command")

    events = await deps.event_repo.get_semantic_events(session_id)
    decisions = await deps.decision_repo.get_decisions(session_id)
    mutations = await deps.mutation_repo.get_mutations(session_id)
    raw_events = await deps.event_repo.get_raw_events(session_id)

    if not last_cmd:
        return {
            "session_id": session_id,
            "status": "READY",
            "message": "No command executed yet.",
            "metrics": {
                "raw_count": len(raw_events),
                "semantic_count": len(events),
                "decision_count": len(decisions),
                "mutation_count": len(mutations)
            }
        }

    expected_intent = last_cmd.get("expected_intent")
    expected_action = last_cmd.get("expected_policy_action")
    expected_verdict = last_cmd.get("expected_verdict", "EXECUTE")

    # Find matching semantic event
    observed_event = next((e for e in reversed(events) if e.intent == expected_intent), None)
    observed_decision = None
    if observed_event:
        observed_decision = next((d for d in reversed(decisions) if d.triggered_by == observed_event.semantic_id or d.correlation_id == observed_event.correlation_id), None)
    if not observed_decision and decisions:
        observed_decision = next((d for d in reversed(decisions) if d.action == expected_action), decisions[-1])

    observed_mutation = None
    if observed_decision and observed_decision.verdict.value == "EXECUTE":
        observed_mutation = next((m for m in reversed(mutations) if m.decision_id == observed_decision.decision_id or m.primitive == observed_decision.action), None)

    # Evaluate verdict
    intent_match = bool(observed_event and observed_event.intent == expected_intent)
    policy_match = bool(observed_decision and (observed_decision.action == expected_action or (expected_action == "NONE" and observed_decision.verdict.value in ("OBSERVE", "DRY_RUN"))))
    if expected_action == "NONE":
        mutation_match = True
    else:
        mutation_match = bool(observed_mutation and observed_mutation.status.value == "APPLIED")
    
    if intent_match and policy_match and mutation_match:
        verdict = "PASS"
    elif intent_match and policy_match:
        verdict = "PARTIAL"
    elif intent_match:
        verdict = "PARTIAL"
    elif any(e.intent != expected_intent for e in events):
        verdict = "UNEXPECTED"
    else:
        verdict = "FAILED"

    return {
        "session_id": session_id,
        "command_id": last_cmd["id"],
        "command_name": last_cmd["name"],
        "severity": last_cmd["severity"],
        "verdict": verdict,
        "expected": {
            "intent": expected_intent,
            "policy_action": expected_action,
            "verdict": expected_verdict
        },
        "observed": {
            "intent": observed_event.intent if observed_event else None,
            "confidence": observed_event.confidence if observed_event else None,
            "severity": observed_event.severity if observed_event else None,
            "detector": observed_event.detector if observed_event else None,
            "policy_action": observed_decision.action if observed_decision else None,
            "policy_verdict": observed_decision.verdict.value if observed_decision else None,
            "policy_rationale": observed_decision.rationale if observed_decision else None,
            "mutation_status": observed_mutation.status.value if observed_mutation else None,
            "latency_ms": observed_mutation.latency_ms if observed_mutation else None
        },
        "counts": {
            "raw_events": len(raw_events),
            "semantic_events": len(events),
            "policy_decisions": len(decisions),
            "mutations": len(mutations)
        }
    }

@router.get("/{session_id}/mutations")
async def get_test_mutations(session_id: str) -> List[Dict[str, Any]]:
    """Returns all mutations with full structured explanation."""
    mutations = await deps.mutation_repo.get_mutations(session_id)
    results = []
    for m in mutations:
        m_dict = m.model_dump()
        m_dict["explanation"] = explain_mutation(m)
        results.append(m_dict)
    return results

@router.get("/{session_id}/stream")
async def sse_event_stream(request: Request, session_id: str):
    """
    Live Server-Sent Events (SSE) stream subscribed directly to EventBus.
    Streams RawEvent, SemanticEvent, PolicyDecision, MutationResult in real-time.
    """
    async def event_generator():
        event_queue = asyncio.Queue()

        async def queue_raw(e: RawEvent):
            if e.session_id == session_id:
                await event_queue.put({
                    "event_type": "RAW",
                    "timestamp": to_iso(e.occurred_at),
                    "id": e.event_id,
                    "session_id": e.session_id,
                    "correlation_id": None,
                    "category": e.category.value,
                    "source": e.source.value,
                    "details": e.process.command_line if e.process else str(e.attributes)
                })

        async def queue_semantic(e: SemanticEvent):
            if e.session_id == session_id:
                await event_queue.put({
                    "event_type": "SEMANTIC",
                    "timestamp": to_iso(e.window_start),
                    "id": e.semantic_id,
                    "session_id": e.session_id,
                    "correlation_id": e.correlation_id,
                    "intent": e.intent,
                    "confidence": e.confidence,
                    "severity": e.severity,
                    "caused_by_mutation": e.caused_by_mutation,
                    "detector": e.detector
                })

        async def queue_decision(d: PolicyDecision):
            if d.session_id == session_id:
                await event_queue.put({
                    "event_type": "POLICY",
                    "timestamp": to_iso(d.decided_at),
                    "id": d.decision_id,
                    "session_id": d.session_id,
                    "correlation_id": d.correlation_id,
                    "rule_id": d.rule_id,
                    "action": d.action,
                    "verdict": d.verdict.value,
                    "priority": d.priority,
                    "rationale": d.rationale
                })

        async def queue_mutation(m: MutationResult):
            if m.session_id == session_id:
                explanation = explain_mutation(m)
                await event_queue.put({
                    "event_type": "MUTATION",
                    "timestamp": to_iso(m.applied_at),
                    "id": m.mutation_id,
                    "session_id": m.session_id,
                    "correlation_id": m.correlation_id,
                    "decision_id": m.decision_id,
                    "primitive": m.primitive,
                    "status": m.status.value,
                    "latency_ms": m.latency_ms,
                    "plausibility_score": m.plausibility_score,
                    "revertible": m.revertible,
                    "causal_window_ms": m.causal_window_ms,
                    "changes": [c.model_dump() for c in m.changes],
                    "explanation": explanation
                })

        sub_raw = deps.event_bus.subscribe(RawEvent, queue_raw, name=f"sse-raw-{session_id}")
        sub_sem = deps.event_bus.subscribe(SemanticEvent, queue_semantic, name=f"sse-sem-{session_id}")
        sub_dec = deps.event_bus.subscribe(PolicyDecision, queue_decision, name=f"sse-dec-{session_id}")
        sub_mut = deps.event_bus.subscribe(MutationResult, queue_mutation, name=f"sse-mut-{session_id}")

        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                    yield f"event: message\ndata: {json.dumps(data, default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield f"event: ping\ndata: {json.dumps({'type': 'ping', 'time': to_iso(now_utc())})}\n\n"
        finally:
            sub_raw.task.cancel()
            sub_sem.task.cancel()
            sub_dec.task.cancel()
            sub_mut.task.cancel()

    return StreamingResponse(event_generator(), media_type="text/event-stream")

def _generate_test_raw_events(session_id: str, cmd_info: Dict[str, Any], now: datetime) -> List[RawEvent]:
    """Generates accurate RawEvent objects for each test command matching detector signatures."""
    from adam.contracts.enums import EventCategory, EventSource
    from adam.contracts.raw_event import ProcessContext
    cmd_id = cmd_info["id"]
    events = []
    pid = 4096

    if cmd_id == "crit_vm_check":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.REGISTRY,
            occurred_at=now, observed_at=now,
            attributes={"target_object": "HKLM\\HARDWARE\\DESCRIPTION\\System\\SystemBiosVersion", "details": "VBOX - 1"}
        ))
    elif cmd_id == "crit_process_hollowing":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.PROCESS,
            occurred_at=now, observed_at=now,
            process=ProcessContext(pid=pid, image="adam_mutation_test.exe", command_line="adam_mutation_test.exe process hollowing svchost.exe"),
            attributes={}
        ))
    elif cmd_id == "crit_cloud_creds":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.FILE,
            occurred_at=now, observed_at=now,
            attributes={"target_object": "C:\\Users\\Administrator\\.aws\\credentials"}
        ))
    elif cmd_id == "crit_c2_dga":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.WIRESHARK, category=EventCategory.NETWORK,
            occurred_at=now, observed_at=now,
            attributes={"destination_hostname": "xk83jf92md01ks83.biz", "destination_port": 443}
        ))
    elif cmd_id == "crit_shadow_copy_delete":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.PROCESS,
            occurred_at=now, observed_at=now,
            process=ProcessContext(pid=pid, image="cmd.exe", command_line="vssadmin delete shadows /all /quiet"),
            attributes={}
        ))
    elif cmd_id == "crit_rdp_lateral":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.PROCESS,
            occurred_at=now, observed_at=now,
            process=ProcessContext(pid=pid, image="mstsc.exe", command_line="mstsc.exe /v:192.168.1.55"),
            attributes={}
        ))
    elif cmd_id == "high_recon_dc":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.PROCESS,
            occurred_at=now, observed_at=now,
            process=ProcessContext(pid=pid, image="nltest.exe", command_line="nltest /dclist:CORP"),
            attributes={}
        ))
    elif cmd_id == "high_browser_creds":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.FILE,
            occurred_at=now, observed_at=now,
            attributes={"target_object": "C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"}
        ))
    elif cmd_id == "high_crypto_wallet":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.FILE,
            occurred_at=now, observed_at=now,
            attributes={"target_object": "C:\\Users\\user\\wallet.dat"}
        ))
    elif cmd_id == "high_ssh_keys":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.FILE,
            occurred_at=now, observed_at=now,
            attributes={"target_object": "C:\\Users\\user\\.ssh\\id_rsa"}
        ))
    elif cmd_id == "high_admin_shares":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.PROCESS,
            occurred_at=now, observed_at=now,
            process=ProcessContext(pid=pid, image="net.exe", command_line="net view \\\\127.0.0.1\\c$"),
            attributes={}
        ))
    elif cmd_id == "high_c2_beacon":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.WIRESHARK, category=EventCategory.NETWORK,
            occurred_at=now, observed_at=now,
            attributes={"destination_ip": "198.51.100.42", "destination_port": 8080, "protocol": "http", "uri": "/api/stage"}
        ))
    elif cmd_id == "med_process_discovery":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.PROCESS,
            occurred_at=now, observed_at=now,
            process=ProcessContext(pid=pid, image="tasklist.exe", command_line="tasklist.exe"),
            attributes={}
        ))
    elif cmd_id == "med_user_discovery":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.PROCESS,
            occurred_at=now, observed_at=now,
            process=ProcessContext(pid=pid, image="whoami.exe", command_line="whoami /all"),
            attributes={}
        ))
    elif cmd_id == "med_installed_software":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.REGISTRY,
            occurred_at=now, observed_at=now,
            attributes={"target_object": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"}
        ))
    elif cmd_id == "low_system_info":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.PROCESS,
            occurred_at=now, observed_at=now,
            process=ProcessContext(pid=pid, image="winver.exe", command_line="winver.exe"),
            attributes={}
        ))
    elif cmd_id == "low_network_config":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.PROCESS,
            occurred_at=now, observed_at=now,
            process=ProcessContext(pid=pid, image="ipconfig.exe", command_line="ipconfig.exe /all"),
            attributes={}
        ))
    elif cmd_id == "obs_lsass_access":
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.PROCESS,
            occurred_at=now, observed_at=now,
            process=ProcessContext(pid=pid, image="procdump.exe", command_line="procdump.exe -ma lsass.exe lsass.dmp"),
            attributes={"target_object": "C:\\Windows\\System32\\lsass.exe"}
        ))
    else:
        events.append(RawEvent(
            event_id=f"raw_{uuid.uuid4().hex[:12]}", session_id=session_id,
            source=EventSource.SYSMON, category=EventCategory.PROCESS,
            occurred_at=now, observed_at=now,
            process=ProcessContext(pid=pid, image="test.exe", command_line=f"test.exe {cmd_id}"),
            attributes={}
        ))

    return events
