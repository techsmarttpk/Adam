import os
import uuid
import hashlib
import asyncio
from datetime import datetime
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional

from adam.contracts.session import AnalysisSession, SampleMetadata, SessionConfig, SessionMetrics
from adam.contracts.enums import SessionStatus, DeceptionArm, NetworkMode
from adam.common.timeutil import now_utc
from adam.orchestrator.session import SessionRunner

# Event contracts for type checks in the live telemetry pipeline
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult

import adam.api.deps as deps
from adam.collectors.agent import AgentCollector
from adam.reporting.generator import ReportGenerator
from adam.dashboard.routes import router as dashboard_router
from adam.api.routers.mutation_tests import router as mutation_tests_router
from adam.api.routers.agent import router as agent_router

from fastapi.staticfiles import StaticFiles

app = FastAPI(title="ADAM Orchestrator API", version="1.0")

static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

app.include_router(dashboard_router)
app.include_router(mutation_tests_router)
app.include_router(agent_router)

agent_collector = AgentCollector(deps.event_bus)

class ContinuousLiveSessionPipeline:
    def __init__(self) -> None:
        self.session_id = "sess_continuous_live"
        self.active_mutation_id: Optional[str] = None
        self._subs = []

    async def start(self) -> None:
        await self.stop()
        self._subs.append(deps.event_bus.subscribe(RawEvent, self._handle_raw_event, name="live-raw-to-fusion"))
        self._subs.append(deps.event_bus.subscribe(SemanticEvent, self._handle_semantic_event, name="live-sem-to-policy"))
        self._subs.append(deps.event_bus.subscribe(PolicyDecision, self._handle_decision, name="live-dec-to-deception"))
        self._subs.append(deps.event_bus.subscribe(MutationResult, self._handle_mutation, name="live-mutation-tracker"))

    async def stop(self) -> None:
        for sub in self._subs:
            sub.task.cancel()
        self._subs.clear()

    def _is_active_session(self, sid: str) -> bool:
        if sid == self.session_id:
            return True
        from adam.api.routers.mutation_tests import _ACTIVE_TEST_SESSIONS
        return sid in _ACTIVE_TEST_SESSIONS

    async def _handle_raw_event(self, event: RawEvent) -> None:
        if not self._is_active_session(event.session_id):
            return
        deps.event_repo.save_raw_event(event)
        session = await deps.session_repo.get(event.session_id)
        if session:
            session.metrics.raw_events += 1
            deps.session_repo.update_metrics(event.session_id, session.metrics)
        await deps.fusion_engine.ingest(event)

    async def _handle_semantic_event(self, event: SemanticEvent) -> None:
        if not self._is_active_session(event.session_id):
            return
        deps.event_repo.save_semantic_event(event)
        session = await deps.session_repo.get(event.session_id)
        if session:
            session.metrics.semantic_events += 1
            if self.active_mutation_id:
                session.metrics.semantic_events_post_mutation += 1
            deps.session_repo.update_metrics(event.session_id, session.metrics)
        await deps.policy_engine.evaluate(event)

    async def _handle_decision(self, decision: PolicyDecision) -> None:
        if not self._is_active_session(decision.session_id):
            return
        deps.decision_repo.save(decision)
        session = await deps.session_repo.get(decision.session_id)
        if session:
            session.metrics.decisions_total += 1
            deps.session_repo.update_metrics(decision.session_id, session.metrics)
        # Execute mutation via Deception Engine
        await deps.deception_engine.execute(decision)

    async def _handle_mutation(self, mutation: MutationResult) -> None:
        if not self._is_active_session(mutation.session_id):
            return
        deps.mutation_repo.save(mutation)
        self.active_mutation_id = mutation.mutation_id
        deps.fusion_engine.set_active_mutation(mutation.mutation_id)
        session = await deps.session_repo.get(mutation.session_id)
        if session:
            session.metrics.decisions_executed += 1
            session.metrics.mutations_applied += 1
            deps.session_repo.update_metrics(mutation.session_id, session.metrics)
        
        async def clear_causal_window_later():
            await asyncio.sleep(30.0)
            if self.active_mutation_id == mutation.mutation_id:
                self.active_mutation_id = None
                deps.fusion_engine.set_active_mutation(None)
        asyncio.create_task(clear_causal_window_later())

live_pipeline = ContinuousLiveSessionPipeline()

@app.on_event("startup")
async def startup_event():
    await deps.db_conn.connect()
    await deps.db_writer.start()
    await deps.event_bus.start()
    await agent_collector.start()
    await live_pipeline.start()
    
    # Initialize the permanent live session record
    live_sess = await deps.session_repo.get("sess_continuous_live")
    if not live_sess:
        from adam.contracts.session import AnalysisSession, SampleMetadata, SessionConfig, SessionMetrics
        from adam.contracts.enums import SessionStatus, DeceptionArm, NetworkMode
        from adam.common.timeutil import now_utc
        
        sample = SampleMetadata(
            sha256="continuous_live_sha256",
            md5="continuous_live_md5",
            filename="live_analysis_guest",
            size_bytes=0,
            file_type="LIVE_VM"
        )
        config = SessionConfig(
            deception_enabled=True,
            policy_ruleset=deps.settings.policy.ruleset_path,
            vm_profile="live-virtio-serial",
            timeout_seconds=0,
            network_mode=NetworkMode.SIMULATED
        )
        session = AnalysisSession(
            session_id="sess_continuous_live",
            experiment_id="exp_continuous_live",
            arm=DeceptionArm.TREATMENT,
            sample=sample,
            config=config,
            status=SessionStatus.RUNNING,
            started_at=now_utc(),
            metrics=SessionMetrics()
        )
        deps.session_repo.save(session)
        
    if deps.settings.sandbox.use_virtio_serial:
        await deps.serial_server.start()

@app.on_event("shutdown")
async def shutdown_event():
    if deps.settings.sandbox.use_virtio_serial:
        await deps.serial_server.stop()
    await live_pipeline.stop()
    await agent_collector.stop()
    await deps.event_bus.stop()
    await deps.db_writer.stop()
    await deps.db_conn.disconnect()

class CreateSessionRequest(BaseModel):
    experiment_id: Optional[str] = None
    arm: DeceptionArm = DeceptionArm.TREATMENT
    filename: Optional[str] = None
    sample_path: Optional[str] = None
    size_bytes: Optional[int] = None
    deception_enabled: bool = True
    ruleset: Optional[str] = None
    vm_profile: Optional[str] = "win10-x64-office"
    timeout_seconds: int = 300

async def background_session_worker(session: AnalysisSession, sample_path: str):
    session_run = SessionRunner(
        session=session,
        bus=deps.event_bus,
        sandbox=deps.sandbox_controller,
        fusion=deps.fusion_engine,
        policy=deps.policy_engine,
        deception=deps.deception_engine,
        session_repo=deps.session_repo,
        event_repo=deps.event_repo,
        decision_repo=deps.decision_repo,
        mutation_repo=deps.mutation_repo
    )
    await session_run.run(sample_path)
    
    generator = ReportGenerator(
        deps.session_repo, deps.event_repo, deps.decision_repo, deps.mutation_repo
    )
    await generator.generate_session_report(session.session_id)

@app.post("/api/v1/sessions", status_code=202)
async def create_session(req: CreateSessionRequest, background_tasks: BackgroundTasks):
    session_id = f"sess_{datetime.now().strftime('%Y%m%d')}_{uuid.uuid4().hex[:6]}"
    
    # Resolve target binary sample path
    sample_path = ""
    if req.sample_path and os.path.exists(req.sample_path):
        sample_path = req.sample_path
        filename = os.path.basename(sample_path)
    elif req.filename:
        filename = req.filename
        candidate = os.path.join(deps.settings.sandbox.sample_dir, req.filename)
        if os.path.exists(candidate):
            sample_path = candidate
        elif os.path.exists(req.filename):
            sample_path = req.filename
    else:
        raise HTTPException(
            status_code=400,
            detail="Either valid 'sample_path' or 'filename' must be provided."
        )

    if not sample_path or not os.path.exists(sample_path):
        raise HTTPException(
            status_code=400,
            detail=f"Sample file not found at: {req.sample_path or req.filename}"
        )

    with open(sample_path, "rb") as sample_file:
        sample_bytes = sample_file.read()

    sample = SampleMetadata(
        sha256=hashlib.sha256(sample_bytes).hexdigest(),
        md5=hashlib.md5(sample_bytes).hexdigest(),
        filename=filename,
        size_bytes=os.path.getsize(sample_path),
        file_type="PE32 executable"
    )
    
    ruleset_path = req.ruleset or deps.settings.policy.ruleset_path
    config = SessionConfig(
        deception_enabled=req.deception_enabled,
        policy_ruleset=ruleset_path,
        vm_profile=req.vm_profile or "win10-x64-office",
        timeout_seconds=req.timeout_seconds,
        network_mode=NetworkMode(deps.settings.sandbox.network_mode)
    )
    
    session = AnalysisSession(
        session_id=session_id,
        experiment_id=req.experiment_id or f"exp_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        arm=req.arm,
        sample=sample,
        config=config,
        status=SessionStatus.PENDING,
        started_at=now_utc(),
        metrics=SessionMetrics()
    )
    
    await deps.session_repo.save_immediate(session)
    
    background_tasks.add_task(background_session_worker, session, sample_path)
    
    return {
        "session_id": session_id,
        "status": "scheduled",
        "detail_url": f"/api/v1/sessions/{session_id}"
    }

@app.get("/api/v1/sessions/{session_id}")
async def get_session(session_id: str):
    session = await deps.session_repo.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session

@app.post("/api/v1/sessions/{session_id}/telemetry")
async def push_telemetry(session_id: str, payload: Dict[str, Any]):
    session = await deps.session_repo.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    await agent_collector.ingest_guest_payload(session_id, payload)
    return {"status": "ingested"}

@app.get("/api/v1/experiments/{experiment_id}/comparison")
async def get_comparison(experiment_id: str):
    generator = ReportGenerator(
        deps.session_repo, deps.event_repo, deps.decision_repo, deps.mutation_repo
    )
    report_md = await generator.generate_comparison_report(experiment_id)
    return {"experiment_id": experiment_id, "comparison_markdown": report_md}

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "hypervisor": deps.settings.sandbox.hypervisor,
        "database": deps.settings.db.path
    }
