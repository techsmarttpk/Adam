import os
import json
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from adam.common.timeutil import parse_iso
import adam.api.deps as deps

router = APIRouter()

templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard", "templates")
templates = Jinja2Templates(directory=templates_dir)

@router.get("/", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    conn = await deps.db_conn.connect()
    async with conn.execute(
        """
        SELECT s.session_id, s.experiment_id, s.arm, s.status, s.started_at, s.sample_filename, s.sample_sha256,
               m.raw_events, m.semantic_events, m.decisions_total, m.decisions_executed, m.mutations_applied, m.semantic_events_post_mutation
        FROM sessions s
        LEFT JOIN session_metrics m ON s.session_id = m.session_id
        ORDER BY s.started_at DESC
        """
    ) as cursor:
        rows = await cursor.fetchall()
        
    sessions = []
    for r in rows:
        sessions.append({
            "session_id": r[0],
            "experiment_id": r[1],
            "arm": r[2],
            "status": r[3],
            "started_at": r[4],
            "sample": {
                "filename": r[5] or "sample.exe",
                "sha256": r[6] or "N/A"
            },
            "metrics": {
                "raw_events": r[7] or 0,
                "semantic_events": r[8] or 0,
                "decisions_total": r[9] or 0,
                "decisions_executed": r[10] or 0,
                "mutations_applied": r[11] or 0,
                "semantic_events_post_mutation": r[12] or 0
            }
        })
        
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"sessions": sessions}
    )

@router.get("/dashboard/session/{session_id}", response_class=HTMLResponse)
@router.get("/dashboard/sessions/{session_id}", response_class=HTMLResponse)
async def get_session_detail(request: Request, session_id: str):
    session = await deps.session_repo.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    events = await deps.event_repo.get_semantic_events(session_id)
    decisions = await deps.decision_repo.get_decisions(session_id)
    mutations = await deps.mutation_repo.get_mutations(session_id)
    raw_events = await deps.event_repo.get_raw_events(session_id)
    
    # Build unified timeline sorted by time of arrival (latest first, oldest last)
    feed_items = []
    
    def get_dt(val):
        if not val:
            return datetime.min.replace(tzinfo=timezone.utc)
        if isinstance(val, datetime):
            return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
        try:
            return parse_iso(str(val))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    for r in raw_events:
        feed_items.append({
            "type": "raw",
            "timestamp": str(r.occurred_at),
            "dt": get_dt(r.occurred_at),
            "data": r,
            "correlation_id": None
        })
        
    for e in events:
        feed_items.append({
            "type": "semantic",
            "timestamp": str(e.window_start),
            "dt": get_dt(e.window_start),
            "data": e,
            "correlation_id": e.correlation_id
        })
        
    for d in decisions:
        feed_items.append({
            "type": "decision",
            "timestamp": str(d.decided_at),
            "dt": get_dt(d.decided_at),
            "data": d,
            "correlation_id": d.correlation_id
        })
        
    for m in mutations:
        feed_items.append({
            "type": "mutation",
            "timestamp": str(m.applied_at),
            "dt": get_dt(m.applied_at),
            "data": m,
            "correlation_id": m.correlation_id
        })
        
    # Sort strictly descending by parsed datetime (latest arrival first)
    feed_items.sort(key=lambda item: item["dt"], reverse=True)
    
    # Also sort events table descending
    sorted_events = sorted(events, key=lambda ev: get_dt(ev.window_start), reverse=True)
    sorted_decisions = sorted(decisions, key=lambda dec: get_dt(dec.decided_at), reverse=True)
    sorted_mutations = sorted(mutations, key=lambda mut: get_dt(mut.applied_at), reverse=True)
    
    return templates.TemplateResponse(
        request=request,
        name="session_detail.html",
        context={
            "session": session,
            "events": sorted_events,
            "decisions": sorted_decisions,
            "mutations": sorted_mutations,
            "raw_events": raw_events,
            "feed_items": feed_items
        }
    )

@router.get("/dashboard/session/{session_id}/report", response_class=HTMLResponse)
@router.get("/dashboard/sessions/{session_id}/report", response_class=HTMLResponse)
async def get_session_report(request: Request, session_id: str):
    session = await deps.session_repo.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    events = await deps.event_repo.get_semantic_events(session_id)
    decisions = await deps.decision_repo.get_decisions(session_id)
    mutations = await deps.mutation_repo.get_mutations(session_id)
    
    # Calculate yield comparison mapping
    yield_comparisons = []
    for ev in events:
        yield_comparisons.append({
            "intent": ev.intent,
            "control_count": 0 if session.arm == "TREATMENT" else 1,
            "treatment_count": 1 if session.arm == "TREATMENT" else 0,
            "attributed": bool(ev.caused_by_mutation),
            "correlation_id": ev.correlation_id
        })
        
    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "session": session,
            "events": events,
            "decisions": decisions,
            "mutations": mutations,
            "yield_comparisons": yield_comparisons
        }
    )

@router.get("/dashboard/mutation-test", response_class=HTMLResponse)
async def get_mutation_test_console(request: Request):
    manifest_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "tools", "mutation_test", "manifest.json")
    manifest = {}
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

    # Get recent sessions for selection
    conn = await deps.db_conn.connect()
    async with conn.execute("SELECT session_id, experiment_id, status FROM sessions ORDER BY started_at DESC LIMIT 10") as cursor:
        rows = await cursor.fetchall()
        recent_sessions = [{"session_id": r[0], "experiment_id": r[1], "status": r[2]} for r in rows]

    return templates.TemplateResponse(
        request=request,
        name="mutation_test_console.html",
        context={
            "manifest": manifest,
            "recent_sessions": recent_sessions,
            "default_session_id": f"sess_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        }
    )
