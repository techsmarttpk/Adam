from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

dashboard_router = APIRouter(prefix="/dashboard", tags=["dashboard"])
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


@dashboard_router.get("/", response_class=HTMLResponse)
async def dashboard_index(request: Request):
    from adam.api.main import get_sessions
    sessions_data = await get_sessions()
    sessions = sessions_data.get("sessions", [])
    return templates.TemplateResponse(
        request=request, name="session_list.html", context={"sessions": sessions}
    )


@dashboard_router.get("/sessions/{session_id}", response_class=HTMLResponse)
async def dashboard_session_detail(request: Request, session_id: str):
    from adam.api.main import get_session, get_session_events, get_session_decisions, get_session_mutations
    session = jsonable_encoder(await get_session(session_id))
    events = jsonable_encoder(await get_session_events(session_id))
    decisions = jsonable_encoder(await get_session_decisions(session_id))
    mutations = jsonable_encoder(await get_session_mutations(session_id))
    return templates.TemplateResponse(
        request=request, name="session_detail.html", context={
            "session_id": session_id,
            "session": session,
            "events": events,
            "decisions": decisions,
            "mutations": mutations
        }
    )


@dashboard_router.get("/sessions/{session_id}/report", response_class=HTMLResponse)
async def dashboard_report(request: Request, session_id: str):
    from adam.api.main import get_session_report
    response = await get_session_report(session_id, format="html")
    # response is an HTMLResponse or JSONResponse on error
    if hasattr(response, "body"):
        content = response.body.decode()
        if response.status_code != 200:
            return HTMLResponse(f"<h1>Error</h1><pre>{content}</pre>", status_code=response.status_code)
        return templates.TemplateResponse(
            request=request, name="report.html", context={"session_id": session_id, "report_html": content}
        )
    return HTMLResponse("Unexpected response format", status_code=500)


@dashboard_router.get("/experiments/{experiment_id}/comparison", response_class=HTMLResponse)
async def dashboard_comparison(request: Request, experiment_id: str):
    from adam.api.main import get_experiment_comparison
    response = await get_experiment_comparison(experiment_id)
    if response.status_code != 200:
        return HTMLResponse(f"<h1>Error</h1><pre>{response.body.decode()}</pre>", status_code=response.status_code)
        
    data = json.loads(response.body.decode())
    return templates.TemplateResponse(
        request=request, name="comparison.html", context={"data": data, "experiment_id": experiment_id}
    )
