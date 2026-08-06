import os
import sqlite3
import json
import uuid
from datetime import datetime
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

app = FastAPI(title="ADAM Dashboard DB Server")

# Get absolute paths to templates and static directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(BASE_DIR, "adam", "dashboard", "templates")
STATIC_DIR = os.path.join(BASE_DIR, "adam", "dashboard", "static")
DB_PATH = os.path.join(BASE_DIR, "artifacts", "adam.sqlite")

# Mount static files and initialize templates
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def dict_from_row(row):
    d = dict(row)
    # Deserialize JSON fields
    for json_field in ['sample_json', 'config_json', 'metrics_json', 'changes_json']:
        if json_field in d and d[json_field]:
            # Use original names without _json
            original_field = json_field.replace('_json', '')
            try:
                d[original_field] = json.loads(d[json_field])
            except:
                d[original_field] = None
    return d

@app.get("/", response_class=RedirectResponse)
def root():
    return "/dashboard"

@app.get("/dashboard", response_class=HTMLResponse)
def view_dashboard(request: Request):
    conn = get_db_connection()
    sessions = []
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions ORDER BY started_at DESC")
        rows = cur.fetchall()
        for r in rows:
            sessions.append(dict_from_row(r))
    except sqlite3.OperationalError:
        pass # Handle case where table doesn't exist yet
    finally:
        conn.close()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"sessions": sessions}
    )

@app.post("/api/v1/sessions")
def create_session(
    sample_path: str = Form(...),
    arm: str = Form(...),
    ruleset: str = Form(...),
    vm_profile: str = Form(...),
    timeout: int = Form(...)
):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        session_id = f"sess_{datetime.now().strftime('%Y_%m_%d')}_{uuid.uuid4().hex[:4]}"
        
        sample_json = json.dumps({
            "filename": os.path.basename(sample_path),
            "path": sample_path,
            "sha256": "pending...",
            "file_type": "Unknown"
        })
        
        config_json = json.dumps({
            "vm_profile": vm_profile,
            "policy_ruleset": ruleset,
            "timeout_seconds": timeout,
            "deception_enabled": (arm == "TREATMENT")
        })
        
        metrics_json = json.dumps({
            "decisions_total": 0,
            "mutations_applied": 0,
            "semantic_events_post_mutation": 0,
            "semantic_events": 0
        })
        
        started_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        cur.execute('''
            INSERT INTO sessions (session_id, arm, status, sample_json, config_json, metrics_json, started_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session_id, arm, "RUNNING", sample_json, config_json, metrics_json, started_at))
        
        conn.commit()
    finally:
        conn.close()
        
    return RedirectResponse(url=f"/dashboard/session/{session_id}", status_code=303)


@app.get("/dashboard/session/{session_id}", response_class=HTMLResponse)
def view_session_detail(request: Request, session_id: str):
    conn = get_db_connection()
    session = None
    decisions = []
    mutations = []
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        row = cur.fetchone()
        if row:
            session = dict_from_row(row)
            
        cur.execute("SELECT * FROM decisions WHERE session_id = ?", (session_id,))
        for r in cur.fetchall():
            decisions.append(dict_from_row(r))
            
        cur.execute("SELECT * FROM mutations WHERE session_id = ?", (session_id,))
        for r in cur.fetchall():
            mutations.append(dict_from_row(r))
    finally:
        conn.close()
        
    return templates.TemplateResponse(
        request=request,
        name="session_detail.html",
        context={
            "session": session,
            "decisions": decisions,
            "mutations": mutations
        }
    )

@app.get("/dashboard/session/{session_id}/report", response_class=HTMLResponse)
def view_report(request: Request, session_id: str):
    conn = get_db_connection()
    session = None
    yield_comparisons = []
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        row = cur.fetchone()
        if row:
            session = dict_from_row(row)
            
        cur.execute("SELECT * FROM yield_comparisons WHERE session_id = ?", (session_id,))
        for r in cur.fetchall():
            yield_comparisons.append(dict_from_row(r))
    finally:
        conn.close()
        
    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "session": session,
            "yield_comparisons": yield_comparisons
        }
    )

if __name__ == "__main__":
    print("Starting ADAM dashboard server at http://127.0.0.1:8000 ...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
