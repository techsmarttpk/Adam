import streamlit as st
import requests
import time
import pandas as pd
import asyncio
import subprocess
import re
import os
import sys
from datetime import datetime, timezone
import httpx
from pathlib import Path

# Add project root to path so we can import adam modules
sys.path.insert(0, os.path.abspath("."))

# Import ADAM components
from adam.sandbox.vbox.client import VirtualBoxClient
from adam.sandbox.controller import SandboxController
from adam.common.config import get_settings
from adam.api.deps import init_dependencies, deps, shutdown_dependencies
from adam.reporting.generator import ReportGenerator
from adam.contracts.session import SampleRef, SessionConfig, AnalysisSession, SessionMetrics
from adam.contracts.enums import Arm, NetworkMode, SessionStatus
from adam.orchestrator.session import SessionOrchestrator, new_session_id
from adam.orchestrator.runner import sample_ref_from_path
from adam.pipeline.wiring import wire_engines
from adam.fusion.engine import EventFusionEngine
from adam.policy.engine import PolicyEngine
from adam.deception.engine import DeceptionEngine

st.set_page_config(
    page_title="ADAM Adaptive Deception Panel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for polished SOC / Threat Intelligence styling
st.markdown("""
<style>
    /* Metric & Card styling */
    .stMetric {
        background-color: #1a1f2c;
        padding: 12px 16px;
        border-radius: 8px;
        border: 1px solid #2d3748;
    }
    .badge-pill {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.78rem;
        font-weight: 600;
        text-transform: uppercase;
        margin-right: 6px;
        letter-spacing: 0.03em;
    }
    .badge-treatment {
        background: rgba(59, 130, 246, 0.2);
        color: #60a5fa;
        border: 1px solid #3b82f6;
    }
    .badge-control {
        background: rgba(148, 163, 184, 0.2);
        color: #cbd5e1;
        border: 1px solid #64748b;
    }
    .badge-event {
        background: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid #10b981;
    }
    .badge-mutation {
        background: rgba(245, 158, 11, 0.2);
        color: #fbbf24;
        border: 1px solid #f59e0b;
    }
    .badge-net {
        background: rgba(147, 197, 253, 0.15);
        color: #93c5fd;
        border: 1px solid #3b82f6;
    }
    .badge-status {
        background: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid #10b981;
    }
    .tag-pill {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.82rem;
        font-family: monospace;
        margin: 3px 4px;
    }
    .timeline-card {
        background: #151922;
        border: 1px solid #283143;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 10px;
    }
    /* Custom Styled IOC Table */
    .ioc-table-container {
        border: 1px solid #2d3748;
        border-radius: 8px;
        overflow: hidden;
        margin-top: 8px;
        margin-bottom: 16px;
    }
    .ioc-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.88rem;
    }
    .ioc-table th {
        background: #141824;
        color: #94a3b8;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.75rem;
        padding: 10px 14px;
        text-align: left;
        border-bottom: 1px solid #2d3748;
    }
    .ioc-table td {
        padding: 10px 14px;
        border-bottom: 1px solid #1e2638;
        color: #e2e8f0;
    }
    .ioc-table tr:last-child td {
        border-bottom: none;
    }
    .ioc-row-mutation {
        border-left: 4px solid #f59e0b;
        background: rgba(245, 158, 11, 0.03);
    }
    .ioc-row-event {
        border-left: 4px solid #10b981;
        background: rgba(16, 185, 129, 0.03);
    }
    /* Hide default Streamlit status widget (cycling runner/biker icons) and deploy button */
    [data-testid="stStatusWidget"] {
        visibility: hidden !important;
    }
    .stDeployButton {
        display: none !important;
    }
    header[data-testid="stHeader"] {
        background: transparent;
    }
</style>
""", unsafe_allow_html=True)

settings = get_settings()

# MITRE ATT&CK Tactic dictionary and distinct color mapping
MITRE_TACTIC_NAMES = {
    "ta0043": "Reconnaissance",
    "ta0042": "Resource Development",
    "ta0001": "Initial Access",
    "ta0002": "Execution",
    "ta0003": "Persistence",
    "ta0004": "Privilege Escalation",
    "ta0005": "Defense Evasion",
    "ta0006": "Credential Access",
    "ta0007": "Discovery",
    "ta0008": "Lateral Movement",
    "ta0009": "Collection",
    "ta0011": "Command and Control",
    "ta0010": "Exfiltration",
    "ta0040": "Impact",
}

TACTIC_COLOR_STYLES = {
    # Discovery / Reconnaissance (Sky Cyan)
    "discovery": ("rgba(56, 189, 248, 0.20)", "#38bdf8", "#0284c7"),
    "reconnaissance": ("rgba(56, 189, 248, 0.20)", "#38bdf8", "#0284c7"),
    "recon": ("rgba(56, 189, 248, 0.20)", "#38bdf8", "#0284c7"),
    # Credential Access (Crimson Red)
    "credential access": ("rgba(244, 63, 94, 0.20)", "#fb7185", "#e11d48"),
    "credential": ("rgba(244, 63, 94, 0.20)", "#fb7185", "#e11d48"),
    # Defense Evasion (Amber / Orange)
    "defense evasion": ("rgba(251, 146, 60, 0.20)", "#fb923c", "#ea580c"),
    "defense": ("rgba(251, 146, 60, 0.20)", "#fb923c", "#ea580c"),
    "evasion": ("rgba(251, 146, 60, 0.20)", "#fb923c", "#ea580c"),
    # Persistence (Electric Indigo / Violet - Distinct from C2)
    "persistence": ("rgba(129, 140, 248, 0.22)", "#818cf8", "#4f46e5"),
    # Command and Control (Hot Pink / Magenta - Distinct from Persistence)
    "command and control": ("rgba(244, 114, 182, 0.22)", "#f472b6", "#db2777"),
    "c2": ("rgba(244, 114, 182, 0.22)", "#f472b6", "#db2777"),
    # Privilege Escalation (Golden Yellow)
    "privilege escalation": ("rgba(234, 179, 8, 0.20)", "#facc15", "#ca8a04"),
    # Lateral Movement (Mint / Green)
    "lateral movement": ("rgba(16, 185, 129, 0.20)", "#34d399", "#059669"),
    # Collection (Teal)
    "collection": ("rgba(20, 184, 166, 0.20)", "#2dd4bf", "#0d9488"),
    # Exfiltration (Crimson)
    "exfiltration": ("rgba(239, 68, 68, 0.20)", "#f87171", "#dc2626"),
    # Impact (Rose/Wine)
    "impact": ("rgba(225, 29, 72, 0.20)", "#fda4af", "#be123c"),
    # Execution (Lime)
    "execution": ("rgba(132, 204, 22, 0.20)", "#a3e635", "#65a30d"),
}

# Helper to color-code MITRE ATT&CK tactics
def get_tactic_badge(tactic_technique: str) -> str:
    parts = tactic_technique.split("/", 1)
    raw_tactic = parts[0].strip()
    technique = parts[1].strip() if len(parts) > 1 else ""
    
    t_key = raw_tactic.lower()
    friendly_name = MITRE_TACTIC_NAMES.get(t_key, raw_tactic)
    
    style_key = friendly_name.lower()
    style = None
    for k, v in TACTIC_COLOR_STYLES.items():
        if k in style_key or k in t_key:
            style = v
            break
            
    if not style:
        style = ("rgba(148, 163, 184, 0.18)", "#cbd5e1", "#64748b")
        
    bg, color, border = style
    display_text = f"{friendly_name} ({raw_tactic}) / {technique}" if friendly_name != raw_tactic and technique else (f"{friendly_name} / {technique}" if technique else friendly_name)
    return f'<span class="tag-pill" style="background: {bg}; color: {color}; border: 1px solid {border};">{display_text}</span>'



# Helper to run async code inside Streamlit's synchronous threads
def run_async(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(lambda: asyncio.run(coro))
            return future.result()
    else:
        return asyncio.run(coro)

# Helper to format datetime in user's local system timezone (e.g. IST +05:30)
def format_local_time(dt, include_date=True, include_ms=False):
    if not dt:
        return "N/A"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except Exception:
            return dt
    try:
        if hasattr(dt, "tzinfo") and dt.tzinfo is not None:
            local_dt = dt.astimezone()
        else:
            local_dt = dt.replace(tzinfo=timezone.utc).astimezone()
        
        if include_ms:
            fmt = "%Y-%m-%d %H:%M:%S.%f" if include_date else "%H:%M:%S.%f"
            return local_dt.strftime(fmt)[:-3]
        else:
            fmt = "%Y-%m-%d %H:%M:%S" if include_date else "%H:%M:%S"
            tz_str = local_dt.strftime("%Z") or "Local"
            return f"{local_dt.strftime(fmt)} ({tz_str})"
    except Exception:
        return str(dt)

# VM Status retriever
def get_vm_status():
    settings = get_settings()
    vm_name = settings.sandbox.vm_name
    client = VirtualBoxClient()
    
    vm_state = "Off"
    agent_healthy = False
    current_snapshot = "Unknown"
    
    try:
        raw_state = run_async(client.get_state(vm_name))
        if raw_state == "running":
            vm_state = "Running"
        elif raw_state in ("restoring", "booting"):
            vm_state = "Booting"
        else:
            vm_state = "Off"
    except Exception:
        vm_state = "Unknown"
        
    if vm_state == "Running":
        try:
            resp = httpx.get(f"{settings.http_guest.base_url}/health", timeout=1.0)
            if resp.status_code == 200 and resp.json().get("success"):
                agent_healthy = True
        except Exception:
            pass
            
    try:
        snapshots = run_async(client.list_snapshots(vm_name))
        for s in snapshots:
            if s.is_current:
                current_snapshot = s.name
                break
    except Exception:
        pass
        
    return vm_state, agent_healthy, current_snapshot

# Clean state reset helper
async def reset_vm_clean():
    settings = get_settings()
    vm_name = settings.sandbox.vm_name
    client = VirtualBoxClient()
    snapshot_name = settings.sandbox.snapshot_name
    
    state = await client.get_state(vm_name)
    if state in ("running", "paused", "stuck"):
        await client.stop(vm_name, mode="poweroff")
    elif state == "saved":
        await client.discard_saved_state(vm_name)
        
    await client.restore_snapshot(vm_name, snapshot_name)

# Live session runner
async def execute_live_session(sample_input, profile_name, deception_enabled, status_container):
    settings = get_settings()
    
    if sample_input is not None and hasattr(sample_input, "getvalue") and hasattr(sample_input, "name"):
        upload_dir = Path("samples/uploaded")
        upload_dir.mkdir(parents=True, exist_ok=True)
        staged_path = upload_dir / sample_input.name
        with open(staged_path, "wb") as f:
            f.write(sample_input.getvalue())
        host_sample_path = str(staged_path.resolve())
        if status_container:
            status_container.info(f"📁 Staged uploaded sample to `{host_sample_path}`")
    elif isinstance(sample_input, (str, Path)):
        host_sample_path = str(Path(sample_input).resolve())
    else:
        from scripts.reliability_check import _locate_smoke_sample
        host_sample_path = _locate_smoke_sample()
        
    if status_container:
        status_container.info("⏳ Restoring VM snapshot, booting, and running live analysis...")

    # Override settings deception arm
    settings.deception.enable_clock_manipulation = deception_enabled

    from adam.orchestrator.runner import Runner
    runner = Runner(settings)
    session = await runner.run(
        host_sample_path,
        vm_profile=profile_name,
        headless=True,
    )
    
    return session.session_id, session

# Retrieve session details and multi-format reports for display
async def get_session_details(session_id):
    import aiosqlite
    from adam.db.repositories.sqlite import (
        SQLiteSessionRepository, SQLiteEventRepository, SQLiteDecisionRepository, SQLiteMutationRepository
    )
    settings = get_settings()
    async with aiosqlite.connect(settings.db.path) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA busy_timeout=5000;")
        
        s_repo = SQLiteSessionRepository(db)
        e_repo = SQLiteEventRepository(db)
        d_repo = SQLiteDecisionRepository(db)
        m_repo = SQLiteMutationRepository(db)
        
        session = await s_repo.get_by_id(session_id)
        events = await e_repo.get_semantic_by_session(session_id)
        decisions = await d_repo.get_by_session(session_id)
        mutations = await m_repo.get_by_session(session_id)
        
        generator = ReportGenerator(s_repo, e_repo, d_repo, m_repo)
        html_report = await generator.generate(session_id, format="html")
        md_report = await generator.generate(session_id, format="md")
        json_report = await generator.generate(session_id, format="json")
        
        return session, events, decisions, mutations, html_report, md_report, json_report

# Retrieve list of all available sessions (newest first)
async def get_all_sessions():
    import aiosqlite
    from adam.db.repositories.sqlite import SQLiteSessionRepository
    settings = get_settings()
    async with aiosqlite.connect(settings.db.path) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA busy_timeout=5000;")
        s_repo = SQLiteSessionRepository(db)
        sessions = await s_repo.list_all()
        sessions_sorted = sorted(
            sessions,
            key=lambda s: s.started_at.isoformat() if s.started_at else "",
            reverse=True
        )
        return [(s.session_id, getattr(s.status, "value", str(s.status))) for s in sessions_sorted]


# ==============================================================================
# 1. PERSISTENT LEFT SIDEBAR CONTROL RAIL
# ==============================================================================

with st.sidebar:
    sidebar_brand_html = """
    <div style="margin-bottom: 16px; padding-bottom: 4px;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
            <span style="font-size: 2.2rem; filter: drop-shadow(0 0 12px rgba(59, 130, 246, 0.45));">🛡️</span>
            <h1 style="margin: 0; font-size: 2.2rem; font-weight: 800; letter-spacing: 0.04em; color: #f8fafc; line-height: 1.1;">ADAM</h1>
        </div>
        <div style="font-size: 0.95rem; font-weight: 600; color: #38bdf8; letter-spacing: 0.04em; text-transform: uppercase; margin-left: 2px;">
            Adaptive Deception Sandbox
        </div>
    </div>
    """
    try:
        st.html(sidebar_brand_html)
    except AttributeError:
        st.markdown(sidebar_brand_html, unsafe_allow_html=True)

    # --- Sandbox Health Indicator ---
    vm_state, agent_healthy, current_snapshot = get_vm_status()
    is_ready = (vm_state == "Off" and (current_snapshot == settings.sandbox.snapshot_name or "golden" in current_snapshot.lower())) or (vm_state == "Running" and agent_healthy)
    
    st.markdown(
        f"""
        <div style="background-color: #1a1f2c; padding: 10px 12px; border-radius: 8px; border: 1px solid #2d3748; margin-bottom: 12px; font-size: 0.85rem;">
            <div><strong>Status:</strong> {'🟢 Ready' if is_ready else '🔴 Not Ready'}</div>
            <div style="color: #94a3b8; margin-top: 4px;"><strong>VM:</strong> <code>{vm_state}</code> | <strong>Agent:</strong> {'🟢 Reachable' if agent_healthy else '🔴 Offline'}</div>
            <div style="color: #94a3b8;"><strong>Snapshot:</strong> <code>{current_snapshot}</code></div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("---")

    # --- Sample Selection ---
    st.subheader("📦 Sample")
    sample_mode = st.radio(
        "Source",
        ["Pre-loaded Benchmark", "Upload Custom"],
        index=0,
        label_visibility="collapsed",
        key="sample_source_mode"
    )
    
    if sample_mode == "Upload Custom":
        uploaded_file = st.file_uploader("Upload Binary", type=None, key="custom_sample_uploader")
        sample_to_run = uploaded_file
    else:
        uploaded_file = None
        sample_to_run = "samples/smoke_sample.exe"
        st.caption("🎯 `samples/smoke_sample.exe`")

    st.markdown("---")

    # --- VM Configuration ---
    st.subheader("⚙️ VM Config")
    profile_choice = st.selectbox(
        "Profile",
        ["bare_control", "enterprise_office_decoy", "developer_decoy"],
        key="unified_profile"
    )
    deception_choice = st.checkbox(
        "Enable Deception",
        value=True,
        help="Inject dynamic decoy credentials, registry lures, and files upon malware detection",
        key="unified_deception"
    )

    st.markdown("---")

    # --- Execution Actions ---
    st.subheader("🚀 Actions")
    live_disabled = not (vm_state in ("Off", "Running") and (current_snapshot == settings.sandbox.snapshot_name or "golden" in current_snapshot.lower()))
    if sample_mode == "Upload Custom" and uploaded_file is None:
        live_disabled = True

    sidebar_status = st.empty()

    if st.button("⚡ Run Live VM Detonation", use_container_width=True, type="primary", disabled=live_disabled, help="Detonate sample live inside VirtualBox sandbox"):
        sidebar_status.info("⏳ Restoring VM snapshot, booting, and running live analysis...")
        try:
            session_id, session = run_async(execute_live_session(sample_to_run, profile_choice, deception_choice, sidebar_status))
            sidebar_status.success(f"✅ Detonation complete!")
            st.session_state.last_session_id = session_id
            st.session_state.history_session_selector = session_id
            st.session_state.session_type = "live"
            st.rerun()
        except Exception as e:
            sidebar_status.error(f"❌ Detonation failed: {e}")

    col_act1, col_act2 = st.columns(2)
    with col_act1:
        if st.button("🚀 Replay Demo", use_container_width=True, help="Run offline synthetic attack replay via Fusion engine"):
            sidebar_status.info("⏳ Running replay...")
            res = subprocess.run(
                [sys.executable, "-m", "adam.cli.main", "replay", "synthetic"],
                capture_output=True, text=True
            )
            match = re.search(r"Session ID: (replay_\w+)", res.stdout)
            if match:
                session_id = match.group(1)
                sidebar_status.success(f"✅ Replay complete!")
                st.session_state.last_session_id = session_id
                st.session_state.history_session_selector = session_id
                st.session_state.session_type = "replay"
                st.rerun()
            else:
                sidebar_status.error("❌ Replay failed.")
                if res.stderr:
                    sidebar_status.code(res.stderr)

    with col_act2:
        if st.button("🔄 Reset VM", use_container_width=True, help="Power off sandbox VM and restore clean snapshot"):
            sidebar_status.info("⏳ Resetting clean snapshot...")
            try:
                run_async(reset_vm_clean())
                sidebar_status.success("✅ Reset clean!")
                st.rerun()
            except Exception as e:
                sidebar_status.error(f"❌ Reset failed: {e}")

    st.markdown("---")

    # --- Session Explorer Navigation ---
    all_sessions_data = run_async(get_all_sessions())
    session_ids = [s[0] for s in all_sessions_data]
    session_status_map = {s[0]: s[1] for s in all_sessions_data}
    
    st.subheader(f"📁 Sessions ({len(session_ids)})")
    
    if session_ids:
        def format_session_label(sid: str) -> str:
            st_val = session_status_map.get(sid, "COMPLETED")
            status_icon = "🟢" if st_val == "COMPLETED" else ("🟡" if st_val in ("RUNNING", "ACTIVE") else "🔴")
            
            if sid.startswith("sess_"):
                return f"{status_icon} [LIVE] {sid} ({st_val})"
            elif sid.startswith("replay_"):
                return f"🚀 [REPLAY] {sid} ({st_val})"
            elif sid.startswith("sim_"):
                return f"🧪 [SIM] {sid} ({st_val})"
            return f"📁 {sid} ({st_val})"

        curr_idx = 0
        if "last_session_id" in st.session_state and st.session_state.last_session_id in session_ids:
            curr_idx = session_ids.index(st.session_state.last_session_id)

        selected_session = st.selectbox(
            "Select Session to Inspect",
            options=session_ids,
            index=curr_idx,
            format_func=format_session_label,
            label_visibility="collapsed",
            key="history_session_selector"
        )
        if selected_session:
            st.session_state.last_session_id = selected_session
            if selected_session.startswith("sess_"):
                st.session_state.session_type = "LIVE"
            elif selected_session.startswith("replay_"):
                st.session_state.session_type = "REPLAY"
            else:
                st.session_state.session_type = "SIMULATION"
    else:
        st.caption("No sessions recorded yet.")



# ==============================================================================
# 2. MAIN REPORT CANVAS
# ==============================================================================

if not ("last_session_id" in st.session_state and st.session_state.last_session_id):
    # Welcome / Empty State Canvas
    st.title("🛡️ ADAM: Adaptive Deception Analysis Platform")
    st.markdown("### Real-Time Behavioral Analysis & Deception Intelligence")
    st.info("👈 **Select a session from the left sidebar** or trigger a **Live VM Detonation** / **Replay Demo** to generate threat intelligence.")
else:
    current_sid = st.session_state.last_session_id
    session_type_label = st.session_state.get('session_type', 'SESSION').upper()

    try:
        session, events, decisions, mutations, html_report, md_report, json_report = run_async(get_session_details(current_sid))

        # Force browser to disable automatic scroll-restoration and lock viewport strictly to top
        st.markdown(
            """
            <img src="data:image/svg+xml;utf8,<svg></svg>" style="display:none;" onerror="
                try {
                    if ('scrollRestoration' in history) {
                        history.scrollRestoration = 'manual';
                    }
                    window.scrollTo(0, 0);
                    const container = document.querySelector('section.main') || document.querySelector('[data-testid=stAppViewContainer]');
                    if (container) {
                        container.scrollTop = 0;
                    }
                } catch(e) {}
            ">
            """,
            unsafe_allow_html=True
        )

        arm_val = session.arm.value if hasattr(session.arm, "value") else str(session.arm)
        status_val = session.status.value if hasattr(session.status, "value") else str(session.status)
        net_mode_val = session.config.network_mode.value if hasattr(session.config.network_mode, "value") else str(session.config.network_mode)

        # Compute unique ATT&CK coverage
        attck_coverage = []
        for e in events:
            if e.attck:
                cov = f"{e.attck.tactic} / {e.attck.technique}"
                if cov not in attck_coverage:
                    attck_coverage.append(cov)

        # --- Top Header & Metadata Banner ---
        head_col, badges_col = st.columns([2.2, 1.8])
        with head_col:
            st.subheader(f"📊 SESSION: `{current_sid}`")
            started_local = format_local_time(session.started_at, include_date=True)
            st.caption(f"Experiment: `{session.experiment_id}` • Started: `{started_local}`")
        
        with badges_col:
            arm_badge_class = "badge-treatment" if arm_val == "TREATMENT" else "badge-control"
            meta_badges_html = (
                '<div style="text-align: right; margin-top: 10px;">'
                f'<span class="badge-pill badge-net" title="Network Isolation Mode">NET: {net_mode_val}</span>'
                f'<span class="badge-pill {arm_badge_class}">ARM: {arm_val}</span>'
                f'<span class="badge-pill badge-status">{status_val}</span>'
                '</div>'
            )
            try:
                st.html(meta_badges_html)
            except AttributeError:
                st.markdown(meta_badges_html, unsafe_allow_html=True)

        # --- Numeric Metrics & Quick Download Actions Bar ---
        mcol1, mcol2, mcol3, mcol4, dcol1, dcol2, dcol3 = st.columns([1, 1, 1, 1, 0.8, 0.8, 0.8])
        mcol1.metric("Events", len(events))
        mcol2.metric("Mutations", len(mutations))
        mcol3.metric("Decisions", len(decisions))
        mcol4.metric("ATT&CK Techs", len(attck_coverage))

        with dcol1:
            st.download_button(
                label="📥 HTML",
                data=html_report,
                file_name=f"report_{current_sid}.html",
                mime="text/html",
                use_container_width=True,
                key=f"dl_html_{current_sid}"
            )
        with dcol2:
            st.download_button(
                label="📥 MD",
                data=md_report,
                file_name=f"report_{current_sid}.md",
                mime="text/markdown",
                use_container_width=True,
                key=f"dl_md_{current_sid}"
            )
        with dcol3:
            st.download_button(
                label="📥 JSON",
                data=json_report,
                file_name=f"report_{current_sid}.json",
                mime="application/json",
                use_container_width=True,
                key=f"dl_json_{current_sid}"
            )

        st.divider()

        # Save HTML report to reports directory on disk
        reports_dir = Path("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_file_path = reports_dir / f"report_{current_sid}.html"
        with open(report_file_path, "w", encoding="utf-8") as f:
            f.write(html_report)

        # Compact Forensic Summary Strip with Full SHA-256
        sample_name = session.sample.filename if session.sample and session.sample.filename else "smoke_sample.exe"
        full_sha = session.sample.sha256 if session.sample and session.sample.sha256 else "N/A"
        vm_prof = session.config.vm_profile if session.config else "bare_control"
        deception_active = session.config.deception_enabled if session.config and hasattr(session.config, "deception_enabled") else (arm_val == "TREATMENT")
        
        meta_strip_html = f"""
        <div style="background-color: #161b26; border: 1px solid #283143; border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; font-size: 0.84rem; color: #94a3b8;">
            <div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 8px;">
                <div><span style="color: #64748b;">Target Sample:</span> <strong style="color: #f1f5f9; font-family: monospace;">{sample_name}</strong></div>
                <div><span style="color: #64748b;">VM Profile:</span> <strong style="color: #f1f5f9;">{vm_prof}</strong></div>
                <div><span style="color: #64748b;">Deception Engine:</span> <strong style="color: {'#34d399' if deception_active else '#94a3b8'};">{'ACTIVE (TREATMENT)' if deception_active else 'MONITOR ONLY (CONTROL)'}</strong></div>
            </div>
            <div style="border-top: 1px solid #1f2737; padding-top: 6px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                <span style="color: #64748b; font-size: 0.78rem; text-transform: uppercase; font-weight: 600;">SHA-256 Hash:</span>
                <code style="color: #93c5fd; font-family: monospace; font-size: 0.82rem; background: #0f131a; padding: 3px 8px; border-radius: 4px; border: 1px solid #283143; word-break: break-all; user-select: all;" title="Full 64-character SHA-256 hash (click to copy)">{full_sha}</code>
            </div>
        </div>
        """
        try:
            st.html(meta_strip_html)
        except AttributeError:
            st.markdown(meta_strip_html, unsafe_allow_html=True)

        # 1. MITRE ATT&CK Coverage with Tactic Color Coding & Legend
        st.markdown("#### 🛡️ MITRE ATT&CK® Coverage")
        legend_html = (
            '<div style="display: flex; gap: 14px; font-size: 0.76rem; color: #94a3b8; margin-bottom: 10px; flex-wrap: wrap;">'
            '<span><span style="color: #38bdf8; font-size: 0.85rem;">●</span> Discovery</span>'
            '<span><span style="color: #fb7185; font-size: 0.85rem;">●</span> Credential Access</span>'
            '<span><span style="color: #818cf8; font-size: 0.85rem;">●</span> Persistence</span>'
            '<span><span style="color: #f472b6; font-size: 0.85rem;">●</span> Command & Control</span>'
            '<span><span style="color: #fb923c; font-size: 0.85rem;">●</span> Defense Evasion</span>'
            '<span><span style="color: #2dd4bf; font-size: 0.85rem;">●</span> Collection</span>'
            '</div>'
        )
        try:
            st.html(legend_html)
        except AttributeError:
            st.markdown(legend_html, unsafe_allow_html=True)

        if attck_coverage:
            tags_html = "".join([get_tactic_badge(tag) for tag in attck_coverage])
            try:
                st.html(f"<div>{tags_html}</div>")
            except AttributeError:
                st.markdown(tags_html, unsafe_allow_html=True)
        else:
            st.caption("No ATT&CK techniques mapped for this session.")

        st.write("")

        # 2. IOCs & Artifacts Table (Enhanced Extraction with Attacker Event Prioritization & Filter)
        st.markdown("#### 🔍 Indicators of Compromise (IOCs) & Planted Artifacts")
        seen_iocs = set()
        event_iocs = []
        mutation_iocs = []

        # 2a. Extract real observed attacker events first
        for e in events:
            target = None
            op = "Observed Access"
            if "target_object" in e.features and e.features["target_object"]:
                target = e.features["target_object"]
                op = "File/Registry Access"
            elif "TargetFilename" in e.features and e.features["TargetFilename"]:
                target = e.features["TargetFilename"]
                op = "File Read/Write"
            elif "TargetObject" in e.features and e.features["TargetObject"]:
                target = e.features["TargetObject"]
                op = "Registry Read/Write"
            elif "network_endpoint" in e.features and e.features["network_endpoint"]:
                target = e.features["network_endpoint"]
                op = "Network Connect"
            elif "DestinationIp" in e.features and e.features["DestinationIp"]:
                target = f"{e.features.get('DestinationIp')}:{e.features.get('DestinationPort', '')}"
                op = "Network Connect"
            elif "QueryName" in e.features and e.features["QueryName"]:
                target = e.features["QueryName"]
                op = "DNS Query"
            elif e.intent:
                intent_map = {
                    "RECON_USER_ARTIFACTS": ("Desktop / Documents / User Artifacts Search", "Directory Traversal"),
                    "CRED_BROWSER_STORE": ("AppData\\Local\\Google\\Chrome / Login Data", "Credential Store Read"),
                    "PERSIST_RUN_KEY": ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Persistence Query"),
                    "C2_BEACON": ("Outbound HTTP/DNS C2 Traffic", "Beaconing / Check-in"),
                    "DISCOVERY_SYS_INFO": ("System Architecture & OS Profile", "Host Discovery"),
                }
                target, op = intent_map.get(e.intent, (f"Observed Intent: {e.intent}", "Attacker Behavior"))
            
            if target:
                key = ("EVENT", target, op)
                if key not in seen_iocs:
                    seen_iocs.add(key)
                    event_iocs.append({"source": "EVENT", "target": target, "operation": op})

        # 2b. Extract planted decoy mutations
        for m in mutations:
            for c in m.changes:
                key = ("MUTATION", c.target, c.operation or "SET")
                if key not in seen_iocs:
                    seen_iocs.add(key)
                    mutation_iocs.append({"source": "MUTATION", "target": c.target, "operation": c.operation or "SET"})

        all_iocs = event_iocs + mutation_iocs

        if all_iocs:
            ioc_rows_html = []
            for ioc in all_iocs:
                row_class = "ioc-row-mutation" if ioc["source"] == "MUTATION" else "ioc-row-event"
                badge_class = "badge-mutation" if ioc["source"] == "MUTATION" else "badge-event"
                ioc_rows_html.append(
                    f'<tr class="{row_class}">'
                    f'<td style="width: 140px;"><span class="badge-pill {badge_class}">{ioc["source"]}</span></td>'
                    f'<td style="font-family: monospace; color: #cbd5e1; word-break: break-all;">{ioc["target"]}</td>'
                    f'<td style="width: 160px; color: #94a3b8;">{ioc["operation"]}</td>'
                    f'</tr>'
                )
            
            table_html = (
                '<div class="ioc-table-container">'
                '<table class="ioc-table">'
                '<thead><tr><th>Source</th><th>Target / Path</th><th>Operation</th></tr></thead>'
                f'<tbody>{"".join(ioc_rows_html)}</tbody>'
                '</table></div>'
            )
            try:
                st.html(table_html)
            except AttributeError:
                st.markdown(table_html, unsafe_allow_html=True)
        else:
            st.caption("No IOCs or decoy interactions extracted.")

        st.write("")

        # 3. Behavioral Timeline with Confidence & Plausibility Pills
        st.markdown("#### ⏱️ Behavioral Timeline")
        
        timeline = []
        for e in events:
            timeline.append({
                "time": e.window_start,
                "type": "EVENT",
                "title": e.intent,
                "confidence": e.confidence,
                "detector": e.detector,
                "badge_class": "badge-event"
            })
        for m in mutations:
            timeline.append({
                "time": m.applied_at,
                "type": "MUTATION",
                "title": m.primitive,
                "status": m.status.value if hasattr(m.status, "value") else str(m.status),
                "plausibility": m.plausibility_score,
                "badge_class": "badge-mutation"
            })
        
        timeline.sort(key=lambda x: str(x["time"]))

        # Deduplicate consecutive identical events with same timestamp and title
        deduped_timeline = []
        for item in timeline:
            if deduped_timeline and deduped_timeline[-1]["title"] == item["title"] and str(deduped_timeline[-1]["time"]) == str(item["time"]):
                continue
            deduped_timeline.append(item)

        if deduped_timeline:
            cards_html = []
            for item in deduped_timeline:
                time_str = format_local_time(item['time'], include_date=False, include_ms=True)
                
                if item['type'] == 'EVENT':
                    conf = item.get('confidence', 0.8)
                    if conf >= 0.85:
                        conf_style = "background: rgba(16, 185, 129, 0.25); color: #34d399; border: 1px solid #10b981;"
                    elif conf >= 0.70:
                        conf_style = "background: rgba(234, 179, 8, 0.25); color: #facc15; border: 1px solid #ca8a04;"
                    else:
                        conf_style = "background: rgba(251, 146, 60, 0.25); color: #fb923c; border: 1px solid #ea580c;"
                    
                    extra_pill = f'<span class="badge-pill" style="{conf_style}; font-size: 0.72rem; padding: 2px 8px;">{int(conf * 100)}% CONF</span>'
                    detail_str = f"Detector: <code style='color: #93c5fd;'>{item.get('detector', 'FusionDetector')}</code>"
                else:
                    plaus = item.get('plausibility', 1.0)
                    status_val = item.get('status', 'APPLIED')
                    status_style = "background: rgba(16, 185, 129, 0.2); color: #34d399;" if status_val == "APPLIED" else "background: rgba(239, 68, 68, 0.2); color: #f87171;"
                    extra_pill = f'<span class="badge-pill" style="{status_style}; font-size: 0.72rem; padding: 2px 8px;">{status_val}</span><span class="badge-pill" style="background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; font-size: 0.72rem; padding: 2px 8px;">PLAUS: {plaus:.2f}</span>'
                    detail_str = "Deception mutation applied to guest environment."

                card_html = (
                    '<div class="timeline-card">'
                    '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">'
                    '<div style="display: flex; align-items: center; gap: 4px; flex-wrap: wrap;">'
                    f'<span class="badge-pill {item["badge_class"]}">{item["type"]}</span>'
                    f'<strong style="color: #f0f4f8; font-size: 0.95rem; margin-right: 6px;">{item["title"]}</strong>'
                    f'{extra_pill}'
                    '</div>'
                    f'<span style="color: #94a3b8; font-family: monospace; font-size: 0.8rem;">{time_str}</span>'
                    '</div>'
                    f'<div style="color: #94a3b8; font-size: 0.84rem; margin-left: 4px;">{detail_str}</div>'
                    '</div>'
                )
                cards_html.append(card_html)

            timeline_html = (
                '<div style="max-height: 450px; overflow-y: auto; padding-right: 6px; margin-bottom: 16px;">'
                f'{"".join(cards_html)}'
                '</div>'
            )
            try:
                st.html(timeline_html)
            except AttributeError:
                st.markdown(timeline_html, unsafe_allow_html=True)
        else:
            st.caption("No events or mutations recorded.")

        st.write("")

        # 4. Raw Telemetry Artifacts
        artifact_dir = Path("artifacts") / current_sid
        raw_jsonl_path = artifact_dir / "raw.jsonl"
        sysmon_path = artifact_dir / "sysmon.evtx"
        
        # Calculate exact raw event count
        raw_event_count = 0
        if raw_jsonl_path.exists():
            with open(raw_jsonl_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_event_count = sum(1 for line in f if line.strip())
        elif session.metrics and getattr(session.metrics, "raw_events", 0):
            raw_event_count = session.metrics.raw_events

        st.markdown("#### 📜 Raw OS Telemetry Artifacts")
        if raw_event_count > 0:
            st.caption(f"📁 **{raw_event_count:,} total raw OS telemetry events** recorded from Sysmon, Procmon, and Tshark collectors.")

        with st.container():
            col_d1, col_d2 = st.columns([1, 1])
            with col_d1:
                if raw_jsonl_path.exists():
                    st.download_button(
                        label=f"📥 Download Full raw.jsonl ({raw_jsonl_path.stat().st_size / 1024 / 1024:.2f} MB • {raw_event_count:,} events)",
                        data=raw_jsonl_path.read_bytes(),
                        file_name=f"raw_{current_sid}.jsonl",
                        mime="application/x-ndjson",
                        use_container_width=True,
                        key=f"dl_raw_{current_sid}"
                    )
                else:
                    st.caption("No `raw.jsonl` artifact on disk.")
            with col_d2:
                if sysmon_path.exists():
                    st.download_button(
                        label=f"📥 Download Full sysmon.evtx ({sysmon_path.stat().st_size / 1024 / 1024:.2f} MB)",
                        data=sysmon_path.read_bytes(),
                        file_name=f"sysmon_{current_sid}.evtx",
                        mime="application/octet-stream",
                        use_container_width=True,
                        key=f"dl_evtx_{current_sid}"
                    )
                else:
                    st.caption("No `sysmon.evtx` artifact on disk.")

            if raw_jsonl_path.exists():
                st.caption(f"📁 Local Artifact Path: `{raw_jsonl_path.resolve()}`")

    except Exception as e:
        st.error(f"Failed to fetch session details: {e}")







