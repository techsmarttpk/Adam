import uuid
from typing import List, Set
from adam.contracts.enums import EventCategory
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent, ActorContext, AttckContext
from adam.fusion.correlate import EventCorrelator
from adam.fusion.registry import register_detector

def _create_campaign_event(session_id: str, correlation_id: str, intent: str, confidence: float, severity: str, tactic: str, technique: str, evidence: list, features: dict) -> SemanticEvent:
    from adam.common.timeutil import now_utc
    feat = dict(features)
    return SemanticEvent(
        semantic_id=f"sem_cmp_{uuid.uuid4().hex[:10]}",
        session_id=session_id,
        correlation_id=correlation_id,
        intent=intent,
        confidence=confidence,
        severity=severity,
        window_start=now_utc(),
        window_end=now_utc(),
        actor=None,
        evidence=evidence,
        attck=AttckContext(tactic=tactic, technique=technique),
        detector="CompoundCampaignDetector@1.0",
        features=feat
    )

@register_detector
def detect_compound_campaigns(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Correlates multi-event sequences across the sliding window to infer higher-level compound attack campaigns.
    
    1. CAMPAIGN_CREDENTIAL_HARVEST: Browser recon + cred store + session cookies
    2. CAMPAIGN_LATERAL_MOVEMENT: DC discovery + shares + SMB enum + cred manager
    3. CAMPAIGN_RANSOMWARE: File directory recon + shadow copy delete + mass file encrypt
    4. CAMPAIGN_SANDBOX_EVASION: Hardware check + process check + time delay check
    5. CAMPAIGN_C2_ESTABLISHMENT: DNS lookup + Beacon/Polling + Stage download
    6. CAMPAIGN_DATA_COLLECTION: Documents + Archives/Database + Financial files
    7. CAMPAIGN_PERSISTENCE: Run key / Startup + Scheduled task / Service
    """
    events = []
    window_events = correlator.get_events_in_window()
    if len(window_events) < 2:
        return events

    # Collect commands, file targets, registry targets in window
    cmds = []
    targets = []
    ev_ids = [e.event_id for e in window_events]

    for ev in window_events:
        if ev.process and ev.process.command_line:
            cmds.append(ev.process.command_line.lower())
        tgt = (ev.attributes.get("target_object", "") or ev.attributes.get("path", "")).lower()
        if tgt:
            targets.append(tgt)

    all_cmd_text = " ".join(cmds)
    all_tgt_text = " ".join(targets)

    # 1. CAMPAIGN_CREDENTIAL_HARVEST
    has_browser = "chrome" in all_tgt_text or "firefox" in all_tgt_text or "edge" in all_tgt_text
    has_cred_store = "login data" in all_tgt_text or "logins.json" in all_tgt_text
    has_cookies = "cookies" in all_tgt_text
    if (has_browser and has_cred_store) or (has_cred_store and has_cookies):
        events.append(_create_campaign_event(
            event.session_id, f"corr_{event.event_id[4:14]}",
            "CAMPAIGN_CREDENTIAL_HARVEST", 0.95, "HIGH",
            "TA0006", "T1555", ev_ids[-4:],
            {"phase": "CREDENTIAL_ACCESS", "campaign": "CREDENTIAL_HARVEST", "signals": ["browser_recon", "cred_store", "cookies"]}
        ))

    # 2. CAMPAIGN_LATERAL_MOVEMENT
    has_dc = "nltest" in all_cmd_text or "dclist" in all_cmd_text or "domain" in all_tgt_text
    has_share = "net view" in all_cmd_text or "net use" in all_cmd_text or "share" in all_cmd_text
    has_cmdkey = "cmdkey" in all_cmd_text or "mstsc" in all_cmd_text or "psexec" in all_cmd_text
    if (has_dc and has_share) or (has_share and has_cmdkey):
        events.append(_create_campaign_event(
            event.session_id, f"corr_{event.event_id[4:14]}",
            "CAMPAIGN_LATERAL_MOVEMENT", 0.96, "CRITICAL",
            "TA0008", "T1021", ev_ids[-4:],
            {"phase": "LATERAL_MOVEMENT", "campaign": "LATERAL_MOVEMENT", "signals": ["dc_recon", "share_enum", "remote_tool"]}
        ))

    # 3. CAMPAIGN_RANSOMWARE
    has_vss = "vssadmin" in all_cmd_text or "shadowcopy" in all_cmd_text or "wbadmin" in all_cmd_text
    has_encrypt = ".locked" in all_tgt_text or ".encrypted" in all_tgt_text or "readme" in all_tgt_text
    if has_vss and has_encrypt:
        events.append(_create_campaign_event(
            event.session_id, f"corr_{event.event_id[4:14]}",
            "CAMPAIGN_RANSOMWARE", 0.99, "CRITICAL",
            "TA0040", "T1486", ev_ids[-4:],
            {"phase": "IMPACT", "campaign": "RANSOMWARE", "signals": ["shadow_copy_delete", "file_encrypt_note"]}
        ))

    # 4. CAMPAIGN_SANDBOX_EVASION
    has_hw = "bios" in all_tgt_text or "qemu" in all_tgt_text or "vbox" in all_tgt_text
    has_proc = "wireshark" in all_cmd_text or "procmon" in all_cmd_text or "x64dbg" in all_cmd_text
    has_sleep = "start-sleep" in all_cmd_text or "timeout" in all_cmd_text or "ping -n" in all_cmd_text
    if (has_hw and has_proc) or (has_hw and has_sleep) or (has_proc and has_sleep):
        events.append(_create_campaign_event(
            event.session_id, f"corr_{event.event_id[4:14]}",
            "CAMPAIGN_SANDBOX_EVASION", 0.95, "HIGH",
            "TA0005", "T1497", ev_ids[-4:],
            {"phase": "DEFENSE_EVASION", "campaign": "SANDBOX_EVASION", "signals": ["hardware_check", "proc_check", "sleep_check"]}
        ))

    # 5. CAMPAIGN_C2_ESTABLISHMENT
    has_dns = "nslookup" in all_cmd_text or "query_name" in str(event.attributes)
    has_download = "curl" in all_cmd_text or "downloadstring" in all_cmd_text or "certutil" in all_cmd_text
    if has_dns and has_download:
        events.append(_create_campaign_event(
            event.session_id, f"corr_{event.event_id[4:14]}",
            "CAMPAIGN_C2_ESTABLISHMENT", 0.94, "CRITICAL",
            "TA0011", "T1071", ev_ids[-4:],
            {"phase": "C2_ESTABLISHMENT", "campaign": "C2_ESTABLISHMENT", "signals": ["dns_lookup", "payload_download"]}
        ))

    # 6. CAMPAIGN_DATA_COLLECTION
    has_docs = ".docx" in all_tgt_text or ".pdf" in all_tgt_text or ".xlsx" in all_tgt_text
    has_arch = ".zip" in all_tgt_text or "7z" in all_cmd_text or "rar" in all_cmd_text
    if has_docs and has_arch:
        events.append(_create_campaign_event(
            event.session_id, f"corr_{event.event_id[4:14]}",
            "CAMPAIGN_DATA_COLLECTION", 0.92, "HIGH",
            "TA0009", "T1005", ev_ids[-4:],
            {"phase": "DATA_COLLECTION", "campaign": "DATA_COLLECTION", "signals": ["docs_access", "archive_staging"]}
        ))

    # 7. CAMPAIGN_PERSISTENCE
    has_run = "currentversion\\run" in all_tgt_text or "startup" in all_tgt_text
    has_task_svc = "schtasks" in all_cmd_text or "sc.exe" in all_cmd_text or "new-service" in all_cmd_text
    if has_run and has_task_svc:
        events.append(_create_campaign_event(
            event.session_id, f"corr_{event.event_id[4:14]}",
            "CAMPAIGN_PERSISTENCE", 0.95, "HIGH",
            "TA0003", "T1547", ev_ids[-4:],
            {"phase": "PERSISTENCE", "campaign": "PERSISTENCE", "signals": ["run_key", "scheduled_task_service"]}
        ))

    return events
