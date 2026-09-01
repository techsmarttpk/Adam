import uuid
from typing import List
from adam.contracts.enums import EventCategory
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent, ActorContext, AttckContext
from adam.fusion.correlate import EventCorrelator
from adam.fusion.registry import register_detector

def _create_sem_event(event: RawEvent, intent: str, confidence: float, severity: str, tactic: str, technique: str, detector: str, features: dict) -> SemanticEvent:
    actor = ActorContext(pid=event.process.pid, image=event.process.image, guid=event.process.guid) if event.process else None
    feat = dict(features)
    feat.setdefault("phase", "DEFENSE_EVASION")
    return SemanticEvent(
        semantic_id=f"sem_{uuid.uuid4().hex[:12]}",
        session_id=event.session_id,
        correlation_id=f"corr_{event.event_id[4:14]}",
        intent=intent,
        confidence=confidence,
        severity=severity,
        window_start=event.occurred_at,
        window_end=event.occurred_at,
        actor=actor,
        evidence=[event.event_id],
        attck=AttckContext(tactic=tactic, technique=technique),
        detector=detector,
        features=feat
    )

@register_detector
def detect_anti_forensics(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects anti-forensics activity: Event log clear, file deletion, timestamp tampering (timestomp), history clear, artifact cleanup, self-deletion, log tampering."""
    events = []
    cmd = (event.process.command_line or "").lower() if event.process else ""
    target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()

    # 1. Event Log Clear (T1070.001) - CRITICAL
    if "wevtutil" in cmd and ("cl" in cmd or "clear-log" in cmd):
        events.append(_create_sem_event(event, "ANTI_FORENSICS_EVENT_LOG_CLEAR", 0.98, "CRITICAL", "TA0005", "T1070.001", "AntiForensicsLogClearDetector@1.0", {"command_line": cmd}))

    # 2. File Deletion (T1070.004) - HIGH
    elif ("del /f /q" in cmd or "remove-item -force" in cmd) and (".tmp" in cmd or ".log" in cmd or ".dat" in cmd):
        events.append(_create_sem_event(event, "ANTI_FORENSICS_FILE_DELETION", 0.88, "HIGH", "TA0005", "T1070.004", "AntiForensicsFileDeleteDetector@1.0", {"command_line": cmd}))

    # 3. Timestamp Tampering / Timestomp (T1070.006) - HIGH
    elif "timestomp" in cmd or "creationtime" in cmd and "lastwritetime" in cmd or "set-itemproperty" in cmd and "creationtime" in cmd:
        events.append(_create_sem_event(event, "ANTI_FORENSICS_TIMESTAMP_TAMPERING", 0.92, "HIGH", "TA0005", "T1070.006", "AntiForensicsTimestompDetector@1.0", {"command_line": cmd}))

    # 4. History Clear (T1070.003) - HIGH
    elif "clear-history" in cmd or "doskey /reinstall" in cmd or "rmdir" in cmd and "history" in cmd:
        events.append(_create_sem_event(event, "ANTI_FORENSICS_HISTORY_CLEAR", 0.90, "HIGH", "TA0005", "T1070.003", "AntiForensicsHistoryClearDetector@1.0", {"command_line": cmd}))

    # 5. Artifact Cleanup (T1070) - HIGH
    elif "cleanmgr" in cmd or "vssadmin delete" in cmd or "prefetc" in cmd:
        events.append(_create_sem_event(event, "ANTI_FORENSICS_ARTIFACT_CLEANUP", 0.88, "HIGH", "TA0005", "T1070", "AntiForensicsArtifactCleanupDetector@1.0", {"command_line": cmd}))

    # 6. Self Delete (T1070.004) - CRITICAL
    elif "cmd /c del %0" in cmd or "cmd.exe /c del" in cmd and ("ping" in cmd or "choice" in cmd):
        events.append(_create_sem_event(event, "ANTI_FORENSICS_SELF_DELETE", 0.95, "CRITICAL", "TA0005", "T1070.004", "AntiForensicsSelfDeleteDetector@1.0", {"command_line": cmd}))

    # 7. Log Tampering (T1562.002) - HIGH
    elif "minlog" in cmd or "etw" in cmd and "disable" in cmd or "wevtutil sl" in cmd and "/e:false" in cmd:
        events.append(_create_sem_event(event, "ANTI_FORENSICS_LOG_TAMPERING", 0.92, "HIGH", "TA0005", "T1562.002", "AntiForensicsLogTamperingDetector@1.0", {"command_line": cmd}))

    return events
