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
    feat.setdefault("phase", "DATA_COLLECTION")
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
def detect_data_collection(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects targeted data collection: Documents, Financial files, Browser data, Email, Archives, Database, Source code, Cloud config, SSH keys, Browser cookies."""
    events = []
    target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
    cmd = (event.process.command_line or "").lower() if event.process else ""

    # 1. Documents (T1005 / T1039) - HIGH
    if target.endswith(".docx") or target.endswith(".pdf") or target.endswith(".txt") or target.endswith(".pptx") or target.endswith(".rtf") or ".docx" in cmd or ".pdf" in cmd or ("documents" in cmd and ("dir" in cmd or "get-childitem" in cmd)):
        events.append(_create_sem_event(event, "COLLECT_DOCUMENTS", 0.85, "HIGH", "TA0009", "T1005", "CollectDocumentsDetector@1.0", {"file_target": target or cmd}))

    # 2. Financial Files (T1005) - HIGH
    elif target.endswith(".xlsx") or target.endswith(".xls") or target.endswith(".csv") or "payroll" in target or "financial" in target or "budget" in target or "invoice" in target or ".xlsx" in cmd or "payroll" in cmd:
        events.append(_create_sem_event(event, "COLLECT_FINANCIAL_FILES", 0.90, "HIGH", "TA0009", "T1005", "CollectFinancialDetector@1.0", {"file_target": target or cmd}))

    # 3. Browser Data / Cookies (T1539 / T1005) - HIGH
    elif "history" in target and ("chrome" in target or "edge" in target or "firefox" in target):
        events.append(_create_sem_event(event, "COLLECT_BROWSER_DATA", 0.88, "HIGH", "TA0009", "T1005", "CollectBrowserDataDetector@1.0", {"file_target": target}))
    elif "cookies" in target and ("chrome" in target or "edge" in target or "firefox" in target):
        events.append(_create_sem_event(event, "COLLECT_BROWSER_COOKIES", 0.88, "HIGH", "TA0009", "T1539", "CollectBrowserCookiesDetector@1.0", {"file_target": target}))

    # 4. Email Data (T1114) - HIGH
    elif target.endswith(".pst") or target.endswith(".ost") or target.endswith(".eml") or target.endswith(".msg") or "outlook" in target:
        events.append(_create_sem_event(event, "COLLECT_EMAIL_DATA", 0.92, "HIGH", "TA0009", "T1114", "CollectEmailDataDetector@1.0", {"file_target": target}))

    # 5. Archives (T1560) - HIGH
    elif target.endswith(".zip") or target.endswith(".7z") or target.endswith(".tar") or target.endswith(".rar") or "7z.exe" in cmd or "rar.exe" in cmd or "zip" in cmd:
        events.append(_create_sem_event(event, "COLLECT_ARCHIVES", 0.88, "HIGH", "TA0009", "T1560", "CollectArchivesDetector@1.0", {"target": target or cmd}))

    # 6. Database Data (T1005) - HIGH
    elif target.endswith(".mdf") or target.endswith(".sqlite") or target.endswith(".db") or target.endswith(".sql") or "mysqldump" in cmd:
        events.append(_create_sem_event(event, "COLLECT_DATABASE_DATA", 0.90, "HIGH", "TA0009", "T1005", "CollectDatabaseDetector@1.0", {"target": target or cmd}))

    # 7. Source Code (T1005) - HIGH
    elif target.endswith(".py") or target.endswith(".java") or target.endswith(".cpp") or target.endswith(".cs") or target.endswith(".go") or target.endswith(".rs") or ".git" in target:
        events.append(_create_sem_event(event, "COLLECT_SOURCE_CODE", 0.85, "HIGH", "TA0009", "T1005", "CollectSourceCodeDetector@1.0", {"file_target": target}))

    # 8. Cloud Config (T1552.005) - HIGH
    elif "terraform" in target or ".aws" in target or ".azure" in target or "kubeconfig" in target or "config.json" in target and "docker" in target:
        events.append(_create_sem_event(event, "COLLECT_CLOUD_CONFIG", 0.90, "HIGH", "TA0009", "T1552.005", "CollectCloudConfigDetector@1.0", {"file_target": target}))

    # 9. SSH Keys (T1552.004) - HIGH
    elif ".ssh" in target and ("id_rsa" in target or "id_ed25519" in target or "authorized_keys" in target):
        events.append(_create_sem_event(event, "COLLECT_SSH_KEYS", 0.92, "HIGH", "TA0009", "T1552.004", "CollectSSHKeysDetector@1.0", {"file_target": target}))

    return events
