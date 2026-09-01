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
    feat.setdefault("phase", "IMPACT")
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
def detect_shadow_copy_delete(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects Volume Shadow Copy deletion (T1490)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if ("vssadmin" in cmd and "delete shadows" in cmd) or ("wmic" in cmd and "shadowcopy delete" in cmd) or "wbadmin delete" in cmd:
            events.append(_create_sem_event(event, "IMPACT_SHADOW_COPY_DELETE", 0.98, "CRITICAL", "TA0040", "T1490", "ShadowCopyDeletionDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_ransom_note_drop(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects ransom note drops (T1486)."""
    events = []
    if event.category == EventCategory.FILE:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if "readme" in target and (".txt" in target or ".html" in target) or "how_to_decrypt" in target or "restore_files" in target or "ransom" in target:
            events.append(_create_sem_event(event, "IMPACT_RANSOM_NOTE_DROP", 0.90, "HIGH", "TA0040", "T1486", "RansomNoteDetector@1.0", {"file_target": target}))
    return events

@register_detector
def detect_extended_impact_and_ransomware(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects advanced ransomware lifecycle and system impact techniques."""
    events = []
    cmd = (event.process.command_line or "").lower() if event.process else ""
    target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()

    # 1. Mass file encryption (T1486) - CRITICAL
    if event.category == EventCategory.FILE and (target.endswith(".locked") or target.endswith(".encrypted") or target.endswith(".crypto")):
        events.append(_create_sem_event(event, "IMPACT_MASS_FILE_ENCRYPT", 0.95, "CRITICAL", "TA0040", "T1486", "MassEncryptDetector@1.0", {"file_target": target}))

    # 2. File Destruction / Disk Wipe (T1485 / T1561) - CRITICAL
    elif "sdelete" in cmd or "cipher /w" in cmd or "fsutil volume clean" in cmd:
        events.append(_create_sem_event(event, "IMPACT_FILE_DESTRUCTION", 0.95, "CRITICAL", "TA0040", "T1485", "FileDestructionDetector@1.0", {"command_line": cmd}))
    elif "\\\\.\\physicaldrive" in cmd or "diskpart" in cmd and "clean" in cmd:
        events.append(_create_sem_event(event, "IMPACT_DISK_WIPE", 0.98, "CRITICAL", "TA0040", "T1561", "DiskWipeDetector@1.0", {"command_line": cmd}))

    # 3. Service Stop (T1489) - HIGH
    elif ("net stop" in cmd or "sc stop" in cmd or "stop-service" in cmd) and ("sql" in cmd or "exchange" in cmd or "backup" in cmd or "veeam" in cmd):
        events.append(_create_sem_event(event, "IMPACT_SERVICE_STOP", 0.92, "HIGH", "TA0040", "T1489", "ServiceStopDetector@1.0", {"command_line": cmd}))

    # 4. Security Tool Disable (T1562.001) - CRITICAL
    elif "taskkill /f /im" in cmd and ("msmpeng.exe" in cmd or "sentinel" in cmd or "carbonblack" in cmd):
        events.append(_create_sem_event(event, "IMPACT_SECURITY_TOOL_DISABLE", 0.98, "CRITICAL", "TA0040", "T1562.001", "SecurityToolDisableDetector@1.0", {"command_line": cmd}))

    # 5. System Recovery Disable / Backup Targeting (T1490) - CRITICAL
    elif "bcdedit" in cmd and ("recoveryenabled no" in cmd or "bootstatuspolicy ignoreallfailures" in cmd):
        events.append(_create_sem_event(event, "IMPACT_SYSTEM_RECOVERY_DISABLE", 0.98, "CRITICAL", "TA0040", "T1490", "SystemRecoveryDisableDetector@1.0", {"command_line": cmd}))
    elif "wbadmin delete catalog" in cmd or "wbadmin delete systemstatebackup" in cmd:
        events.append(_create_sem_event(event, "IMPACT_BACKUP_TARGETING", 0.98, "CRITICAL", "TA0040", "T1490", "BackupTargetingDetector@1.0", {"command_line": cmd}))

    # 6. Ransomware Granular Lifecycle Intents
    elif "enum" in cmd and ("c:\\" in cmd or "d:\\" in cmd) and ("*.doc" in cmd or "*.pdf" in cmd):
        events.append(_create_sem_event(event, "RANSOM_FILE_ENUMERATION", 0.88, "HIGH", "TA0040", "T1486", "RansomFileEnumDetector@1.0", {"command_line": cmd}))
    elif "cryptgenrandom" in cmd or "cryptacquirecontext" in cmd or "cryptgenkey" in cmd:
        events.append(_create_sem_event(event, "RANSOM_KEY_GENERATION", 0.92, "CRITICAL", "TA0040", "T1486", "RansomKeyGenDetector@1.0", {"command_line": cmd}))
    elif "readme.txt" in target or "decrypt_instructions" in target:
        events.append(_create_sem_event(event, "RANSOM_NOTE_DEPLOYMENT", 0.92, "HIGH", "TA0040", "T1486", "RansomNoteDeployDetector@1.0", {"file_target": target}))
    elif "target_extensions" in cmd or "whitelist" in cmd and "encrypt" in cmd:
        events.append(_create_sem_event(event, "RANSOM_TARGET_SELECTION", 0.90, "CRITICAL", "TA0040", "T1486", "RansomTargetSelectionDetector@1.0", {"command_line": cmd}))
    elif "start_encryption" in cmd or "encrypt_thread" in cmd:
        events.append(_create_sem_event(event, "RANSOM_ENCRYPTION_START", 0.95, "CRITICAL", "TA0040", "T1486", "RansomEncryptionStartDetector@1.0", {"command_line": cmd}))
    elif "bcdedit /set {default} bootstatuspolicy ignoreallfailures" in cmd:
        events.append(_create_sem_event(event, "RANSOM_RECOVERY_DISABLE", 0.98, "CRITICAL", "TA0040", "T1490", "RansomRecoveryDisableDetector@1.0", {"command_line": cmd}))
    elif "prepare_ransom" in cmd:
        events.append(_create_sem_event(event, "RANSOM_PREPARATION", 0.88, "HIGH", "TA0040", "T1486", "RansomPrepDetector@1.0", {"command_line": cmd}))

    return events
