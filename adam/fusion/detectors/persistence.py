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
    feat.setdefault("phase", "PERSISTENCE")
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
def detect_run_key_persistence(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects registry Run/RunOnce key persistence modifications (T1547.001)."""
    events = []
    if event.category == EventCategory.REGISTRY:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if "currentversion\\run" in target or "currentversion\\runonce" in target:
            events.append(_create_sem_event(event, "PERSIST_RUN_KEY", 0.92, "HIGH", "TA0003", "T1547.001", "RunKeyPersistenceDetector@1.0", {"registry_target": target}))
    elif event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "reg " in cmd and "add" in cmd and ("\\run" in cmd or "\\runonce" in cmd):
            events.append(_create_sem_event(event, "PERSIST_RUN_KEY", 0.92, "HIGH", "TA0003", "T1547.001", "RunKeyPersistenceDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_scheduled_task_persistence(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects scheduled task persistence (T1053.005)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "schtasks" in cmd and ("/create" in cmd or "-create" in cmd) or "register-scheduledtask" in cmd:
            events.append(_create_sem_event(event, "PERSIST_SCHEDULED_TASK", 0.95, "HIGH", "TA0003", "T1053.005", "ScheduledTaskPersistenceDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_service_persistence(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects new service creation persistence (T1543.003)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if ("sc.exe" in cmd or "sc " in cmd) and "create" in cmd or "new-service" in cmd:
            events.append(_create_sem_event(event, "PERSIST_SERVICE", 0.95, "HIGH", "TA0003", "T1543.003", "ServicePersistenceDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_wmi_subscription_persistence(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects WMI event subscription persistence (T1546.003)."""
    events = []
    if event.category == EventCategory.WMI or (event.category == EventCategory.PROCESS and event.process):
        cmd = (event.process.command_line or "").lower() if event.process else ""
        if "__eventfilter" in cmd or "__eventconsumer" in cmd or "__filtertoconsumerbinding" in cmd or event.category == EventCategory.WMI:
            events.append(_create_sem_event(event, "PERSIST_WMI_SUBSCRIPTION", 0.90, "HIGH", "TA0003", "T1546.003", "WMISubscriptionDetector@1.0", {"details": cmd or str(event.attributes)}))
    return events

@register_detector
def detect_extended_persistence(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects startup folder, sideloading, BITS, boot, logon scripts, COM hijack, IFEO, Office addin, etc."""
    events = []
    target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
    cmd = (event.process.command_line or "").lower() if event.process else ""

    # 1. Startup folder (T1547.001)
    if ("microsoft\\windows\\start menu\\programs\\startup" in target) or ("start menu\\programs\\startup" in cmd):
        events.append(_create_sem_event(event, "PERSIST_STARTUP_FOLDER", 0.92, "MEDIUM", "TA0003", "T1547.001", "StartupFolderDetector@1.0", {"target": target or cmd}))

    # 2. DLL Sideloading / Search Order (T1574.001 / T1574.002)
    elif "known_dlls" in target or "app paths" in target:
        events.append(_create_sem_event(event, "PERSIST_DLL_SEARCH_ORDER", 0.88, "HIGH", "TA0003", "T1574.001", "DLLSearchOrderDetector@1.0", {"target": target}))
    elif event.category == EventCategory.FILE and target.endswith(".dll") and ("system32" not in target and "syswow64" not in target and ("program files" in target or "appdata" in target)):
        events.append(_create_sem_event(event, "PERSIST_DLL_SIDELOAD", 0.85, "HIGH", "TA0003", "T1574.002", "DLLSideloadDetector@1.0", {"file_target": target}))

    # 3. BITS Job (T1197)
    elif "bitsadmin" in cmd and ("/create" in cmd or "/addfile" in cmd or "/resume" in cmd):
        events.append(_create_sem_event(event, "PERSIST_BITS_JOB", 0.90, "HIGH", "TA0003", "T1197", "BITSJobDetector@1.0", {"command_line": cmd}))

    # 4. Boot Execution / Winlogon (T1547.004)
    elif "software\\microsoft\\windows nt\\currentversion\\winlogon" in target:
        events.append(_create_sem_event(event, "PERSIST_BOOT_EXECUTION", 0.95, "HIGH", "TA0003", "T1547.004", "BootExecutionDetector@1.0", {"target": target}))

    # 5. Logon Script (T1037.001)
    elif "userinitmprlogonscript" in target or "environment\\userinit" in target:
        events.append(_create_sem_event(event, "PERSIST_LOGON_SCRIPT", 0.92, "MEDIUM", "TA0003", "T1037.001", "LogonScriptDetector@1.0", {"target": target}))

    # 6. WMI Event Filter (T1546.003)
    elif "__eventfilter" in target or "__filtertoconsumerbinding" in target:
        events.append(_create_sem_event(event, "PERSIST_WMI_EVENT_FILTER", 0.92, "HIGH", "TA0003", "T1546.003", "WMIEventFilterDetector@1.0", {"target": target}))

    # 7. Service Modification (T1543.003)
    elif ("sc.exe" in cmd or "sc " in cmd) and ("config" in cmd or "failure" in cmd):
        events.append(_create_sem_event(event, "PERSIST_SERVICE_MODIFICATION", 0.90, "HIGH", "TA0003", "T1543.003", "ServiceModificationDetector@1.0", {"command_line": cmd}))

    # 8. COM Hijacking (T1546.015)
    elif "classes\\clsid" in target and "inprocserver32" in target:
        events.append(_create_sem_event(event, "PERSIST_COM_HIJACK", 0.92, "HIGH", "TA0003", "T1546.015", "COMHijackDetector@1.0", {"target": target}))

    # 9. IFEO Image File Execution Options (T1546.012)
    elif "image file execution options" in target and "debugger" in target:
        events.append(_create_sem_event(event, "PERSIST_IFEO", 0.95, "HIGH", "TA0003", "T1546.012", "IFEODetector@1.0", {"target": target}))

    # 10. Office Add-in (T1137)
    elif "software\\microsoft\\office" in target and "addins" in target:
        events.append(_create_sem_event(event, "PERSIST_OFFICE_ADDIN", 0.90, "HIGH", "TA0003", "T1137", "OfficeAddinDetector@1.0", {"target": target}))

    return events
