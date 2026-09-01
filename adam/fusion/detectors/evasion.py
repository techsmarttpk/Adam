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
def detect_sandbox_hardware_check(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects checks for virtualization/sandbox hardware descriptors (T1497.001)."""
    events = []
    if event.category == EventCategory.REGISTRY:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        details = str(event.attributes.get("details", "")).lower()
        if "biosversion" in target or "systembiosversion" in target or "videobiosversion" in target:
            if "vbox" in details or "qemu" in details or "virtualbox" in details or "vmware" in details or "bochs" in details or "red hat" in details:
                events.append(_create_sem_event(event, "SANDBOX_HARDWARE_CHECK", 0.92, "HIGH", "TA0005", "T1497.001", "SandboxHardwareCheckDetector@1.0", {"virtualization_keyword": details}))
    elif event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if ("wmic" in cmd and "bios" in cmd) or ("systembiosversion" in cmd) or ("wmic" in cmd and "computersystem get model" in cmd):
            events.append(_create_sem_event(event, "SANDBOX_HARDWARE_CHECK", 0.90, "HIGH", "TA0005", "T1497.001", "SandboxHardwareCheckDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_sandbox_registry_check(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects registry queries probing for virtualization keys (T1497.001)."""
    events = []
    if event.category == EventCategory.REGISTRY:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if ("software\\oracle\\virtualbox" in target or "software\\vmware, inc." in target or "system\\currentcontrolset\\services\\vbox" in target or "system\\currentcontrolset\\services\\qemu" in target):
            events.append(_create_sem_event(event, "SANDBOX_REGISTRY_CHECK", 0.90, "HIGH", "TA0005", "T1497.001", "SandboxRegistryCheckDetector@1.0", {"registry_target": target}))
    return events

@register_detector
def detect_sandbox_process_check(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects checks for analysis tools / sandbox agent processes (T1497.001)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        analysis_tools = ["wireshark", "procmon", "procexp", "x64dbg", "ida64", "fiddler", "vboxservice", "vboxtray"]
        for tool in analysis_tools:
            if tool in cmd and ("tasklist" in cmd or "get-process" in cmd or "findstr" in cmd):
                events.append(_create_sem_event(event, "SANDBOX_PROCESS_CHECK", 0.92, "HIGH", "TA0005", "T1497.001", "SandboxProcessCheckDetector@1.0", {"targeted_tool": tool, "command_line": cmd}))
                break
    return events

@register_detector
def detect_sandbox_user_activity_check(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects probing for user presence / activity / mouse dwell (T1497.002)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "getcursorpos" in cmd or "getlastinputinfo" in cmd or "getasynckeystate" in cmd or "recent" in cmd:
            events.append(_create_sem_event(event, "SANDBOX_USER_ACTIVITY_CHECK", 0.88, "MEDIUM", "TA0005", "T1497.002", "SandboxUserActivityDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_sandbox_time_delay_check(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects extended sleep delay or time-acceleration detection (T1497.003)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if ("start-sleep" in cmd or "timeout /t" in cmd or "ping -n " in cmd or "waitfor" in cmd) and ("30" in cmd or "60" in cmd or "120" in cmd or "300" in cmd):
            events.append(_create_sem_event(event, "SANDBOX_TIME_DELAY_CHECK", 0.85, "MEDIUM", "TA0005", "T1497.003", "SandboxTimeDelayDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_sandbox_evasion_composite(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Composite broad semantic summary when evasion signals are detected (T1497)."""
    events = []
    if event.category == EventCategory.REGISTRY:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        details = str(event.attributes.get("details", "")).lower()
        if ("biosversion" in target or "systembiosversion" in target or "videobiosversion" in target) and ("qemu" in details or "vbox" in details):
            events.append(_create_sem_event(event, "EVADE_SANDBOX_DETECTED", 0.90, "HIGH", "TA0005", "T1497", "SandboxEvasionDetector@1.0", {"virtualization_keyword": details}))
    return events

@register_detector
def detect_extended_defense_evasion(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects specific defense evasion techniques (AMSI bypass, ETW tampering, Defender tampering, Debugger checks, VM artifacts, unhooking)."""
    events = []
    cmd = (event.process.command_line or "").lower() if event.process else ""
    target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
    details = str(event.attributes.get("details", "")).lower()

    # 1. AMSI Bypass (T1562.001) - HIGH
    if "amsiutils" in cmd or "amsiinitfailed" in cmd or "amsiscanbuffer" in cmd:
        events.append(_create_sem_event(event, "EVADE_AMSI_BYPASS", 0.96, "HIGH", "TA0005", "T1562.001", "AMSIBypassDetector@1.0", {"command_line": cmd}))

    # 2. ETW Tampering (T1562.006) - HIGH
    if "etweventwrite" in cmd or "eventprovider" in cmd or "wevtutil set-log" in cmd:
        events.append(_create_sem_event(event, "EVADE_ETW_TAMPERING", 0.94, "HIGH", "TA0005", "T1562.006", "ETWTamperingDetector@1.0", {"command_line": cmd}))

    # 3. Defender Tampering (T1562.001) - HIGH
    if ("set-mppreference" in cmd and ("-disablerealtime" in cmd or "-disablebehavior" in cmd or "-exclusionpath" in cmd)) or "disablerealtimemonitoring" in target:
        events.append(_create_sem_event(event, "EVADE_DEFENDER_TAMPERING", 0.95, "HIGH", "TA0005", "T1562.001", "DefenderTamperingDetector@1.0", {"target": target or cmd}))

    # 4. Firewall Check / Modification (T1562.004) - MEDIUM
    if "netsh advfirewall set" in cmd or "netsh firewall set" in cmd:
        events.append(_create_sem_event(event, "EVADE_FIREWALL_CHECK", 0.88, "MEDIUM", "TA0005", "T1562.004", "FirewallCheckDetector@1.0", {"command_line": cmd}))

    # 5. Event Log Clear (T1070.001) - CRITICAL
    if "wevtutil cl" in cmd or "clear-eventlog" in cmd:
        events.append(_create_sem_event(event, "EVADE_EVENT_LOG_CLEAR", 0.98, "CRITICAL", "TA0005", "T1070.001", "EventLogClearDetector@1.0", {"command_line": cmd}))

    # 6. Debugger Check (T1497.001 / T1622) - HIGH
    if "isdebuggerpresent" in cmd or "checkremotedebuggerpresent" in cmd or "ntqueryinformationprocess" in cmd:
        events.append(_create_sem_event(event, "EVADE_DEBUGGER_CHECK", 0.92, "HIGH", "TA0005", "T1622", "DebuggerCheckDetector@1.0", {"command_line": cmd}))

    # 7. VM Artifact Check (T1497.001) - CRITICAL
    if "vmware" in details or "vbox" in details or "vboxguest" in target or "vmsrvc" in cmd or "qemu" in details or "systembiosversion" in target:
        events.append(_create_sem_event(event, "EVADE_VM_ARTIFACT_CHECK", 0.95, "CRITICAL", "TA0005", "T1497.001", "VMArtifactCheckDetector@1.0", {"details": details or target or cmd}))

    # 8. Analysis Tool Check (T1497.001) - CRITICAL
    if "procmon64.exe" in cmd or "wireshark.exe" in cmd or "x32dbg.exe" in cmd or "fiddler.exe" in cmd:
        events.append(_create_sem_event(event, "EVADE_ANALYSIS_TOOL_CHECK", 0.95, "CRITICAL", "TA0005", "T1497.001", "AnalysisToolCheckDetector@1.0", {"command_line": cmd}))

    # 9. Sandbox User Profile (T1497.001) - HIGH
    if "testuser" in cmd or "sandbox" in cmd or "john doe" in cmd or "currentuser" in cmd:
        events.append(_create_sem_event(event, "EVADE_SANDBOX_USER_PROFILE", 0.85, "HIGH", "TA0005", "T1497.001", "SandboxUserProfileDetector@1.0", {"command_line": cmd}))

    # 10. Time Delay Check (T1497.003) - HIGH
    elif "gettickcount" in cmd or "rdtsc" in cmd or "queryperformancecounter" in cmd:
        events.append(_create_sem_event(event, "EVADE_TIMING_CHECK", 0.88, "HIGH", "TA0005", "T1497.003", "TimingCheckDetector@1.0", {"command_line": cmd}))

    # 11. Mutex Check (T1497) - MEDIUM
    elif "createmutex" in cmd or "openmutex" in cmd:
        events.append(_create_sem_event(event, "EVADE_MUTEX_CHECK", 0.85, "MEDIUM", "TA0005", "T1497", "MutexCheckDetector@1.0", {"command_line": cmd}))

    # 12. Parent Process Check (T1497.001) - HIGH
    elif "parentprocessid" in cmd or "ppid" in cmd or "get-ciminstance win32_process" in cmd:
        events.append(_create_sem_event(event, "EVADE_PARENT_PROCESS_CHECK", 0.88, "HIGH", "TA0005", "T1497.001", "ParentProcessCheckDetector@1.0", {"command_line": cmd}))

    return events
