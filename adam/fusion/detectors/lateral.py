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
    feat.setdefault("phase", "LATERAL_MOVEMENT")
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
def detect_lateral_smb(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects SMB lateral movement and remote file execution probes (T1021.002)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "net use" in cmd and ("\\\\" in cmd or "/user" in cmd) or "psexec" in cmd:
            events.append(_create_sem_event(event, "LATERAL_SMB_ENUM", 0.92, "HIGH", "TA0008", "T1021.002", "LateralSMBDetector@1.0", {"command_line": cmd}))
    elif event.category == EventCategory.NETWORK:
        dest_port = event.attributes.get("destination_port", 0)
        if dest_port in (445, 139):
            events.append(_create_sem_event(event, "LATERAL_SMB_ENUM", 0.88, "HIGH", "TA0008", "T1021.002", "LateralSMBDetector@1.0", {"destination_port": dest_port}))
    return events

@register_detector
def detect_extended_lateral(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects SMB share access, admin share enum, RDP, WinRM, WMI remote exec, remote services, domain trust, and DC discovery."""
    events = []
    cmd = (event.process.command_line or "").lower() if event.process else ""
    target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()

    # 1. Admin Share Enumeration (T1135) - HIGH
    if "c$" in cmd or "admin$" in cmd or "ipc$" in cmd or "\\c$" in target or "\\admin$" in target:
        events.append(_create_sem_event(event, "LATERAL_ADMIN_SHARE_ENUM", 0.92, "HIGH", "TA0008", "T1135", "AdminShareEnumDetector@1.0", {"target": target or cmd}))

    # 2. RDP Discovery & Connection (T1021.001) - HIGH / CRITICAL
    elif "mstsc" in cmd or "rdesktop" in cmd or (event.category == EventCategory.NETWORK and event.attributes.get("destination_port") == 3389):
        events.append(_create_sem_event(event, "LATERAL_RDP_CONNECTION", 0.95, "CRITICAL", "TA0008", "T1021.001", "RDPConnectionDetector@1.0", {"details": cmd or str(event.attributes)}))
    elif "portqry" in cmd and "3389" in cmd or "test-netconnection" in cmd and "3389" in cmd:
        events.append(_create_sem_event(event, "LATERAL_RDP_DISCOVERY", 0.90, "HIGH", "TA0008", "T1021.001", "RDPDiscoveryDetector@1.0", {"command_line": cmd}))

    # 3. WinRM Discovery & Execution (T1021.006) - HIGH / CRITICAL
    elif "enter-pssession" in cmd or "invoke-command" in cmd and "-computername" in cmd or "winrs" in cmd:
        events.append(_create_sem_event(event, "LATERAL_WINRM_EXECUTION", 0.95, "CRITICAL", "TA0008", "T1021.006", "WinRMExecutionDetector@1.0", {"command_line": cmd}))
    elif (event.category == EventCategory.NETWORK and event.attributes.get("destination_port") in (5985, 5986)) or "5985" in cmd:
        events.append(_create_sem_event(event, "LATERAL_WINRM_DISCOVERY", 0.90, "HIGH", "TA0008", "T1021.006", "WinRMDiscoveryDetector@1.0", {"command_line": cmd}))

    # 4. WMI Remote Execution (T1047) - CRITICAL
    elif "wmic" in cmd and "/node:" in cmd and "process call create" in cmd:
        events.append(_create_sem_event(event, "LATERAL_WMI_REMOTE_EXEC", 0.98, "CRITICAL", "TA0008", "T1047", "WMIRemoteExecDetector@1.0", {"command_line": cmd}))

    # 5. Remote Service Creation (T1543.003 / T1021) - HIGH
    elif "sc" in cmd and "\\\\" in cmd and "create" in cmd:
        events.append(_create_sem_event(event, "LATERAL_REMOTE_SERVICE", 0.95, "HIGH", "TA0008", "T1543.003", "RemoteServiceDetector@1.0", {"command_line": cmd}))

    # 6. Domain Trust Discovery (T1482) - CRITICAL
    elif "nltest /domain_trusts" in cmd or "get-adtrust" in cmd or "netdom trust" in cmd:
        events.append(_create_sem_event(event, "LATERAL_DOMAIN_TRUST_DISCOVERY", 0.95, "CRITICAL", "TA0008", "T1482", "DomainTrustDetector@1.0", {"command_line": cmd}))

    # 7. DC Discovery (T1018) - CRITICAL
    elif "nltest /dclist:" in cmd or "get-addomaincontroller" in cmd:
        events.append(_create_sem_event(event, "LATERAL_DC_DISCOVERY", 0.95, "CRITICAL", "TA0008", "T1018", "DCDiscoveryDetector@1.0", {"command_line": cmd}))

    # 8. Host Discovery / Ping Sweep (T1018) - HIGH
    elif "nbtstat -a" in cmd or "ping -n 1 192.168." in cmd or "test-connection" in cmd:
        events.append(_create_sem_event(event, "LATERAL_HOST_DISCOVERY", 0.88, "HIGH", "TA0008", "T1018", "HostDiscoveryDetector@1.0", {"command_line": cmd}))

    return events
