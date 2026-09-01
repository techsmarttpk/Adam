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
    feat.setdefault("phase", "EXECUTION")
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
def detect_execution_interpreter(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects standard script, shell, proxy, and LOLBAS execution tools."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        image = (event.process.image or "").lower()
        
        interpreters = [
            # Shells & Interpreters
            ("powershell", "EXEC_POWERSHELL", "TA0002", "T1059.001", 0.90, "MEDIUM"),
            ("pwsh", "EXEC_POWERSHELL", "TA0002", "T1059.001", 0.90, "MEDIUM"),
            ("cmd.exe", "EXEC_CMD", "TA0002", "T1059.003", 0.90, "MEDIUM"),
            ("wscript.exe", "EXEC_WSCRIPT", "TA0002", "T1059.005", 0.92, "MEDIUM"),
            ("cscript.exe", "EXEC_CSCRIPT", "TA0002", "T1059.005", 0.92, "MEDIUM"),
            ("mshta.exe", "EXEC_MSHTA", "TA0002", "T1218.005", 0.95, "HIGH"),
            ("rundll32.exe", "EXEC_RUNDLL32", "TA0002", "T1218.011", 0.92, "MEDIUM"),
            ("regsvr32.exe", "EXEC_REGSVR32", "TA0002", "T1218.010", 0.95, "MEDIUM"),
            
            # LOLBAS Execution Primitives
            ("wmic.exe", "EXEC_WMI", "TA0002", "T1047", 0.92, "MEDIUM"),
            ("msbuild.exe", "EXEC_MSBUILD", "TA0002", "T1127.001", 0.95, "HIGH"),
            ("installutil.exe", "EXEC_INSTALLUTIL", "TA0002", "T1218.004", 0.95, "HIGH"),
            ("certutil.exe", "EXEC_CERTUTIL", "TA0002", "T1140", 0.92, "MEDIUM"),
            ("bitsadmin.exe", "EXEC_BITSADMIN", "TA0002", "T1197", 0.90, "MEDIUM"),
            ("control.exe", "EXEC_CONTROL", "TA0002", "T1218.002", 0.90, "MEDIUM"),
            ("forfiles.exe", "EXEC_FORFILES", "TA0002", "T1202", 0.90, "LOW"),
            ("schtasks.exe", "EXEC_SCHTASKS", "TA0002", "T1053.005", 0.90, "MEDIUM"),
            ("netsh.exe", "EXEC_NETSH", "TA0002", "T1562.004", 0.88, "LOW"),
            ("wbadmin.exe", "EXEC_WBADMIN", "TA0002", "T1490", 0.92, "HIGH"),
        ]
        
        for name, intent, tactic, tech, conf, sev in interpreters:
            if name in image or (name in cmd and name not in ("cmd.exe", "powershell.exe")):
                events.append(_create_sem_event(
                    event, intent, conf, sev, tactic, tech,
                    f"{intent.title().replace('_', '')}Detector@1.0",
                    {"command_line": cmd, "image": image}
                ))
                break
    return events
