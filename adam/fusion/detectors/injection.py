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
def detect_process_injection(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects process injection techniques: Remote Thread, Hollowing, APC, Section Mapping, Reflective DLL, Doppelganging, and RWX memory allocations."""
    events = []
    cmd = (event.process.command_line or "").lower() if event.process else ""
    target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
    details = str(event.attributes.get("details", "")).lower()

    # 1. INJECT_REMOTE_THREAD (T1055.002) - CRITICAL / HIGH
    if "createremotethread" in cmd or "ntcreatethreadex" in cmd or ("target_pid" in event.attributes and event.attributes.get("call_trace", "").find("CreateRemoteThread") != -1):
        events.append(_create_sem_event(event, "INJECT_REMOTE_THREAD", 0.95, "CRITICAL", "TA0005", "T1055.002", "RemoteThreadInjectionDetector@1.0", {"details": cmd or details}))

    # 2. INJECT_PROCESS_HOLLOWING (T1055.012) - CRITICAL
    elif "process hollowing" in cmd or "zwunmapviewofsection" in cmd or "ntunmapviewofsection" in cmd:
        events.append(_create_sem_event(event, "INJECT_PROCESS_HOLLOWING", 0.98, "CRITICAL", "TA0005", "T1055.012", "ProcessHollowingDetector@1.0", {"details": cmd}))

    # 3. INJECT_APC (T1055.004) - CRITICAL
    elif "queueuserapc" in cmd or "ntqueueapcthread" in cmd:
        events.append(_create_sem_event(event, "INJECT_APC", 0.95, "CRITICAL", "TA0005", "T1055.004", "QueueUserAPCInjectionDetector@1.0", {"details": cmd}))

    # 4. INJECT_SECTION_MAPPING (T1055) - CRITICAL
    elif "ntmapviewofsection" in cmd or "zwmapviewofsection" in cmd:
        events.append(_create_sem_event(event, "INJECT_SECTION_MAPPING", 0.92, "CRITICAL", "TA0005", "T1055", "SectionMappingInjectionDetector@1.0", {"details": cmd}))

    # 5. INJECT_THREAD_CONTEXT (T1055.003) - HIGH
    elif "setthreadcontext" in cmd or "ntsetcontextthread" in cmd or "getthreadcontext" in cmd:
        events.append(_create_sem_event(event, "INJECT_THREAD_CONTEXT", 0.92, "HIGH", "TA0005", "T1055.003", "ThreadContextInjectionDetector@1.0", {"details": cmd}))

    # 6. INJECT_REFLECTIVE_DLL (T1055.001) - CRITICAL
    elif "reflectivedllinjection" in cmd or "reflective_dll" in cmd or "reflectivepe" in cmd:
        events.append(_create_sem_event(event, "INJECT_REFLECTIVE_DLL", 0.96, "CRITICAL", "TA0005", "T1055.001", "ReflectiveDLLInjectionDetector@1.0", {"details": cmd}))

    # 7. INJECT_PROCESS_DOPPELGANGING (T1055.013) - CRITICAL
    elif "process doppelganging" in cmd or "createtransaction" in cmd and "ntcreatesection" in cmd:
        events.append(_create_sem_event(event, "INJECT_PROCESS_DOPPELGANGING", 0.98, "CRITICAL", "TA0005", "T1055.013", "ProcessDoppelgangingDetector@1.0", {"details": cmd}))

    # 8. MEM_ALLOC_RWX / MEM_PROTECT_RWX (T1055) - HIGH
    elif "0x40" in details or "page_execute_readwrite" in details or "virtualalloc" in cmd and ("0x40" in cmd or "rwx" in cmd):
        events.append(_create_sem_event(event, "MEM_ALLOC_RWX", 0.90, "HIGH", "TA0005", "T1055", "MemoryAllocRWXDetector@1.0", {"details": details or cmd}))
    elif "virtualprotect" in cmd and ("0x40" in cmd or "rwx" in cmd) or ("virtualprotect" in details and "0x40" in details):
        events.append(_create_sem_event(event, "MEM_PROTECT_RWX", 0.90, "HIGH", "TA0005", "T1055", "MemoryProtectRWXDetector@1.0", {"details": details or cmd}))

    return events
