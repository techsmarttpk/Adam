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
    feat.setdefault("phase", "UNPACKING")
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
def detect_payload_unpacking(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects payload decryption, decompression, unpacking, reflective load, staged execution, and in-memory execution."""
    events = []
    cmd = (event.process.command_line or "").lower() if event.process else ""
    target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
    details = str(event.attributes.get("details", "")).lower()

    # 1. PAYLOAD_DECRYPTION (T1140) - HIGH
    if "cryptdecrypt" in cmd or "aes" in cmd and "decrypt" in cmd or "cryptderivekey" in cmd or "cryptdestroykey" in details:
        events.append(_create_sem_event(event, "PAYLOAD_DECRYPTION", 0.90, "HIGH", "TA0005", "T1140", "PayloadDecryptionDetector@1.0", {"details": cmd or details}))

    # 2. PAYLOAD_DECOMPRESSION (T1140) - HIGH
    elif "decompress" in cmd or "gzipstream" in cmd or "deflatestream" in cmd or "expand.exe" in cmd:
        events.append(_create_sem_event(event, "PAYLOAD_DECOMPRESSION", 0.88, "HIGH", "TA0005", "T1140", "PayloadDecompressionDetector@1.0", {"details": cmd}))

    # 3. PAYLOAD_UNPACKING (T1027.002) - HIGH
    elif "upx -d" in cmd or "unpack" in cmd or "self-extract" in details or "packed" in details:
        events.append(_create_sem_event(event, "PAYLOAD_UNPACKING", 0.92, "HIGH", "TA0005", "T1027.002", "PayloadUnpackingDetector@1.0", {"details": cmd or details}))

    # 4. PAYLOAD_REFLECTIVE_LOAD (T1620) - CRITICAL
    elif "reflectiveldr" in cmd or "loadlibraryr" in cmd or "memorymodule" in cmd:
        events.append(_create_sem_event(event, "PAYLOAD_REFLECTIVE_LOAD", 0.95, "CRITICAL", "TA0005", "T1620", "PayloadReflectiveLoadDetector@1.0", {"details": cmd}))

    # 5. PAYLOAD_STAGED_EXECUTION (T1105) - CRITICAL
    elif "downloadstring" in cmd and "iex" in cmd or "invoke-expression (new-object net.webclient)" in cmd or "stage2" in cmd:
        events.append(_create_sem_event(event, "PAYLOAD_STAGED_EXECUTION", 0.95, "CRITICAL", "TA0002", "T1105", "PayloadStagedExecutionDetector@1.0", {"command_line": cmd}))

    # 6. PAYLOAD_MEMORY_EXECUTION (T1620) - CRITICAL
    elif "virtualalloc" in cmd and "call" in cmd or "writeprocessmemory" in cmd and "rwx" in details or "runpe" in cmd:
        events.append(_create_sem_event(event, "PAYLOAD_MEMORY_EXECUTION", 0.95, "CRITICAL", "TA0005", "T1620", "PayloadMemoryExecutionDetector@1.0", {"details": cmd or details}))

    return events
