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
    feat.setdefault("phase", "DISCOVERY")
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
def detect_malware_configuration_search(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects malware searching for its own configuration: C2 config, Campaign ID, Operator ID, Encryption keys, Mutexes, Deployment ID."""
    events = []
    cmd = (event.process.command_line or "").lower() if event.process else ""
    target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()

    # 1. C2 Config Search (T1082) - MEDIUM
    if "c2_config" in target or "server.ini" in target or "config.json" in target and "c2" in cmd or "bot.conf" in target:
        events.append(_create_sem_event(event, "CONFIG_C2_CONFIG_SEARCH", 0.88, "MEDIUM", "TA0007", "T1082", "C2ConfigSearchDetector@1.0", {"target": target or cmd}))

    # 2. Campaign ID Search (T1082) - MEDIUM
    elif "campaign_id" in target or "camp_id" in cmd or "affiliate_id" in target:
        events.append(_create_sem_event(event, "CONFIG_CAMPAIGN_ID_SEARCH", 0.88, "MEDIUM", "TA0007", "T1082", "CampaignIDSearchDetector@1.0", {"target": target or cmd}))

    # 3. Operator ID Search (T1082) - MEDIUM
    elif "operator_id" in target or "op_id" in cmd or "sub_id" in target:
        events.append(_create_sem_event(event, "CONFIG_OPERATOR_ID_SEARCH", 0.85, "MEDIUM", "TA0007", "T1082", "OperatorIDSearchDetector@1.0", {"target": target or cmd}))

    # 4. Encryption Key Search (T1082) - HIGH
    elif "master_key" in target or "public_key.pem" in target or "rsa_pub" in target or "encryption_key" in cmd:
        events.append(_create_sem_event(event, "CONFIG_ENCRYPTION_KEY_SEARCH", 0.90, "HIGH", "TA0007", "T1082", "EncryptionKeySearchDetector@1.0", {"target": target or cmd}))

    # 5. Mutex Search (T1082) - MEDIUM
    elif "mutex_name" in cmd or "global\\\\" in cmd or "basenamedobjects" in target:
        events.append(_create_sem_event(event, "CONFIG_MUTEX_SEARCH", 0.85, "MEDIUM", "TA0007", "T1082", "MutexSearchDetector@1.0", {"target": target or cmd}))

    # 6. Deployment ID Search (T1082) - MEDIUM
    elif "build_id" in target or "deployment_id" in target or "version.txt" in target and "build" in cmd:
        events.append(_create_sem_event(event, "CONFIG_DEPLOYMENT_ID_SEARCH", 0.85, "MEDIUM", "TA0007", "T1082", "DeploymentIDSearchDetector@1.0", {"target": target or cmd}))

    return events
