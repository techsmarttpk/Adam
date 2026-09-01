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
    feat.setdefault("phase", "C2_ESTABLISHMENT")
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
def detect_c2_beacon(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects outbound network connection beacons (T1071.001)."""
    events = []
    if event.category == EventCategory.NETWORK:
        dest_ip = event.attributes.get("destination_ip", "")
        dest_port = event.attributes.get("destination_port", 0)
        dest_host = event.attributes.get("destination_hostname", "")
        if dest_ip and dest_ip not in ("127.0.0.1", "0.0.0.0", "localhost") and not dest_ip.startswith("10.") and not dest_ip.startswith("192.168."):
            events.append(_create_sem_event(
                event, "C2_BEACON", 0.85, "HIGH", "TA0011", "T1071.001", "C2BeaconDetector@1.0",
                {"destination_ip": dest_ip, "destination_port": dest_port}
            ))
    return events

@register_detector
def detect_extended_c2(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects advanced C2 channels: DNS lookups, HTTP/S polling, DGA, Fast-Flux, Stage download, Command responses, Custom protocols."""
    events = []
    cmd = (event.process.command_line or "").lower() if event.process else ""
    
    if event.category == EventCategory.NETWORK:
        dest_ip = str(event.attributes.get("destination_ip", ""))
        dest_port = int(event.attributes.get("destination_port", 0) or 0)
        dest_host = str(event.attributes.get("destination_hostname", "") or "").lower()
        protocol = str(event.attributes.get("protocol", "") or "").lower()
        uri = str(event.attributes.get("uri", "") or "").lower()

        # 1. DNS Lookup (T1071.004) - MEDIUM
        if dest_port == 53 or protocol == "dns" or "query_name" in event.attributes:
            qname = event.attributes.get("query_name", dest_host)
            events.append(_create_sem_event(event, "C2_DNS_LOOKUP", 0.85, "MEDIUM", "TA0011", "T1071.004", "DNSLookupDetector@1.0", {"query_name": qname}))

        # 2. DGA Activity (T1568.002) - CRITICAL
        if dest_host and (len(dest_host.split(".")[0]) > 14 and sum(c.isdigit() for c in dest_host) > 4):
            events.append(_create_sem_event(event, "C2_DGA_ACTIVITY", 0.92, "CRITICAL", "TA0011", "T1568.002", "DGADetector@1.0", {"dga_domain": dest_host}))

        # 3. HTTP / HTTPS Polling (T1071.001) - HIGH
        if dest_port == 80 or protocol == "http":
            events.append(_create_sem_event(event, "C2_HTTP_POLLING", 0.88, "HIGH", "TA0011", "T1071.001", "HTTPPollingDetector@1.0", {"destination_ip": dest_ip, "uri": uri}))
        elif dest_port == 443 or protocol == "https":
            events.append(_create_sem_event(event, "C2_HTTPS_POLLING", 0.88, "HIGH", "TA0011", "T1071.001", "HTTPSPollingDetector@1.0", {"destination_ip": dest_ip}))

        # 4. IP Direct Connect (T1095) - HIGH
        if dest_ip and not dest_host and dest_port not in (80, 443, 53) and not dest_ip.startswith("10.") and not dest_ip.startswith("192.168."):
            events.append(_create_sem_event(event, "C2_IP_DIRECT_CONNECT", 0.88, "HIGH", "TA0011", "T1095", "IPDirectConnectDetector@1.0", {"destination_ip": dest_ip, "port": dest_port}))

        # 5. Fast Flux Activity (T1568.001) - CRITICAL
        if event.attributes.get("fast_flux") is True or event.attributes.get("ttl", 300) < 60:
            events.append(_create_sem_event(event, "C2_FAST_FLUX_ACTIVITY", 0.90, "CRITICAL", "TA0011", "T1568.001", "FastFluxDetector@1.0", {"hostname": dest_host}))

        # 6. Proxy Communication (T1090) - MEDIUM
        if event.attributes.get("is_proxy") or dest_port in (8080, 3128, 1080):
            events.append(_create_sem_event(event, "C2_PROXY_COMMUNICATION", 0.85, "MEDIUM", "TA0011", "T1090", "ProxyCommDetector@1.0", {"destination_ip": dest_ip, "port": dest_port}))

        # 7. Custom / Encrypted Channel (T1026 / T1573) - HIGH
        if protocol in ("custom_raw", "tcp_raw") or event.attributes.get("encrypted_payload"):
            events.append(_create_sem_event(event, "C2_CUSTOM_PROTOCOL", 0.90, "HIGH", "TA0011", "T1026", "CustomProtocolDetector@1.0", {"port": dest_port}))

        # 8. Command Response / Stage Download (T1105) - CRITICAL
        if uri.endswith(".exe") or uri.endswith(".dll") or uri.endswith(".ps1") or uri.endswith(".bin") or "stage" in uri:
            events.append(_create_sem_event(event, "C2_STAGE_DOWNLOAD", 0.95, "CRITICAL", "TA0011", "T1105", "StageDownloadDetector@1.0", {"uri": uri, "host": dest_host}))
        elif "command" in uri or "tasks" in uri or "result" in uri:
            events.append(_create_sem_event(event, "C2_COMMAND_RESPONSE", 0.90, "CRITICAL", "TA0011", "T1071", "CommandResponseDetector@1.0", {"uri": uri}))

    elif event.category == EventCategory.PROCESS and event.process:
        if "curl" in cmd or "certutil -urlcache" in cmd or "bitsadmin /transfer" in cmd or "wget" in cmd or "invoke-webrequest" in cmd:
            events.append(_create_sem_event(event, "C2_STAGE_DOWNLOAD", 0.92, "CRITICAL", "TA0011", "T1105", "StageDownloadDetector@1.0", {"command_line": cmd}))

    return events
