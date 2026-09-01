"""Predictive DNS Sinkholing and Interactive Synthetic C2 Listener.

Intercepts Domain Generation Algorithm (DGA) and fast-flux queries in an air-gapped network.
Emulates common C2 protocol responses (e.g. Cobalt Strike, HTTP/HTTPS staged payloads)
to trick malware into executing its secondary attack routines and payload stages.
"""

from __future__ import annotations
import dataclasses
import enum
import hashlib
import time
from typing import Dict, List, Optional


class C2ProtocolType(enum.Enum):
    COBALT_STRIKE = "COBALT_STRIKE"
    HTTP_BEACON = "HTTP_BEACON"
    DNS_TUNNEL = "DNS_TUNNEL"
    RAW_TCP = "RAW_TCP"


@dataclasses.dataclass
class SyntheticC2Response:
    protocol: C2ProtocolType
    status_code: int
    headers: Dict[str, str]
    payload_body: bytes
    task_type: str  # SLEEP, INJECT, DOWNLOAD_EXEC, WHOAMI, SHELL


@dataclasses.dataclass
class InterceptedBeacon:
    timestamp_ns: int
    client_ip: str
    target_domain: str
    target_port: int
    raw_query: str
    synthetic_response: SyntheticC2Response


class C2Sinkhole:
    """Air-gapped C2 listener and sinkhole emulator."""

    def __init__(self, sinkhole_ip: str = "192.168.100.1") -> None:
        self.sinkhole_ip = sinkhole_ip
        self.intercepted_beacons: List[InterceptedBeacon] = []
        self.dga_domains_resolved: Dict[str, str] = {}
        self.stage_counter = 0

    def resolve_dns_query(self, query_domain: str) -> str:
        """Sinkholes all outbound DGA and external queries to local emulator IP."""
        self.dga_domains_resolved[query_domain] = self.sinkhole_ip
        return self.sinkhole_ip

    def handle_http_beacon(
        self,
        client_ip: str,
        target_domain: str,
        path: str,
        headers: Dict[str, str],
        body: bytes,
    ) -> SyntheticC2Response:
        """Emulates interactive C2 server response to elicit further malware activity."""
        self.stage_counter += 1

        # Determine tasking to send back to the malware
        if self.stage_counter == 1:
            # Stage 1 response: Send interactive acknowledgment
            response = SyntheticC2Response(
                protocol=C2ProtocolType.HTTP_BEACON,
                status_code=200,
                headers={"Server": "nginx/1.18.0", "Content-Type": "application/octet-stream"},
                payload_body=b"\x00\x00\x00\x01\x00\x00\x00\x10" + b"TASK_STAGER_INIT",
                task_type="WHOAMI",
            )
        elif self.stage_counter == 2:
            # Stage 2 response: Command sample to unpack / execute secondary payload
            response = SyntheticC2Response(
                protocol=C2ProtocolType.COBALT_STRIKE,
                status_code=200,
                headers={"Server": "Apache/2.4.41", "Content-Type": "application/octet-stream"},
                payload_body=b"\x4d\x5a\x90\x00" + (b"\x90" * 32) + b"STAGE2_BENIGN_PROBE_SHELLCODE",
                task_type="DOWNLOAD_EXEC",
            )
        else:
            # Subsequent responses: keep connection alive with short sleep tasks
            response = SyntheticC2Response(
                protocol=C2ProtocolType.HTTP_BEACON,
                status_code=200,
                headers={"Server": "nginx/1.18.0"},
                payload_body=b"SLEEP_1000",
                task_type="SLEEP",
            )

        beacon = InterceptedBeacon(
            timestamp_ns=time.perf_counter_ns(),
            client_ip=client_ip,
            target_domain=target_domain,
            target_port=443 if "https" in path else 80,
            raw_query=f"{target_domain}{path}",
            synthetic_response=response,
        )
        self.intercepted_beacons.append(beacon)
        return response
