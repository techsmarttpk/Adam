"""In-Memory TLS/SSL Session Key Extractor and Encrypted Traffic Analyzer.

Coupled with the VMI Dynamic Memory Map (from dkom_tracker.py) to accurately locate
SSL/TLS master secrets in memory across dynamic memory layout shuffling and mutations.
"""

from __future__ import annotations
import dataclasses
import hashlib
import time
from typing import Dict, List, Optional

from adam.sandbox.vmi.dkom_tracker import DynamicMemoryMap


@dataclasses.dataclass
class TLSSessionSecret:
    client_random: str  # 32-byte hex
    master_key: str  # 48-byte hex
    protocol_version: str  # TLS 1.2, TLS 1.3
    extracted_from_pid: int
    offset_used: int


@dataclasses.dataclass
class DecryptedFlow:
    flow_id: str
    client_ip: str
    server_ip: str
    server_port: int
    sni_hostname: str
    decrypted_content: bytes
    timestamp_ns: int


class TLSSessionKeyExtractor:
    """Extracts TLS keys from guest process memory and decrypts intercepted C2 sessions."""

    def __init__(self) -> None:
        self.extracted_keys: Dict[str, TLSSessionSecret] = {}  # client_random -> secret
        self.decrypted_flows: List[DecryptedFlow] = []
        self.active_memory_map: Optional[DynamicMemoryMap] = None

    def on_memory_map_updated(self, new_map: DynamicMemoryMap) -> None:
        """Dynamic memory map callback triggered whenever kernel memory shuffling occurs."""
        self.active_memory_map = new_map

    def extract_tls_keys_from_memory(
        self, pid: int, raw_process_memory: bytes
    ) -> List[TLSSessionSecret]:
        """Scan process memory using current dynamic memory offsets to extract TLS Master Secrets."""
        extracted = []
        # Use dynamic offset if available
        base_offset = self.active_memory_map.open_ssl_ctx_offset if self.active_memory_map else 0x238

        # Locate TLS 1.2 / 1.3 master key signatures
        # In a production VMI, this searches for SSL_SESSION structs or LSASS key blocks
        # Here we simulate scanning memory at dynamic offset
        if len(raw_process_memory) >= 64:
            # Derive deterministic key material from memory slice for demonstration
            client_rnd = hashlib.sha256(raw_process_memory[:32]).hexdigest()[:64]
            master_sec = hashlib.sha256(raw_process_memory[32:64]).hexdigest()[:96]

            secret = TLSSessionSecret(
                client_random=client_rnd,
                master_key=master_sec,
                protocol_version="TLS_1.3",
                extracted_from_pid=pid,
                offset_used=base_offset,
            )
            self.extracted_keys[client_rnd] = secret
            extracted.append(secret)

        return extracted

    def decrypt_payload_stream(
        self,
        flow_id: str,
        client_ip: str,
        server_ip: str,
        server_port: int,
        sni_hostname: str,
        encrypted_stream: bytes,
        client_random: str,
    ) -> Optional[DecryptedFlow]:
        """Decrypts encrypted C2 flow using extracted session secret."""
        if client_random not in self.extracted_keys:
            return None

        # Simulate AES-GCM / ChaCha20 decryption
        # Unmask payload structure
        decrypted_bytes = b"DECRYPTED_C2_COMMAND: " + encrypted_stream[:64]

        flow = DecryptedFlow(
            flow_id=flow_id,
            client_ip=client_ip,
            server_ip=server_ip,
            server_port=server_port,
            sni_hostname=sni_hostname,
            decrypted_content=decrypted_bytes,
            timestamp_ns=time.perf_counter_ns(),
        )
        self.decrypted_flows.append(flow)
        return flow
