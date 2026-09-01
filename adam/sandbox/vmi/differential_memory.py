"""Differential Memory Forensics and Payload Verification.

Captures baseline host-level memory snapshots, monitors anomalous memory transitions
(such as PAGE_EXECUTE_READWRITE / RWX and process hollowing primitives), and performs
dynamic memory diffing to extract decrypted/unpacked payloads before self-deletion.
"""

from __future__ import annotations
import dataclasses
import hashlib
import time
from typing import Dict, List, Optional, Set


@dataclasses.dataclass
class MemoryPageDelta:
    address: int
    size: int
    old_hash: str
    new_hash: str
    is_rwx: bool
    is_unmapped_code: bool
    extracted_payload: Optional[bytes] = None
    entropy: float = 0.0


@dataclasses.dataclass
class MemoryRegion:
    base_address: int
    size: int
    protection: str  # PAGE_READWRITE, PAGE_EXECUTE_READWRITE, etc.
    content_hash: str
    content: bytes = b""


class DifferentialMemoryAnalyzer:
    """Performs dynamic differential memory forensics between sandbox execution phases."""

    def __init__(self) -> None:
        self.baseline_snapshot: Dict[int, MemoryRegion] = {}
        self.rwx_regions: Set[int] = set()
        self.captured_payloads: List[MemoryPageDelta] = []
        self.hollowing_alerts: List[Dict[str, object]] = []

    def capture_baseline(self, regions: List[MemoryRegion]) -> int:
        """Capture baseline memory layout after initial OS boot."""
        self.baseline_snapshot.clear()
        for r in regions:
            c_hash = hashlib.sha256(r.content).hexdigest() if r.content else r.content_hash
            r_normalized = MemoryRegion(
                base_address=r.base_address,
                size=r.size,
                protection=r.protection,
                content_hash=c_hash,
                content=r.content,
            )
            self.baseline_snapshot[r.base_address] = r_normalized
        return len(self.baseline_snapshot)

    def record_memory_protection_change(
        self, pid: int, address: int, size: int, new_protection: str
    ) -> Optional[Dict[str, object]]:
        """Tracks VirtualProtect/VirtualAllocEx transitions to PAGE_EXECUTE_READWRITE."""
        if "EXECUTE_READWRITE" in new_protection.upper() or new_protection.upper() == "RWX":
            self.rwx_regions.add(address)
            alert = {
                "timestamp_ns": time.perf_counter_ns(),
                "pid": pid,
                "address": hex(address),
                "size": size,
                "protection": new_protection,
                "type": "RWX_MEMORY_TRANSITION_DETECTED",
            }
            self.hollowing_alerts.append(alert)
            return alert
        return None

    def record_process_hollowing_event(
        self, target_pid: int, caller_pid: int, section_base: int, primitive: str
    ) -> Dict[str, object]:
        """Tracks process hollowing indicators (e.g. NtMapViewOfSection, WriteProcessMemory)."""
        alert = {
            "timestamp_ns": time.perf_counter_ns(),
            "target_pid": target_pid,
            "caller_pid": caller_pid,
            "section_base": hex(section_base),
            "primitive": primitive,
            "type": "PROCESS_HOLLOWING_ATTEMPT",
        }
        self.hollowing_alerts.append(alert)
        return alert

    def compute_differential_deltas(self, current_regions: List[MemoryRegion]) -> List[MemoryPageDelta]:
        """Compare active memory regions with baseline to locate newly injected/decrypted code."""
        deltas = []
        for reg in current_regions:
            base = reg.base_address
            is_rwx = ("EXECUTE_READWRITE" in reg.protection.upper()) or (reg.protection.upper() == "RWX")
            cur_hash = hashlib.sha256(reg.content).hexdigest() if reg.content else reg.content_hash

            if base not in self.baseline_snapshot:
                # Newly mapped region
                entropy = self._calculate_shannon_entropy(reg.content) if reg.content else 0.0
                delta = MemoryPageDelta(
                    address=base,
                    size=reg.size,
                    old_hash="",
                    new_hash=cur_hash,
                    is_rwx=is_rwx,
                    is_unmapped_code=True,
                    extracted_payload=reg.content if reg.content else None,
                    entropy=entropy,
                )
                deltas.append(delta)
                self.captured_payloads.append(delta)
            else:
                baseline_reg = self.baseline_snapshot[base]
                if baseline_reg.content_hash != cur_hash:
                    entropy = self._calculate_shannon_entropy(reg.content) if reg.content else 0.0
                    delta = MemoryPageDelta(
                        address=base,
                        size=reg.size,
                        old_hash=baseline_reg.content_hash,
                        new_hash=cur_hash,
                        is_rwx=is_rwx,
                        is_unmapped_code=False,
                        extracted_payload=reg.content if reg.content else None,
                        entropy=entropy,
                    )
                    deltas.append(delta)
                    self.captured_payloads.append(delta)

        return deltas

    @staticmethod
    def _calculate_shannon_entropy(data: bytes) -> float:
        import math
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return round(entropy, 4)
