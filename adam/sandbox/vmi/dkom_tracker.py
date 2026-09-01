"""Allocation-Driven Mapping and DKOM (Direct Kernel Object Manipulation) Tracker.

Bridges the semantic gap by capturing low-level kernel memory allocation events
and maintaining untampered object registries to unmask rootkits and hidden processes.
Provides dynamic memory offset maps to downstream consumers (e.g. TLS Key Extractor).
"""

from __future__ import annotations
import dataclasses
import time
from typing import Callable, Dict, List, Optional, Set


@dataclasses.dataclass
class AllocationRecord:
    pool_tag: str
    virtual_address: int
    size_bytes: int
    object_type: str  # EPROCESS, ETHREAD, FILE_OBJECT, DRIVER_OBJECT
    timestamp_ns: int
    freed: bool = False
    metadata: Dict[str, object] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class DynamicMemoryMap:
    version: int
    lsass_base_offset: int
    open_ssl_ctx_offset: int
    eprocess_active_links_offset: int
    kthread_stack_offset: int
    last_updated_ns: int


class DKOMTracker:
    """Tracks dynamic kernel allocations to maintain ground truth process/object lists

    independent of compromised guest doubly-linked lists (ActiveProcessLinks).
    """

    def __init__(self) -> None:
        self.allocations: Dict[int, AllocationRecord] = {}  # address -> record
        self.active_processes: Dict[int, Dict[str, object]] = {}  # pid -> details
        self.memory_map_listeners: List[Callable[[DynamicMemoryMap], None]] = []
        self.current_memory_map = DynamicMemoryMap(
            version=1,
            lsass_base_offset=0x140000000,
            open_ssl_ctx_offset=0x238,
            eprocess_active_links_offset=0x448,
            kthread_stack_offset=0x28,
            last_updated_ns=time.perf_counter_ns(),
        )

    def record_kernel_allocation(
        self, pool_tag: str, address: int, size: int, object_type: str, metadata: Optional[Dict[str, object]] = None
    ) -> AllocationRecord:
        """Capture raw kernel allocation (e.g. ExAllocatePoolWithTag / kmalloc)."""
        rec = AllocationRecord(
            pool_tag=pool_tag,
            virtual_address=address,
            size_bytes=size,
            object_type=object_type,
            timestamp_ns=time.perf_counter_ns(),
            metadata=metadata or {},
        )
        self.allocations[address] = rec
        if object_type == "EPROCESS" and metadata and "pid" in metadata:
            self.active_processes[int(metadata["pid"])] = {
                "address": address,
                "name": metadata.get("image_name", "unknown"),
                "unlinked": False,
            }
        return rec

    def record_kernel_free(self, address: int) -> bool:
        if address in self.allocations:
            self.allocations[address].freed = True
            return True
        return False

    def detect_dkom_hidden_processes(self, guest_reported_pids: Set[int]) -> List[Dict[str, object]]:
        """Cross-reference allocation-driven ground truth with guest API reported processes.

        Identifies processes that were unlinked from ActiveProcessLinks (DKOM hiding).
        """
        hidden = []
        for pid, pinfo in self.active_processes.items():
            if pid not in guest_reported_pids:
                pinfo["unlinked"] = True
                hidden.append({
                    "pid": pid,
                    "image_name": pinfo["name"],
                    "eprocess_address": hex(pinfo["address"]),
                    "detection": "DKOM_UNLINKED_ACTIVE_PROCESS_LINKS",
                })
        return hidden

    def update_dynamic_memory_map(
        self, lsass_delta: int = 0, openssl_delta: int = 0
    ) -> DynamicMemoryMap:
        """Update dynamic memory layout offsets and notify listeners (e.g. TLS Extractor)."""
        self.current_memory_map.version += 1
        self.current_memory_map.lsass_base_offset += lsass_delta
        self.current_memory_map.open_ssl_ctx_offset += openssl_delta
        self.current_memory_map.last_updated_ns = time.perf_counter_ns()

        for listener in self.memory_map_listeners:
            listener(self.current_memory_map)

        return self.current_memory_map

    def register_memory_map_listener(self, listener: Callable[[DynamicMemoryMap], None]) -> None:
        self.memory_map_listeners.append(listener)
