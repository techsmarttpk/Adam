"""System Call Table Virtualization and Dynamic Index Remapping.

Maintains multi-table views of the System Service Descriptor Table (SSDT / Shadow SSDT).
Permits execution rerouting to randomized indices while maintaining an un-mutated
appearance for in-guest integrity checks.
"""

from __future__ import annotations
import dataclasses
import random
from typing import Dict, List, Optional


@dataclasses.dataclass
class SyscallTableEntry:
    original_index: int
    virtual_index: int
    name: str
    target_address: int
    shadow_hook_address: Optional[int] = None
    invocation_count: int = 0
    trapped: bool = False


class SyscallVirtualizer:
    """Virtualizes System Call tables (SSDT) to prevent static signature indexing

    and confuse malware relying on hardcoded SSNs (System Service Numbers).
    """

    DEFAULT_SYSCALLS = [
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtQueueApcThread",
        "NtResumeThread",
        "NtCreateFile",
        "NtWriteFile",
        "NtSetValueKey",
        "NtDeleteValueKey",
        "NtQuerySystemInformation",
        "NtTerminateProcess",
        "NtDelayExecution",
    ]

    def __init__(self, base_address: int = 0xFFFFF80000000000) -> None:
        self.base_address = base_address
        self.original_table: Dict[int, SyscallTableEntry] = {}
        self.active_virtual_table: Dict[int, SyscallTableEntry] = {}
        self.name_to_virtual_index: Dict[str, int] = {}
        self._seed_default_table()

    def _seed_default_table(self) -> None:
        for idx, name in enumerate(self.DEFAULT_SYSCALLS):
            addr = self.base_address + (idx * 0x100)
            entry = SyscallTableEntry(
                original_index=idx,
                virtual_index=idx,
                name=name,
                target_address=addr,
                shadow_hook_address=addr + 0x50,
            )
            self.original_table[idx] = entry
            self.active_virtual_table[idx] = dataclasses.replace(entry)
            self.name_to_virtual_index[name] = idx

    def randomize_syscall_indices(self, seed: Optional[int] = None) -> Dict[str, int]:
        """Perform dynamic syscall table randomization.

        Swaps virtual indices for security-sensitive syscalls.
        """
        rng = random.Random(seed)
        names = list(self.name_to_virtual_index.keys())
        indices = list(range(len(names)))
        rng.shuffle(indices)

        new_virtual_table: Dict[int, SyscallTableEntry] = {}
        self.name_to_virtual_index.clear()

        for name, new_idx in zip(names, indices):
            orig_entry = next(e for e in self.original_table.values() if e.name == name)
            mutated_entry = SyscallTableEntry(
                original_index=orig_entry.original_index,
                virtual_index=new_idx,
                name=name,
                target_address=orig_entry.target_address,
                shadow_hook_address=orig_entry.shadow_hook_address,
                invocation_count=orig_entry.invocation_count,
            )
            new_virtual_table[new_idx] = mutated_entry
            self.name_to_virtual_index[name] = new_idx

        self.active_virtual_table = new_virtual_table
        return dict(self.name_to_virtual_index)

    def resolve_syscall(self, index: int, by_original: bool = False) -> Optional[SyscallTableEntry]:
        """Resolves syscall entry.

        If by_original is True, returns entry corresponding to standard OS index.
        Otherwise returns entry for the active randomized virtual index.
        """
        if by_original:
            return self.original_table.get(index)
        return self.active_virtual_table.get(index)

    def dispatch_syscall(self, index: int) -> Dict[str, object]:
        """Simulate a guest syscall dispatch through the virtualized SSDT."""
        entry = self.active_virtual_table.get(index)
        if not entry:
            return {"status": "INVALID_SSN", "index": index}

        entry.invocation_count += 1
        return {
            "status": "DISPATCHED",
            "syscall_name": entry.name,
            "original_index": entry.original_index,
            "virtual_index": entry.virtual_index,
            "target_address": hex(entry.target_address),
            "hook_address": hex(entry.shadow_hook_address) if entry.shadow_hook_address else None,
            "invocation_count": entry.invocation_count,
        }

    def get_table_state(self) -> List[Dict[str, object]]:
        return [
            {
                "name": entry.name,
                "original_index": entry.original_index,
                "virtual_index": entry.virtual_index,
                "invocations": entry.invocation_count,
            }
            for entry in self.active_virtual_table.values()
        ]
