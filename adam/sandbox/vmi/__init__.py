"""Virtual Machine Introspection and Kernel Mutation Engine for ADAM."""

from adam.sandbox.vmi.ept_controller import EPTController, EPTMemoryView, EPTPermission, TSCCompensator
from adam.sandbox.vmi.syscall_virtualizer import SyscallVirtualizer, SyscallTableEntry
from adam.sandbox.vmi.kernel_polymorphism import KernelPolymorphismEngine, TransactionalStateSwitch
from adam.sandbox.vmi.dkom_tracker import DKOMTracker, DynamicMemoryMap, AllocationRecord
from adam.sandbox.vmi.object_randomizer import ObjectIdentityRandomizer
from adam.sandbox.vmi.differential_memory import DifferentialMemoryAnalyzer, MemoryPageDelta

__all__ = [
    "EPTController",
    "EPTMemoryView",
    "EPTPermission",
    "TSCCompensator",
    "SyscallVirtualizer",
    "SyscallTableEntry",
    "KernelPolymorphismEngine",
    "TransactionalStateSwitch",
    "DKOMTracker",
    "DynamicMemoryMap",
    "AllocationRecord",
    "ObjectIdentityRandomizer",
    "DifferentialMemoryAnalyzer",
    "MemoryPageDelta",
]
