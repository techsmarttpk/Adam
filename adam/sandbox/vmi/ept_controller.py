"""Extended Page Table (EPT) & Second-Level Address Translation (SLAT) Controller.

Manages multi-view memory shadowing, split-page (2MB -> 4KB) mapping,
hardware-assisted execution trapping, Copy-on-Write (CoW) memory delta snapshots,
and TSC offset compensation (Anti-RDTSC countermeasure).
"""

from __future__ import annotations
import dataclasses
import time
from enum import IntFlag, auto
from typing import Dict, List, Optional, Set, Tuple


class EPTPermission(IntFlag):
    NONE = 0
    READ = auto()
    WRITE = auto()
    EXECUTE = auto()
    RW = READ | WRITE
    RX = READ | EXECUTE
    RWX = READ | WRITE | EXECUTE


@dataclasses.dataclass
class PageEntry:
    gfn: int  # Guest Frame Number
    mfn: int  # Machine/Host Frame Number
    permissions: EPTPermission
    is_shadowed: bool = False
    shadow_mfn: Optional[int] = None
    is_split: bool = False  # Split from 2MB to 4KB
    dirty: bool = False


@dataclasses.dataclass
class EPTMemoryView:
    view_id: int
    name: str
    pages: Dict[int, PageEntry] = dataclasses.field(default_factory=dict)
    active: bool = False


class TSCCompensator:
    """Compensates for VM-exit execution timing overhead to defeat RDTSC/RDTSCP anti-analysis checks."""

    def __init__(self, baseline_tsc_freq_mhz: float = 3000.0) -> None:
        self.tsc_freq_mhz = baseline_tsc_freq_mhz
        self.accumulated_tsc_offset: int = 0
        self.vm_exit_overhead_cycles: int = 250  # Average hardware VM exit cycle count

    def record_vm_exit(self, duration_ns: float) -> int:
        """Calculate and accumulate cycle adjustment for hypervisor execution."""
        cycles_spent = int((duration_ns * self.tsc_freq_mhz) / 1000.0)
        adjusted_cycles = cycles_spent + self.vm_exit_overhead_cycles
        self.accumulated_tsc_offset += adjusted_cycles
        return self.accumulated_tsc_offset

    def get_guest_tsc(self, raw_host_tsc: int) -> int:
        """Returns normalized guest TSC."""
        return max(0, raw_host_tsc - self.accumulated_tsc_offset)

    def reset(self) -> None:
        self.accumulated_tsc_offset = 0


class EPTController:
    """Control plane interface for Second-Level Address Translation (SLAT / EPT).

    Provides multi-view switching, execution traps via split-page shadowing,
    high-speed Copy-on-Write (CoW) dirty-page bitmap tracking for fast state resets.
    """

    PAGE_SIZE_4K = 4096
    PAGE_SIZE_2M = 2 * 1024 * 1024

    def __init__(self, vm_id: str = "default_vm") -> None:
        self.vm_id = vm_id
        self.views: Dict[int, EPTMemoryView] = {}
        self.active_view_id: int = 0
        self.tsc_compensator = TSCCompensator()
        self.dirty_pages: Set[int] = set()
        self.cow_snapshot_pages: Dict[int, bytes] = {}
        self.trapped_gfn_handlers: Dict[int, str] = {}
        self._initialize_default_view()

    def _initialize_default_view(self) -> None:
        default_view = EPTMemoryView(view_id=0, name="default_unrestricted", active=True)
        self.views[0] = default_view
        self.active_view_id = 0

    def create_view(self, view_id: int, name: str) -> EPTMemoryView:
        """Create a distinct EPT view for shadow execution or decoy memory layouts."""
        if view_id in self.views:
            return self.views[view_id]
        view = EPTMemoryView(view_id=view_id, name=name, active=False)
        # Inherit mappings from active view
        active_view = self.views[self.active_view_id]
        for gfn, entry in active_view.pages.items():
            view.pages[gfn] = dataclasses.replace(entry)
        self.views[view_id] = view
        return view

    def switch_view(self, target_view_id: int) -> bool:
        """Atomically switch active EPT pointer (EPTP) to a new view."""
        if target_view_id not in self.views:
            return False
        for vid, v in self.views.items():
            v.active = (vid == target_view_id)
        self.active_view_id = target_view_id
        return True

    def split_page(self, gfn_2m: int, view_id: Optional[int] = None) -> List[int]:
        """Split a 2MB large page into 512 x 4KB small pages for fine-grained trapping."""
        vid = self.active_view_id if view_id is None else view_id
        view = self.views.get(vid)
        if not view:
            return []

        base_4k_gfn = (gfn_2m * self.PAGE_SIZE_2M) // self.PAGE_SIZE_4K
        split_gfns = []
        for i in range(512):
            sub_gfn = base_4k_gfn + i
            if sub_gfn not in view.pages:
                view.pages[sub_gfn] = PageEntry(
                    gfn=sub_gfn,
                    mfn=sub_gfn,
                    permissions=EPTPermission.RWX,
                    is_split=True,
                )
            else:
                view.pages[sub_gfn].is_split = True
            split_gfns.append(sub_gfn)
        return split_gfns

    def set_page_permission(
        self, gfn: int, permissions: EPTPermission, view_id: Optional[int] = None
    ) -> bool:
        """Set EPT permissions (Read/Write/Execute) for a given GFN."""
        vid = self.active_view_id if view_id is None else view_id
        view = self.views.get(vid)
        if not view:
            return False

        if gfn not in view.pages:
            view.pages[gfn] = PageEntry(gfn=gfn, mfn=gfn, permissions=permissions)
        else:
            view.pages[gfn].permissions = permissions
        return True

    def shadow_page_for_execution_trap(
        self, gfn: int, shadow_mfn: int, hook_identifier: str
    ) -> Tuple[int, int]:
        """Setup split-view memory shadowing.

        Original View: Set to Read/Write only (No-Execute) -> Traps execution.
        Shadow View: Set to Read/Execute only -> Contains hook or randomized function.
        """
        # Ensure default view has RW only
        self.set_page_permission(gfn, EPTPermission.RW, view_id=0)
        self.trapped_gfn_handlers[gfn] = hook_identifier

        # Ensure shadow view has RX with redirected MFN
        shadow_view = self.views.get(1)
        if not shadow_view:
            shadow_view = self.create_view(1, "shadow_hook_view")

        shadow_view.pages[gfn] = PageEntry(
            gfn=gfn,
            mfn=shadow_mfn,
            permissions=EPTPermission.RX,
            is_shadowed=True,
            shadow_mfn=shadow_mfn,
        )
        return (0, 1)

    def handle_ept_violation(self, gfn: int, access_type: EPTPermission) -> Dict[str, object]:
        """Simulate/Process an EPT violation from hardware.

        Returns metadata about intercepted execution trap and applies TSC compensation.
        """
        t0 = time.perf_counter_ns()
        handler = self.trapped_gfn_handlers.get(gfn, "unknown_handler")

        # Mark dirty if write occurred
        if access_type & EPTPermission.WRITE:
            self.dirty_pages.add(gfn)
            if self.active_view_id in self.views and gfn in self.views[self.active_view_id].pages:
                self.views[self.active_view_id].pages[gfn].dirty = True

        switched = False
        if access_type & EPTPermission.EXECUTE:
            # Trapped execution attempt -> switch to shadow view
            if 1 in self.views:
                self.switch_view(1)
                switched = True

        elapsed_ns = time.perf_counter_ns() - t0
        tsc_offset = self.tsc_compensator.record_vm_exit(elapsed_ns)

        return {
            "gfn": gfn,
            "access_type": access_type.name,
            "handler": handler,
            "switched_to_shadow": switched,
            "tsc_offset_adjusted": tsc_offset,
            "elapsed_ns": elapsed_ns,
        }

    # Copy-on-Write (CoW) State Snapshot & Micro-Reset
    def capture_cow_checkpoint(self, sample_pages: Dict[int, bytes]) -> int:
        """Capture initial memory baseline for sub-second delta restoration."""
        self.cow_snapshot_pages = dict(sample_pages)
        self.dirty_pages.clear()
        return len(self.cow_snapshot_pages)

    def mark_dirty(self, gfn: int) -> None:
        self.dirty_pages.add(gfn)

    def restore_cow_delta(self) -> Dict[str, int]:
        """Sub-second reset: discard dirty pages and restore to baseline."""
        reverted_count = len(self.dirty_pages)
        self.dirty_pages.clear()
        self.switch_view(0)
        self.tsc_compensator.reset()
        return {"reverted_pages": reverted_count, "active_view": self.active_view_id}
