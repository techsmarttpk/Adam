"""Unit tests for Virtual Machine Introspection and Kernel Mutation Engine."""

import pytest
from adam.sandbox.vmi.ept_controller import EPTController, EPTPermission, TSCCompensator
from adam.sandbox.vmi.syscall_virtualizer import SyscallVirtualizer
from adam.sandbox.vmi.kernel_polymorphism import KernelPolymorphismEngine, MitigationState, TransactionalStateSwitch
from adam.sandbox.vmi.dkom_tracker import DKOMTracker
from adam.sandbox.vmi.object_randomizer import ObjectIdentityRandomizer
from adam.sandbox.vmi.differential_memory import DifferentialMemoryAnalyzer, MemoryRegion


def test_tsc_compensator_normalization():
    compensator = TSCCompensator(baseline_tsc_freq_mhz=3000.0)
    # Simulate a VM exit lasting 500ns
    offset = compensator.record_vm_exit(500.0)
    assert offset > 0
    raw_tsc = 1000000
    normalized = compensator.get_guest_tsc(raw_tsc)
    assert normalized == raw_tsc - offset


def test_ept_controller_multi_view_and_shadowing():
    ept = EPTController(vm_id="test_vm")
    assert ept.active_view_id == 0

    # Test page splitting (2MB -> 4KB)
    sub_gfns = ept.split_page(gfn_2m=1)
    assert len(sub_gfns) == 512

    # Setup execution shadow trap
    view_orig, view_shadow = ept.shadow_page_for_execution_trap(
        gfn=0x200, shadow_mfn=0x500, hook_identifier="hook_nt_alloc"
    )
    assert view_orig == 0
    assert view_shadow == 1

    # Simulate execute violation -> should switch to shadow view
    res = ept.handle_ept_violation(gfn=0x200, access_type=EPTPermission.EXECUTE)
    assert res["switched_to_shadow"] is True
    assert res["handler"] == "hook_nt_alloc"
    assert ept.active_view_id == 1

    # Test CoW delta reset
    ept.mark_dirty(0x200)
    cow_res = ept.restore_cow_delta()
    assert cow_res["reverted_pages"] == 1
    assert ept.active_view_id == 0


def test_syscall_virtualizer_randomization():
    virtualizer = SyscallVirtualizer()
    orig_entry = virtualizer.resolve_syscall(0, by_original=True)
    assert orig_entry is not None
    assert orig_entry.name == "NtAllocateVirtualMemory"

    # Randomize
    remap = virtualizer.randomize_syscall_indices(seed=42)
    assert len(remap) == len(SyscallVirtualizer.DEFAULT_SYSCALLS)

    # Test dispatch
    dispatch_res = virtualizer.dispatch_syscall(0)
    assert dispatch_res["status"] == "DISPATCHED"
    assert dispatch_res["invocation_count"] == 1


def test_kernel_polymorphism_and_transactional_switch():
    engine = KernelPolymorphismEngine(vcpu_count=4)
    # Test atomic mitigation toggle
    res = engine.toggle_mitigation_atomically("CVE-2017-5715", MitigationState.ENABLED)
    assert res["status"] == "COMMITTED"
    assert res["new_state"] == "ENABLED"
    assert res["toggles"] == 1

    # Test memory layout shuffling
    shuffle_res = engine.shuffle_kernel_memory_layout(entropy_seed=12345)
    assert shuffle_res["status"] == "COMMITTED"
    assert "stack_entropy" in shuffle_res


def test_dkom_tracker_hidden_process_detection():
    tracker = DKOMTracker()
    tracker.record_kernel_allocation(
        pool_tag="Proc", address=0xFFFFE0001000, size=4096, object_type="EPROCESS",
        metadata={"pid": 1337, "image_name": "stealth_rootkit.exe"}
    )

    # Guest OS reports only legitimate processes (PID 4 and 100)
    hidden = tracker.detect_dkom_hidden_processes(guest_reported_pids={4, 100})
    assert len(hidden) == 1
    assert hidden[0]["pid"] == 1337
    assert hidden[0]["image_name"] == "stealth_rootkit.exe"


def test_object_identity_randomizer():
    randomizer = ObjectIdentityRandomizer(session_salt="test_session")
    alias1 = randomizer.get_or_create_alias("MyMalwareMutex", "MUTEX")
    assert alias1.startswith("Global\\Mtx_")

    # Second call should return same alias
    alias2 = randomizer.get_or_create_alias("MyMalwareMutex", "MUTEX")
    assert alias1 == alias2

    orig = randomizer.resolve_original(alias1)
    assert orig == "MyMalwareMutex"


def test_differential_memory_forensics():
    analyzer = DifferentialMemoryAnalyzer()
    # Baseline
    base_region = MemoryRegion(
        base_address=0x400000, size=4096, protection="PAGE_READONLY", content_hash="hash_base", content=b"BASE_EXE"
    )
    analyzer.capture_baseline([base_region])

    # RWX Alert
    rwx_alert = analyzer.record_memory_protection_change(
        pid=1234, address=0x500000, size=8192, new_protection="PAGE_EXECUTE_READWRITE"
    )
    assert rwx_alert is not None
    assert rwx_alert["type"] == "RWX_MEMORY_TRANSITION_DETECTED"

    # Compute delta on new unmapped region
    injected_region = MemoryRegion(
        base_address=0x500000, size=8192, protection="PAGE_EXECUTE_READWRITE", content_hash="hash_injected",
        content=b"\x90\x90\x90\xcc" * 20
    )
    deltas = analyzer.compute_differential_deltas([base_region, injected_region])
    assert len(deltas) == 1
    assert deltas[0].is_unmapped_code is True
    assert deltas[0].is_rwx is True
    assert deltas[0].entropy > 0.0
