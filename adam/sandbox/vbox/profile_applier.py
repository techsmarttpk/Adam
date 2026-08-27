"""
adam/sandbox/vbox/profile_applier.py

Loads VM profiles from config/vm_profiles/ and applies hardware settings and
pre-session decoy persona lures (using adam/deception/catalogue.py primitives).
"""

from __future__ import annotations

import os
from pathlib import Path
import random
from typing import Any
import tomllib

from adam.contracts.profile import VMProfile
from adam.deception.catalogue import get_primitive_class
from adam.sandbox.guest.channel import GuestChannel
from adam.sandbox.vbox.client import VirtualBoxClient

PROFILE_DIR = Path(__file__).resolve().parents[3] / "config" / "vm_profiles"


def load_profile(profile_id_or_path: str) -> VMProfile:
    """
    Load a VMProfile given a profile ID (e.g. 'win10_x64_enterprise_office_decoy')
    or a path to a TOML file.
    """
    path = Path(profile_id_or_path)
    if not path.exists():
        if not str(profile_id_or_path).endswith(".toml"):
            path = PROFILE_DIR / f"{profile_id_or_path}.toml"
        else:
            path = PROFILE_DIR / profile_id_or_path

    if not path.exists():
        raise FileNotFoundError(f"VM Profile not found at '{path}' or '{profile_id_or_path}'")

    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return VMProfile.model_validate(data)


async def apply_profile_hardware(
    client: VirtualBoxClient,
    vm_name: str,
    profile: VMProfile,
) -> None:
    """
    Apply hardware specifications (CPU, RAM, network) and security hardening to a VM.
    """
    await client.harden_vm_security(vm_name)
    await client.modify_hardware(
        vm_name,
        cpu_count=profile.hardware.cpu_count,
        memory_mb=profile.hardware.memory_mb,
    )
    if profile.network_mode == "host-only-isolated":
        await client.configure_network(vm_name, mode="host-only-isolated")


async def apply_profile_persona(
    guest_channel: GuestChannel | Any,
    profile: VMProfile,
) -> list[str]:
    """
    Pre-seed the guest with decoy persona lures before detonation by invoking
    existing deception primitives from adam/deception/catalogue.py.
    """
    applied = []
    persona = profile.decoy_persona

    if persona.fake_user_documents:
        try:
            prim_cls = get_primitive_class("PLANT_DECOY_DOCUMENTS")
            prim = prim_cls(guest_channel)
            await prim.apply_async("pre_session", "pre_session", "pre_session", {})
            applied.append("PLANT_DECOY_DOCUMENTS")
        except Exception:
            pass

    if persona.fake_browser_history:
        try:
            prim_cls = get_primitive_class("INJECT_FAKE_BROWSER_CREDS")
            prim = prim_cls(guest_channel)
            await prim.apply_async("pre_session", "pre_session", "pre_session", {})
            applied.append("INJECT_FAKE_BROWSER_CREDS")
        except Exception:
            pass

    if persona.hostname_pool:
        selected_hostname = random.choice(persona.hostname_pool)
        applied.append(f"HOSTNAME:{selected_hostname}")

    return applied
