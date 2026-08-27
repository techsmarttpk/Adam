"""
adam/contracts/profile.py

VMProfile and hardware/persona configuration models for Phase 2.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class HardwareConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    cpu_count: int = Field(default=2, ge=1)
    memory_mb: int = Field(default=4096, ge=1024)
    disk_profile: str = Field(default="standard")


class DecoyPersona(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    installed_software: List[str] = Field(default_factory=list)
    fake_user_documents: bool = Field(default=False)
    fake_browser_history: bool = Field(default=False)
    hostname_pool: List[str] = Field(default_factory=list)


class GuestAgentConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    install_path: str = Field(default="C:\\ProgramData\\adam-agent")
    autostart: bool = Field(default=True)


class VMProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    profile_id: str = Field(min_length=1)
    base_snapshot: str = Field(min_length=1)
    hardware: HardwareConfig = Field(default_factory=HardwareConfig)
    decoy_persona: DecoyPersona = Field(default_factory=DecoyPersona)
    network_mode: str = Field(default="host-only-isolated")
    guest_agent: GuestAgentConfig = Field(default_factory=GuestAgentConfig)
