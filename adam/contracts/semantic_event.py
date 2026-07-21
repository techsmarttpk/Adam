"""
SemanticEvent — the message Fusion (Raghu's module) publishes and Policy
(you) consumes. Mirrors ARCHITECTURE.md §7.3 exactly.

LOCAL STUB — see enums.py note. Field names/types here must match the real
frozen contract byte for byte; if Raghu's actual output differs, that is a
§7 contract discussion for the whole team, not something to quietly patch
in your own module.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class Actor(BaseModel):
    pid: int
    image: str
    guid: str


class AttckRef(BaseModel):
    tactic: str
    technique: str


class SemanticEvent(BaseModel):
    semantic_id: str
    session_id: str
    correlation_id: str
    intent: str  # e.g. "RECON_DOMAIN_CONTROLLER" — see §7.7 taxonomy
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str
    window_start: datetime
    window_end: datetime
    actor: Actor
    evidence: list[str] = Field(default_factory=list)
    attck: Optional[AttckRef] = None
    detector: str
    features: dict[str, Any] = Field(default_factory=dict)
    caused_by_mutation: Optional[str] = None
