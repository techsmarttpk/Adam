"""
MutationResult — what the Deception Engine publishes back onto the bus
after applying (or failing to apply) a primitive. §7.5.

Critical: this MUST be published back onto the bus (ADR-003) so Fusion can
attribute subsequent malware behaviour to it via `caused_by_mutation`. That
link is the entire behavioural-yield metric — do not skip it "for now."

LOCAL STUB — see enums.py note.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from adam.contracts.enums import ChangeKind, MutationStatus


class Change(BaseModel):
    kind: ChangeKind
    target: str
    operation: str  # e.g. "SET", "CREATE", "RESPOND"
    value: Optional[str] = None


class MutationResult(BaseModel):
    mutation_id: str
    session_id: str
    correlation_id: str
    decision_id: str
    primitive: str  # e.g. "FakeDomainControllerDeception@1.0"
    status: MutationStatus
    applied_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    latency_ms: float = 0.0
    changes: list[Change] = Field(default_factory=list)
    plausibility_score: float = Field(default=1.0, ge=0.0, le=1.0)
    plausibility_notes: str = ""
    revertible: bool = True
    causal_window_ms: int = 30_000
    error: Optional[str] = None
