"""
adam/contracts/raw_event.py

RawEvent -- ARCHITECTURE.md section 7.2. The normalised shape every
collector (adam/collectors/, section 5.3) must produce regardless of
source. This is the contract Fusion (Dev B) consumes; getting it wrong here
is the single most consequential mistake Phase 2 could make, since three
other developers build against it sight-unseen via the recorded corpus
(section 10.3).

`occurred_at` vs `observed_at` is the field pair section 5.3 calls out as
"the most likely subtle bug in the project" -- occurred_at is the source's
own clock (guest-time corrected), observed_at is host ingest time. Fusion
orders on occurred_at; only occurred_at is meaningful for causal reasoning.
Both are required and independently timezone-validated below so a collector
cannot accidentally supply one and let the model silently default the other.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from adam.contracts.enums import Category, Source


class ProcessInfo(BaseModel):
    """RawEvent.process -- ARCHITECTURE.md section 7.2 example."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pid: int = Field(ge=0)
    ppid: int = Field(ge=0)
    image: str = Field(min_length=1)
    command_line: str
    integrity_level: str = Field(min_length=1)
    user: str = Field(min_length=1)
    guid: str = Field(min_length=1)


class RawEvent(BaseModel):
    """See module docstring. Matches the JSON shape in section 7.2 exactly."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    source: Source
    source_event_id: int
    category: Category
    occurred_at: datetime
    observed_at: datetime
    process: ProcessInfo | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_ref: str | None = None

    @field_validator("occurred_at", "observed_at")
    @classmethod
    def _require_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError(
                "occurred_at/observed_at must be timezone-aware (UTC), "
                "per ARCHITECTURE.md section 5.1"
            )
        return value
