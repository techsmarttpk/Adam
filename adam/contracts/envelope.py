"""
adam/contracts/envelope.py

Envelope -- ARCHITECTURE.md section 7.1. Every message published on the
event bus (adam/common/bus.py, section 8) is wrapped in one of these.
`correlation_id` is the thread that lets a mutation be traced back to the
raw event that caused it (section 7.1); losing it breaks the paper's
traceability claim, so it is a required field here, not optional.

Generic over the payload type so a publisher/subscriber pair gets static
type-checking on `envelope.payload` (e.g. `Envelope[RawEvent]`) instead of
every consumer re-validating an `Any`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

PayloadT = TypeVar("PayloadT")


class Envelope(BaseModel, Generic[PayloadT]):
    """See module docstring. Matches the JSON shape in section 7.1 exactly."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    envelope_version: str = Field(default="1.0", min_length=1)
    message_id: str = Field(min_length=1)
    message_type: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    correlation_id: str = Field(min_length=1)
    emitted_at: datetime
    emitter: str = Field(min_length=1)
    payload: PayloadT

    @field_validator("emitted_at")
    @classmethod
    def _require_timezone_aware(cls, value: datetime) -> datetime:
        """
        ARCHITECTURE.md section 5.1: 'Time normalisation (all timestamps
        UTC, ISO-8601, microsecond precision)' is a stated responsibility of
        this package. A naive datetime here would silently defeat that
        guarantee for every message on the bus, so it is rejected rather
        than assumed to be UTC.
        """
        if value.tzinfo is None:
            raise ValueError(
                "emitted_at must be timezone-aware (UTC), per ARCHITECTURE.md section 5.1"
            )
        return value
