from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

@dataclass(slots=True)
class RawEvent:
    timestamp: datetime
    source: str
    event_type: str

    process_id: int | None = None
    parent_process_id: int | None = None

    process_name: str | None = None
    command_line: str | None = None

    payload: dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class SemanticEvent:
    """
    High-level security event produced after analysis.
    """

    timestamp: datetime

    category: str

    technique_id: str

    severity: str

    confidence: float

    description: str

    evidence: list[RawEvent] = field(default_factory=list)

@dataclass(slots=True)
class FusionResult:
    """
    Final output returned by the Event Fusion Engine.
    """

    timestamp: datetime

    processed_events: int

    normalized_events: int

    correlated_groups: int

    detections: list[SemanticEvent] = field(default_factory=list)

    runtime_ms: float = 0.0