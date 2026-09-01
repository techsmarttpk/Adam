from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel
from adam.contracts.enums import MutationStatus

class MutationChange(BaseModel):
    kind: str
    target: str
    operation: str
    value: Optional[str] = None

class MutationResult(BaseModel):
    mutation_id: str
    session_id: str
    correlation_id: str
    decision_id: str
    primitive: str
    status: MutationStatus
    applied_at: datetime
    latency_ms: float
    changes: list[MutationChange]
    plausibility_score: float
    plausibility_notes: Optional[str] = None
    revertible: bool = True
    causal_window_ms: int = 30000
    error: Optional[str] = None
