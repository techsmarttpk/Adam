from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel

class ActorContext(BaseModel):
    pid: int
    image: Optional[str] = None
    guid: Optional[str] = None

class AttckContext(BaseModel):
    tactic: str
    technique: str

class SemanticEvent(BaseModel):
    semantic_id: str
    session_id: str
    correlation_id: str
    intent: str
    confidence: float
    severity: str
    window_start: datetime
    window_end: datetime
    actor: Optional[ActorContext] = None
    evidence: list[str]
    attck: Optional[AttckContext] = None
    detector: str
    features: dict[str, Any]
    caused_by_mutation: Optional[str] = None
