from datetime import datetime
from typing import Any
from pydantic import BaseModel
from adam.contracts.enums import PolicyVerdict

class PolicyDecision(BaseModel):
    decision_id: str
    session_id: str
    correlation_id: str
    triggered_by: str
    rule_id: str
    rule_version: str
    action: str
    verdict: PolicyVerdict
    priority: int
    parameters: dict[str, Any]
    rationale: str
    decided_at: datetime
    evaluation_ms: float
