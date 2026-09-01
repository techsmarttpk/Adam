from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from adam.contracts.enums import SessionStatus, DeceptionArm, NetworkMode

class SampleMetadata(BaseModel):
    sha256: str
    md5: str
    filename: str
    size_bytes: int
    file_type: str

class SessionConfig(BaseModel):
    deception_enabled: bool
    policy_ruleset: str
    vm_profile: str
    timeout_seconds: int
    network_mode: NetworkMode

class SessionMetrics(BaseModel):
    raw_events: int = 0
    semantic_events: int = 0
    decisions_total: int = 0
    decisions_executed: int = 0
    mutations_applied: int = 0
    semantic_events_post_mutation: int = 0

class AnalysisSession(BaseModel):
    session_id: str
    experiment_id: str
    arm: DeceptionArm
    sample: SampleMetadata
    config: SessionConfig
    status: SessionStatus
    started_at: datetime
    ended_at: Optional[datetime] = None
    metrics: SessionMetrics
    error: Optional[str] = None
