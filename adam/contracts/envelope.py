from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field

class Envelope(BaseModel):
    envelope_version: str = "1.0"
    message_id: str
    message_type: str
    session_id: str
    correlation_id: str
    emitted_at: datetime
    emitter: str
    payload: dict[str, Any] = Field(default_factory=dict)
