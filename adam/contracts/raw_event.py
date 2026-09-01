from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel
from adam.contracts.enums import EventSource, EventCategory

class ProcessContext(BaseModel):
    pid: int
    ppid: Optional[int] = None
    image: Optional[str] = None
    command_line: Optional[str] = None
    integrity_level: Optional[str] = None
    user: Optional[str] = None
    guid: Optional[str] = None

class RawEvent(BaseModel):
    event_id: str
    session_id: str
    source: EventSource
    source_event_id: Optional[int] = None
    category: EventCategory
    occurred_at: datetime
    observed_at: datetime
    process: Optional[ProcessContext] = None
    attributes: dict[str, Any]
    raw_ref: Optional[str] = None
