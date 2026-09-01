import uuid
from typing import Dict, Any
from adam.contracts.enums import EventSource, EventCategory
from adam.contracts.raw_event import RawEvent, ProcessContext
from adam.common.bus import EventBus
from adam.common.timeutil import now_utc, parse_iso
from adam.collectors.base import BaseCollector

class AgentCollector(BaseCollector):
    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)

    async def ingest_guest_payload(self, session_id: str, payload: Dict[str, Any]) -> None:
        """Receives a telemetry payload from the guest agent, normalizes it, and publishes it."""
        if not self._running:
            return
            
        events = payload.get("events", [])
        for e in events:
            source_str = e.get("source", "AGENT")
            try:
                source = EventSource(source_str)
            except ValueError:
                source = EventSource.AGENT
            
            category_str = e.get("category", "SYSTEM")
            try:
                category = EventCategory(category_str)
            except ValueError:
                category = EventCategory.SYSTEM
            
            occurred_at_str = e.get("occurred_at")
            occurred_at = parse_iso(occurred_at_str) if occurred_at_str else now_utc()
            
            proc_data = e.get("process")
            process = None
            if proc_data:
                process = ProcessContext(
                    pid=proc_data.get("pid", 0),
                    ppid=proc_data.get("ppid"),
                    image=proc_data.get("image"),
                    command_line=proc_data.get("command_line"),
                    integrity_level=proc_data.get("integrity_level"),
                    user=proc_data.get("user"),
                    guid=proc_data.get("guid")
                )
                
            raw_event = RawEvent(
                event_id=f"raw_{uuid.uuid4().hex[:16]}",
                session_id=session_id,
                source=source,
                source_event_id=e.get("source_event_id"),
                category=category,
                occurred_at=occurred_at,
                observed_at=now_utc(),
                process=process,
                attributes=e.get("attributes", {}),
                raw_ref=e.get("raw_ref")
            )
            
            await self.bus.publish(raw_event)
