import uuid
from datetime import datetime
from typing import List
from adam.contracts.enums import EventSource, EventCategory
from adam.contracts.raw_event import RawEvent, ProcessContext
from adam.collectors.base import BaseCollector
from adam.common.timeutil import now_utc

class ProcmonCollector(BaseCollector):
    def parse_csv_line(self, row: List[str], session_id: str) -> RawEvent:
        """Parses a single row from a Procmon CSV export."""
        time_str = row[0]
        proc_name = row[1]
        pid = int(row[2]) if row[2].isdigit() else 0
        operation = row[3]
        path = row[4]
        result = row[5]
        detail = row[6] if len(row) > 6 else ""

        process = ProcessContext(pid=pid, image=proc_name)
        
        category = EventCategory.SYSTEM
        if "Reg" in operation:
            category = EventCategory.REGISTRY
        elif "File" in operation or "Create" in operation or "Write" in operation or "Set" in operation:
            category = EventCategory.FILE
        elif "Process" in operation or "Thread" in operation:
            category = EventCategory.PROCESS

        attrs = {
            "operation": operation,
            "target_object": path,
            "result": result,
            "detail": detail
        }

        try:
            # Try parsing typical "H:M:S.ffffff AM/PM" format
            occurred_at = datetime.strptime(time_str, "%I:%M:%S.%f %p")
            # Replace year/month/day with current date context
            now = datetime.now()
            occurred_at = occurred_at.replace(year=now.year, month=now.month, day=now.day)
        except Exception:
            occurred_at = now_utc()

        return RawEvent(
            event_id=f"raw_pm_{uuid.uuid4().hex[:12]}",
            session_id=session_id,
            source=EventSource.PROCMON,
            category=category,
            occurred_at=occurred_at,
            observed_at=now_utc(),
            process=process,
            attributes=attrs,
            raw_ref=None
        )
