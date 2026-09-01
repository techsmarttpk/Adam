from collections import deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from adam.contracts.raw_event import RawEvent
from adam.contracts.enums import EventCategory

class ProcessNode:
    def __init__(self, pid: int, ppid: Optional[int], image: Optional[str], guid: Optional[str]) -> None:
        self.pid = pid
        self.ppid = ppid
        self.image = image
        self.guid = guid

class EventCorrelator:
    def __init__(self, window_seconds: float = 5.0) -> None:
        self.window_seconds = window_seconds
        self.window_events: deque[RawEvent] = deque()
        self.process_tree: Dict[int, ProcessNode] = {}

    def add_event(self, event: RawEvent) -> None:
        if event.category == EventCategory.PROCESS and event.process:
            pid = event.process.pid
            ppid = event.process.ppid
            image = event.process.image
            guid = event.process.guid
            self.process_tree[pid] = ProcessNode(pid, ppid, image, guid)
        elif event.process and event.process.pid not in self.process_tree:
            self.process_tree[event.process.pid] = ProcessNode(
                event.process.pid,
                event.process.ppid,
                event.process.image,
                event.process.guid
            )
            
        self.window_events.append(event)
        self._prune_window(event.occurred_at)

    def _prune_window(self, current_time: datetime) -> None:
        cutoff = current_time - timedelta(seconds=self.window_seconds)
        while self.window_events and self.window_events[0].occurred_at < cutoff:
            self.window_events.popleft()

    def get_events_in_window(self) -> List[RawEvent]:
        return list(self.window_events)

    def get_process_ancestry(self, pid: int, max_depth: int = 10) -> List[str]:
        """Returns list of parent process images up to max_depth."""
        ancestry = []
        curr_pid = pid
        depth = 0
        while curr_pid in self.process_tree and depth < max_depth:
            node = self.process_tree[curr_pid]
            if node.image:
                ancestry.append(node.image)
            if node.ppid is not None and node.ppid != curr_pid:
                curr_pid = node.ppid
            else:
                break
            depth += 1
        return ancestry
