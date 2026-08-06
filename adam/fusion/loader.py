from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .models import RawEvent


class EventLoader:
    """
    Loads telemetry from JSON files and converts it
    into RawEvent objects.
    """
    @staticmethod
    def load_json(path: str | Path) -> list[RawEvent]:

        path = Path(path)

        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        events: list[RawEvent] = []

        for item in data:

            payload = item.get("payload")

            if payload is None:
                payload = {}

            # Generator format
            if "command_line" in item:
                payload["command_line"] = item.get("command_line")

            if "image_path" in item:
                payload["image_path"] = item.get("image_path")

            if "target_path" in item:
                payload["target_path"] = item.get("target_path")

            if "host" in item:
                payload["host"] = item.get("host")

            if "user" in item:
                payload["user"] = item.get("user")

            event = RawEvent(

                timestamp=datetime.fromisoformat(
                    item["timestamp"].replace("Z", "+00:00")
                ),

                source=item.get("source", "generator"),

                event_type=item["event_type"].upper(),

                process_id=item.get("process_id", item.get("pid")),

                parent_process_id=item.get(
                    "parent_process_id",
                    item.get("ppid"),
                ),

                process_name=item.get("process_name"),

                command_line=payload.get("command_line"),

                payload=payload,
            )

            events.append(event)

        return events