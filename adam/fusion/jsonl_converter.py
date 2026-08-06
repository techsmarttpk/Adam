import json
from pathlib import Path


def convert_raw_jsonl_to_json(input_file: str, output_file: str):
    """
    Convert Pranav's raw.jsonl into the JSON format expected
    by the current ADAM Fusion Engine.
    """

    events = []

    with open(input_file, "r", encoding="utf-8") as infile:

        for line_number, line in enumerate(infile, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                print(f"Skipping invalid JSON on line {line_number}")
                continue

            # Safe handling of optional fields
            process = raw.get("process") or {}
            attributes = raw.get("attributes") or {}

            if not isinstance(process, dict):
                process = {}

            if not isinstance(attributes, dict):
                attributes = {}

            process_image = process.get("image")

            event = {
                "timestamp": raw.get("occurred_at"),

                "source": (raw.get("source") or "").lower(),

                "event_type": (raw.get("category") or "").upper(),

                "process_id": process.get("pid"),

                "parent_process_id": process.get("ppid"),

                "process_name": (
                    Path(process_image).name
                    if process_image
                    else None
                ),

                "payload": {
                    "command_line": process.get("command_line", "")
                }
            }

            # Preserve all additional attributes
            event["payload"].update(attributes)

            # Keep useful metadata
            event["payload"]["host"] = raw.get("host")
            event["payload"]["user"] = raw.get("user")
            event["payload"]["session_id"] = raw.get("session_id")
            event["payload"]["event_id"] = raw.get("event_id")

            events.append(event)

    with open(output_file, "w", encoding="utf-8") as outfile:
        json.dump(events, outfile, indent=4)

    print(f"Converted {len(events)} events")
    print(f"Saved to {output_file}")


if __name__ == "__main__":

    convert_raw_jsonl_to_json(
        input_file=r"C:\ADAM\Adam\adam\fusion\logs\raw.jsonl",
        output_file=r"C:\ADAM\Adam\adam\fusion\logs\raw.json",
    )