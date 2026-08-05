from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .engine import EventFusionEngine
from .loader import EventLoader


def print_results(result) -> None:
    print("=" * 65)
    print("              ADAM Event Fusion Engine")
    print("=" * 65)

    print(f"Timestamp          : {result.timestamp}")
    print(f"Processed Events   : {result.processed_events}")
    print(f"Normalized Events  : {result.normalized_events}")
    print(f"Correlated Groups  : {result.correlated_groups}")
    print(f"Detections         : {len(result.detections)}")
    print(f"Runtime            : {result.runtime_ms:.2f} ms")

    print("\n" + "=" * 65)
    print("Detected Behaviors")
    print("=" * 65)

    if not result.detections:
        print("\nNo suspicious activity detected.")
        return

    for idx, detection in enumerate(result.detections, start=1):

        print(f"\n[{idx}] {detection.category}")
        print(f"Technique  : {detection.technique_id}")
        print(f"Severity   : {detection.severity}")
        print(f"Confidence : {detection.confidence:.2f}")

        print("\nDescription")
        print(f"  {detection.description}")

        print("\nEvidence")

        for event in detection.evidence:

            process = event.process_name or "Unknown Process"

            cmd = event.payload.get("command_line", "")

            if cmd:
                print(f"  • {process}")
                print(f"      {cmd}")
            else:
                print(f"  • {process}")

        print("-" * 65)


def main() -> None:

    base = Path(__file__).parent

    # Change this whenever you want to test a different dataset
    #log_file = base / "logs" / "telemetry.json"
    log_file = base / "logs" / "raw.json"

    loader = EventLoader()
    events = loader.load_json(log_file)

    engine = EventFusionEngine()

    result = engine.process(events)

    print_results(result)

    output = base / "outputs" / "fusion_result.json"

    with output.open("w", encoding="utf-8") as f:

        json.dump(
            asdict(result),
            f,
            indent=4,
            default=str,
        )

    print(f"\nFusion result saved to {output}")


if __name__ == "__main__":
    main()