"""
Standalone ADAM Simulation Runner — processes events through EventFusionEngine,
PolicyEngine, and DeceptionEngine using a FakeGuestChannel test double.

Supports:
- Fusion engine telemetry JSON logs (e.g., adam/fusion/logs/telemetry.json)
- Pre-compiled synthetic events JSON (e.g., demo/datasets/synthetic_events.json)

Outputs:
- Live progress lines to stdout
- Structured JSON lines to demo/logs/simulation_run.jsonl (or custom --log)
- Markdown report to demo/REPORT.md (via generate_report)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure workspace root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from adam.contracts.enums import MutationStatus, Verdict
from adam.contracts.semantic_event import Actor, AttckRef, SemanticEvent
from adam.deception.engine import DeceptionEngine
from adam.fusion.engine import EventFusionEngine
from adam.fusion.loader import EventLoader
from adam.fusion.mapping import map_detection_to_intent
from adam.policy.context import SessionContext
from adam.policy.engine import PolicyEngine
from demo.generate_report import generate_report
from tests.unit.test_deception.test_engine import FakeGuestChannel

RULES_PATH = BASE_DIR / "rules" / "default"


def load_and_convert_events(dataset_path: Path) -> tuple[list[SemanticEvent], str]:
    """
    Loads dataset JSON. If raw telemetry format, runs EventFusionEngine to detect
    intents and converts them to contract SemanticEvent objects. If already SemanticEvent
    format, validates directly.
    """
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"Expected top-level JSON list in {dataset_path.name}")

    if not data:
        return [], "empty dataset"

    first_item = data[0]

    # Case A: Dataset is already contract SemanticEvent format
    if isinstance(first_item, dict) and ("semantic_id" in first_item or "intent" in first_item):
        events = [SemanticEvent.model_validate(e) for e in data]
        return events, f"Loaded {len(events)} pre-compiled SemanticEvent objects"

    import contextlib
    import io

    loader = EventLoader()
    raw_telemetry = loader.load_json(dataset_path)

    # Monkey-patch CredentialAccessDetector to fix missing indicators
    from adam.fusion.detectors.credential_access import CredentialAccessDetector
    CredentialAccessDetector.STRONG_INDICATORS = ["mimikatz.exe", "invoke-mimikatz", "minidumpwritedump"]
    CredentialAccessDetector.MEDIUM_INDICATORS = ["procdump.exe", "lsass.exe", "comsvcs.dll", "reg save"]
    CredentialAccessDetector.WEAK_INDICATORS = ["sekurlsa", "privilege::debug", "lsadump", "wallet", "chrome"]

    fusion_engine = EventFusionEngine()
    with contextlib.redirect_stdout(io.StringIO()):
        fusion_result = fusion_engine.process(raw_telemetry)

    events: list[SemanticEvent] = []
    for idx, detection in enumerate(fusion_result.detections, start=1):
        intent, tactic, technique = map_detection_to_intent(detection)

        first_ev = detection.evidence[0] if detection.evidence else None
        pid = first_ev.process_id if (first_ev and first_ev.process_id) else 1000
        pname = first_ev.process_name if (first_ev and first_ev.process_name) else "unknown.exe"

        ts = detection.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        features = {"file_count": len(detection.evidence), "has_target": True}
        if intent == "RECON_DOMAIN_CONTROLLER":
            features["ldap_attempts"] = 3
            features["all_failed"] = True
        elif intent == "PERSIST_RUN_KEY":
            features["distinct_registry_keys"] = 6

        se = SemanticEvent(
            semantic_id=f"sem_fusion_{idx:03d}",
            session_id="sess_fusion_001",
            correlation_id=f"corr_fusion_{idx:03d}",
            intent=intent,
            confidence=detection.confidence,
            severity=detection.severity,
            window_start=ts,
            window_end=ts,
            actor=Actor(pid=pid, image=f"C:\\Windows\\System32\\{pname}", guid=f"{{guid-fusion-{idx:04d}}}"),
            evidence=[ev.process_name for ev in detection.evidence if ev.process_name],
            attck=AttckRef(tactic=tactic, technique=technique),
            detector=f"{detection.category}Detector@1.0",
            features=features,
        )
        events.append(se)

    source_info = (
        f"Processed {len(raw_telemetry)} raw events via EventFusionEngine -> "
        f"{fusion_result.correlated_groups} correlated groups -> {len(events)} SemanticEvent detections"
    )
    return events, source_info


async def main() -> None:
    parser = argparse.ArgumentParser(description="ADAM Simulation Runner")
    parser.add_argument(
        "--dataset",
        type=str,
        default="adam/fusion/logs/telemetry.json",
        help="Path to input dataset JSON (default: adam/fusion/logs/telemetry.json)",
    )
    parser.add_argument(
        "--log",
        type=str,
        default=None,
        help="Path to output JSONL log file",
    )
    parser.add_argument(
        "--report",
        type=str,
        default=None,
        help="Path to output Markdown report file (default: demo/REPORT.md)",
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.is_absolute():
        dataset_path = BASE_DIR / dataset_path

    if args.log:
        log_file_path = Path(args.log)
        if not log_file_path.is_absolute():
            log_file_path = BASE_DIR / log_file_path
    else:
        if "stress" in dataset_path.name:
            log_file_path = BASE_DIR / "demo" / "logs" / "simulation_run_stress.jsonl"
        else:
            log_file_path = BASE_DIR / "demo" / "logs" / "simulation_run.jsonl"

    report_path = Path(args.report) if args.report else None

    print("=" * 80)
    print(f"ADAM Adaptive Deception Analysis - Run Start ({dataset_path.name})")
    print("=" * 80)

    # 1. Load and process dataset
    events, info_msg = load_and_convert_events(dataset_path)
    print(f"{info_msg}\n")

    # Ensure logs directory exists
    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    # 2. Setup Policy Engine, Deception Engine & FakeGuestChannel
    policy_engine = PolicyEngine(str(RULES_PATH))
    channel = FakeGuestChannel()
    deception_engine = DeceptionEngine(channel)

    # Session contexts dictionary: reuse per session_id, fresh across session_ids
    session_contexts: dict[str, SessionContext] = {}
    last_event_timestamps: dict[str, datetime] = {}

    # Statistics tracking
    total_events = len(events)
    total_decisions = 0
    verdict_counts: dict[str, int] = {}

    log_entries: list[str] = []

    # 3. Process events in order
    for idx, event in enumerate(events, start=1):
        if event.session_id not in session_contexts:
            session_contexts[event.session_id] = SessionContext(session_id=event.session_id)
            last_event_timestamps[event.session_id] = event.window_start
        else:
            prev_dt = last_event_timestamps[event.session_id]
            delta_sec = (event.window_start - prev_dt).total_seconds()
            if delta_sec > 0:
                context = session_contexts[event.session_id]
                for rule_usage in context.budget._usage.values():
                    if rule_usage.last_fired_at is not None:
                        rule_usage.last_fired_at -= delta_sec
            last_event_timestamps[event.session_id] = event.window_start

        context = session_contexts[event.session_id]
        decisions = policy_engine.evaluate(event, context)

        if not decisions:
            # If no rule triggered for the event
            timestamp = datetime.now(timezone.utc).isoformat()
            log_item = {
                "timestamp": timestamp,
                "event": event.model_dump(mode="json"),
                "decision": None,
                "mutation_result": None,
            }
            log_entries.append(json.dumps(log_item))
            print(
                f"[{idx:02d}/{total_events:02d}] Event: {event.semantic_id} | Session: {event.session_id} | "
                f"Intent: {event.intent:<23} | No Rule Triggered (0 Decisions)"
            )
            continue

        for decision in decisions:
            total_decisions += 1
            verdict_str = decision.verdict.value if isinstance(decision.verdict, Verdict) else str(decision.verdict)
            verdict_counts[verdict_str] = verdict_counts.get(verdict_str, 0) + 1

            mutation_result = None
            if decision.verdict == Verdict.EXECUTE:
                mutation_result = await deception_engine.execute_async(decision)

            # Record log entry
            timestamp = datetime.now(timezone.utc).isoformat()
            log_item = {
                "timestamp": timestamp,
                "event": event.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json"),
                "mutation_result": mutation_result.model_dump(mode="json") if mutation_result else None,
            }
            log_entries.append(json.dumps(log_item))

            # Progress output string formatting
            rule_id = decision.rule_id

            if mutation_result is not None:
                status_val = (
                    mutation_result.status.value
                    if isinstance(mutation_result.status, MutationStatus)
                    else str(mutation_result.status)
                )
                if status_val == "SKIPPED":
                    status_str = "SKIPPED"
                    primitive_str = "none (skipped)"
                    plausibility_str = "N/A"
                else:
                    status_str = status_val
                    primitive_str = decision.action if decision.action else "None"
                    plausibility_str = f"{mutation_result.plausibility_score:.2f}"
            else:
                status_str = "N/A"
                primitive_str = "None"
                plausibility_str = "N/A"

            print(
                f"[{idx:02d}/{total_events:02d}] Event: {event.semantic_id} | "
                f"Session: {event.session_id} | "
                f"Intent: {event.intent:<23} | "
                f"Rule: {rule_id:<8} | "
                f"Verdict: {verdict_str:<21} | "
                f"Status: {status_str:<8} | "
                f"Primitive: {primitive_str:<26} | "
                f"Plausibility: {plausibility_str}"
            )

    # 4. Write log file
    with open(log_file_path, "w", encoding="utf-8") as f:
        for entry in log_entries:
            f.write(entry + "\n")

    # 5. Generate Markdown summary report
    out_report_path = generate_report(log_file_path, report_path)

    print("\n" + "=" * 80)
    print("Simulation Run Summary")
    print("=" * 80)
    print(f"Total events processed : {total_events}")
    print(f"Total decisions        : {total_decisions}")
    print("Verdict breakdown      :")
    for verdict, count in sorted(verdict_counts.items()):
        print(f"  - {verdict:<22}: {count}")
    print(f"Logs written to        : {log_file_path}")
    print(f"Report generated at    : {out_report_path}")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
