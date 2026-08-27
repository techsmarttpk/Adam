"""
Generate ADAM Execution Summary Report (demo/REPORT.md or demo/REPORT_STRESS.md)

Reads JSONL decision logs and produces a simplified, strictly fact-based
Markdown summary. All data, counts, confidence values, rationale strings, and
plausibility statistics are extracted directly from the log file.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def generate_report(log_file_path: Path, report_path: Path | None = None) -> Path:
    """Generates a Markdown report from an execution JSONL log file."""
    if not log_file_path.is_absolute():
        log_file_path = BASE_DIR / log_file_path

    if report_path:
        if not report_path.is_absolute():
            report_path = BASE_DIR / report_path
    else:
        if "stress" in log_file_path.name:
            report_path = BASE_DIR / "demo" / "REPORT_STRESS.md"
        else:
            report_path = BASE_DIR / "demo" / "REPORT.md"

    if not log_file_path.exists():
        raise FileNotFoundError(f"Log file not found at {log_file_path}")

    entries = []
    with open(log_file_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line.strip()))

    total_events = len(entries)
    total_decisions = sum(1 for e in entries if e.get("decision") is not None)
    no_rule_count = total_events - total_decisions
    run_timestamp = entries[0]["timestamp"] if entries else "N/A"
    sessions = sorted(list({e["event"]["session_id"] for e in entries if "event" in e and "session_id" in e["event"]}))
    dataset_name = (
        "adam/fusion/logs/telemetry.json"
        if "telemetry" in str(log_file_path)
        else ("demo/datasets/large_telemetry_dataset.json" if "large" in log_file_path.name else "demo/datasets/telemetry_dataset.json")
    )

    # Verdict breakdown counters
    execute_applied_count = 0
    log_only_skipped_count = 0
    budget_suppressed_count = 0
    confidence_suppressed_count = 0
    cooldown_suppressed_count = 0

    applied_scores: list[float] = []
    suppressed_entries: list[dict] = []

    for entry in entries:
        dec = entry.get("decision")
        mut = entry.get("mutation_result")
        if not dec:
            continue

        verdict = dec.get("verdict")
        if verdict == "EXECUTE":
            if mut and mut.get("status") == "SKIPPED":
                log_only_skipped_count += 1
            else:
                execute_applied_count += 1
                if mut and "plausibility_score" in mut:
                    applied_scores.append(float(mut["plausibility_score"]))
        elif verdict == "SUPPRESSED_BUDGET":
            budget_suppressed_count += 1
            suppressed_entries.append(entry)
        elif verdict == "SUPPRESSED_CONFIDENCE":
            confidence_suppressed_count += 1
            suppressed_entries.append(entry)
        elif verdict == "SUPPRESSED_COOLDOWN":
            cooldown_suppressed_count += 1
            suppressed_entries.append(entry)

    pct = lambda count: (count / total_decisions * 100) if total_decisions > 0 else 0.0

    # Plausibility score calculations directly from logged values
    min_score = min(applied_scores) if applied_scores else 0.0
    max_score = max(applied_scores) if applied_scores else 0.0
    avg_score = (sum(applied_scores) / len(applied_scores)) if applied_scores else 0.0

    # Construct Markdown report
    lines: list[str] = []
    report_title = (
        "ADAM Adaptive Deception Analysis Report (Stress Run)"
        if "stress" in report_path.name.lower()
        else "ADAM Adaptive Deception Analysis Report"
    )
    lines.append(f"# {report_title}\n")

    # 1. Overview
    lines.append("## 1. Overview\n")
    lines.append(
        f"Processed {total_events} events across {len(sessions)} session(s) ({', '.join(sessions)}) "
        f"from `{dataset_name}`, producing {total_decisions} decisions (with {no_rule_count} unsupported/untriggered events producing zero decisions) on {run_timestamp}.\n"
    )

    # 2. Verdict Breakdown Table
    lines.append("## 2. Verdict Breakdown\n")
    lines.append("| Verdict Category | Count | Percentage |")
    lines.append("|---|---|---|")
    lines.append(f"| EXECUTE (Applied) | {execute_applied_count} | {pct(execute_applied_count):.2f}% |")
    lines.append(f"| LOG_ONLY-as-SKIPPED | {log_only_skipped_count} | {pct(log_only_skipped_count):.2f}% |")
    lines.append(f"| SUPPRESSED_BUDGET | {budget_suppressed_count} | {pct(budget_suppressed_count):.2f}% |")
    lines.append(f"| SUPPRESSED_CONFIDENCE | {confidence_suppressed_count} | {pct(confidence_suppressed_count):.2f}% |")
    lines.append(f"| SUPPRESSED_COOLDOWN | {cooldown_suppressed_count} | {pct(cooldown_suppressed_count):.2f}% |")
    lines.append(f"| **Total Decisions** | **{total_decisions}** | **100.00%** |\n")

    # 3. Per-Event Table
    lines.append("## 3. Per-Event Execution Ledger\n")
    lines.append("| Event ID | Intent | Rule | Verdict | Primitive | Plausibility |")
    lines.append("|---|---|---|---|---|---|")

    for entry in entries:
        ev = entry["event"]
        dec = entry.get("decision")
        mut = entry.get("mutation_result")

        sem_id = ev["semantic_id"]
        intent = ev["intent"]

        if dec:
            rule_id = dec["rule_id"]
            verdict = dec["verdict"]

            if mut:
                if mut["status"] == "SKIPPED":
                    primitive_str = "none (skipped)"
                    plaus_str = "N/A"
                else:
                    primitive_str = dec.get("action", "None")
                    plaus_str = f"{mut['plausibility_score']:.2f}"
            else:
                primitive_str = "None"
                plaus_str = "N/A"
        else:
            rule_id = "N/A"
            verdict = "NO_RULE (Zero Decisions)"
            primitive_str = "None"
            plaus_str = "N/A"

        lines.append(f"| `{sem_id}` | `{intent}` | `{rule_id}` | `{verdict}` | `{primitive_str}` | `{plaus_str}` |")

    lines.append("\n")

    # 4. Suppression Section
    lines.append("## 4. Suppression Verification\n")
    if suppressed_entries:
        for entry in suppressed_entries:
            ev = entry["event"]
            dec = entry["decision"]
            lines.append(f"- **`{ev['semantic_id']}`** (`{ev['intent']}`): confidence = `{ev['confidence']:.2f}` — `\"{dec['rationale']}\"`")
    else:
        lines.append("No suppressed events logged.")

    lines.append("\n")

    # 5. Plausibility Summary
    lines.append("## 5. Plausibility Score Distribution\n")
    lines.append(f"Plausibility Score (across {len(applied_scores)} applied mutations): Min = {min_score:.2f}, Max = {max_score:.2f}, Avg = {avg_score:.2f}.\n")

    # 6. Technical Notes
    lines.append("## 6. Technical Notes\n")
    lines.append("- This report combines EventFusionEngine output with PolicyEngine & DeceptionEngine evaluation.")
    lines.append(
        "- RULE-022 (EVADE_SANDBOX_DETECTED) intentionally produces no deception by design (verdict shows EXECUTE with action=LOG_ONLY internally, but DeceptionEngine skips environment mutation)."
    )

    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(description="ADAM Report Generator")
    parser.add_argument(
        "--log",
        type=str,
        default="demo/logs/simulation_run.jsonl",
        help="Path to input JSONL log file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to output Markdown report file",
    )
    args = parser.parse_args()

    log_path = Path(args.log)
    out_path = Path(args.output) if args.output else None
    result_path = generate_report(log_path, out_path)
    print(f"Report successfully generated at {result_path}")


if __name__ == "__main__":
    main()
