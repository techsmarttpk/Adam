import json
from pathlib import Path
from unittest.mock import AsyncMock
import pytest

from adam.contracts.enums import Verdict, MutationStatus
from adam.contracts.semantic_event import SemanticEvent
from adam.policy.context import SessionContext
from adam.policy.engine import PolicyEngine
from adam.deception.engine import DeceptionEngine
from adam.deception.catalogue import get_primitive_class

FIXTURES_DIR = Path(__file__).parents[1] / "fixtures" / "semantic_events"
RULES_DIR = Path(__file__).parents[2] / "rules" / "default"


@pytest.mark.asyncio
async def test_replay_pipeline_end_to_end(capsys):
    engine = PolicyEngine(str(RULES_DIR), global_confidence_gate=0.60)
    fixture_files = sorted(FIXTURES_DIR.glob("*.json"))
    assert len(fixture_files) >= 10, f"Expected at least 10 fixtures, found {len(fixture_files)}"

    summary_rows = []

    for fixture_path in fixture_files:
        raw_data = json.loads(fixture_path.read_text(encoding="utf-8"))
        event = SemanticEvent.model_validate(raw_data)
        context = SessionContext(session_id=event.session_id)

        decisions = engine.evaluate(event, context)
        
        for decision in decisions:
            if decision.verdict == Verdict.EXECUTE and decision.action:
                channel = AsyncMock()
                deception_engine = DeceptionEngine(channel)

                # Execute mutation
                mutation = await deception_engine.execute_async(decision)
                assert mutation.status in (MutationStatus.APPLIED, MutationStatus.SKIPPED)

                if mutation.status == MutationStatus.APPLIED:
                    # Revert mutation
                    primitive_cls = get_primitive_class(decision.action)
                    primitive = primitive_cls(channel)
                    reverted_mutation = await primitive.revert_async(mutation)
                    assert reverted_mutation.status == MutationStatus.REVERTED
                    revert_str = "YES"
                    prim_str = decision.action
                else:
                    revert_str = "N/A (LOG_ONLY)"
                    prim_str = f"none ({decision.action})"

                summary_rows.append({
                    "intent": event.intent,
                    "rule": decision.rule_id,
                    "primitive": prim_str,
                    "plausibility": f"{mutation.plausibility_score:.2f}",
                    "revert_verified": revert_str
                })

    # Print Summary Table
    header = f"{'INTENT':<24} | {'RULE FIRED':<10} | {'PRIMITIVE EXECUTED':<27} | {'PLAUSIBILITY':<12} | {'REVERT VERIFIED':<15}"
    divider = "-" * len(header)
    table_lines = ["\nADAM Pipeline End-to-End Replay Summary:", divider, header, divider]

    for r in summary_rows:
        line = f"{r['intent']:<24} | {r['rule']:<10} | {r['primitive']:<27} | {r['plausibility']:<12} | {r['revert_verified']:<15}"
        table_lines.append(line)
    
    table_lines.append(divider)
    output_str = "\n".join(table_lines)
    
    with capsys.disabled():
        print(output_str)

    assert len(summary_rows) > 0
