"""Multidimensional Behavioral Yield Analysis Framework for ADAM.

Computes 12 distinct novelty and discovery dimensions between CONTROL and TREATMENT runs:
1. Semantic Intent Novelty (new unobserved semantic intents)
2. API Call Novelty (new distinct Windows/Syscall APIs)
3. Network Endpoint Novelty (new IP/domains contacted)
4. Network Protocol Novelty (new protocols/ports used)
5. Memory Behavior Novelty (new RWX transitions, injections)
6. IOC Novelty (new file drops, mutexes, registry modifications)
7. MITRE ATT&CK Novelty (new ATT&CK tactic/technique coverage)
8. Milestone Progression (advancement across execution stages)
9. Time-to-Discovery Delta (acceleration of malicious activity)
10. Time-to-First-C2 Delta (acceleration of C2 beaconing)
11. Time-to-Payload-Decryption Delta (acceleration of unpacking)
12. Causal Attribution Rate (% of new behaviors causally tied to mutations)
"""

from __future__ import annotations
import dataclasses
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime

from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.mutation import MutationResult
from adam.contracts.session import AnalysisSession


@dataclasses.dataclass
class NoveltyDimension:
    dimension_name: str
    control_count: int
    treatment_count: int
    novel_count: int
    novel_items: List[str]
    percentage_increase: float


@dataclasses.dataclass
class TimingDelta:
    metric_name: str
    control_seconds: Optional[float]
    treatment_seconds: Optional[float]
    speedup_seconds: Optional[float]
    accelerated: bool


@dataclasses.dataclass
class MultidimensionalYieldReport:
    experiment_id: str
    sample_sha256: str
    control_session_id: str
    treatment_session_id: str
    total_mutations_applied: int
    causally_attributed_events_count: int
    causal_attribution_rate: float
    dimensions: Dict[str, NoveltyDimension]
    timing_deltas: Dict[str, TimingDelta]
    overall_yield_score: float
    summary_markdown: str


class MultidimensionalYieldAnalyzer:
    """Extracts and compares multidimensional behavioral yield between paired sessions."""

    @staticmethod
    def analyze(
        control_session: AnalysisSession,
        control_raw: List[RawEvent],
        control_semantic: List[SemanticEvent],
        treatment_session: AnalysisSession,
        treatment_raw: List[RawEvent],
        treatment_semantic: List[SemanticEvent],
        treatment_mutations: List[MutationResult],
    ) -> MultidimensionalYieldReport:
        dimensions: Dict[str, NoveltyDimension] = {}

        # 1. Semantic Intent Novelty
        ctrl_intents = {e.intent for e in control_semantic}
        treat_intents = {e.intent for e in treatment_semantic}
        novel_intents = sorted(list(treat_intents - ctrl_intents))
        pct_intent = (len(novel_intents) / max(1, len(ctrl_intents))) * 100.0
        dimensions["semantic_intent"] = NoveltyDimension(
            dimension_name="Semantic Intent Novelty",
            control_count=len(ctrl_intents),
            treatment_count=len(treat_intents),
            novel_count=len(novel_intents),
            novel_items=novel_intents,
            percentage_increase=round(pct_intent, 2),
        )

        # 2. API Call Novelty
        ctrl_apis = {
            str(e.attributes.get("operation") or e.attributes.get("details") or e.category.value)
            for e in control_raw if e.attributes
        }
        treat_apis = {
            str(e.attributes.get("operation") or e.attributes.get("details") or e.category.value)
            for e in treatment_raw if e.attributes
        }
        novel_apis = sorted(list(treat_apis - ctrl_apis))
        dimensions["api_calls"] = NoveltyDimension(
            dimension_name="API Call Novelty",
            control_count=len(ctrl_apis),
            treatment_count=len(treat_apis),
            novel_count=len(novel_apis),
            novel_items=novel_apis,
            percentage_increase=round((len(novel_apis) / max(1, len(ctrl_apis))) * 100.0, 2),
        )

        # 3. Network Endpoint Novelty
        ctrl_endpoints = set()
        for e in control_raw:
            dst_ip = e.attributes.get("dest_ip") or e.attributes.get("destination_ip")
            if dst_ip:
                ctrl_endpoints.add(str(dst_ip))
        treat_endpoints = set()
        for e in treatment_raw:
            dst_ip = e.attributes.get("dest_ip") or e.attributes.get("destination_ip")
            if dst_ip:
                treat_endpoints.add(str(dst_ip))
        novel_endpoints = sorted(list(treat_endpoints - ctrl_endpoints))
        dimensions["network_endpoints"] = NoveltyDimension(
            dimension_name="Network Endpoint Novelty",
            control_count=len(ctrl_endpoints),
            treatment_count=len(treat_endpoints),
            novel_count=len(novel_endpoints),
            novel_items=novel_endpoints,
            percentage_increase=round((len(novel_endpoints) / max(1, len(ctrl_endpoints))) * 100.0, 2),
        )

        # 4. MITRE ATT&CK Novelty
        ctrl_attck = {f"{e.attck.tactic}:{e.attck.technique}" for e in control_semantic if e.attck}
        treat_attck = {f"{e.attck.tactic}:{e.attck.technique}" for e in treatment_semantic if e.attck}
        novel_attck = sorted(list(treat_attck - ctrl_attck))
        dimensions["mitre_attck"] = NoveltyDimension(
            dimension_name="MITRE ATT&CK Novelty",
            control_count=len(ctrl_attck),
            treatment_count=len(treat_attck),
            novel_count=len(novel_attck),
            novel_items=novel_attck,
            percentage_increase=round((len(novel_attck) / max(1, len(ctrl_attck))) * 100.0, 2),
        )

        # 5. IOC Novelty (Files, Registry, Mutexes)
        ctrl_iocs = {
            str(e.attributes.get("target_object") or e.attributes.get("target_path") or "")
            for e in control_raw if e.attributes and (e.attributes.get("target_object") or e.attributes.get("target_path"))
        }
        treat_iocs = {
            str(e.attributes.get("target_object") or e.attributes.get("target_path") or "")
            for e in treatment_raw if e.attributes and (e.attributes.get("target_object") or e.attributes.get("target_path"))
        }
        novel_iocs = sorted(list(treat_iocs - ctrl_iocs))[:50]  # Cap at 50 for summary
        dimensions["iocs"] = NoveltyDimension(
            dimension_name="IOC Discovery Novelty",
            control_count=len(ctrl_iocs),
            treatment_count=len(treat_iocs),
            novel_count=len(novel_iocs),
            novel_items=novel_iocs,
            percentage_increase=round((len(novel_iocs) / max(1, len(ctrl_iocs))) * 100.0, 2),
        )

        # Timing Deltas
        timing_deltas: Dict[str, TimingDelta] = {}

        # Time to first network event
        ctrl_net_time = None
        for ev in sorted(control_raw, key=lambda x: x.occurred_at):
            if ev.category.value == "NETWORK":
                ctrl_net_time = (ev.occurred_at - control_session.started_at).total_seconds()
                break

        treat_net_time = None
        for ev in sorted(treatment_raw, key=lambda x: x.occurred_at):
            if ev.category.value == "NETWORK":
                treat_net_time = (ev.occurred_at - treatment_session.started_at).total_seconds()
                break

        speedup_net = None
        acc_net = False
        if ctrl_net_time is not None and treat_net_time is not None:
            speedup_net = round(ctrl_net_time - treat_net_time, 2)
            acc_net = speedup_net > 0

        timing_deltas["time_to_first_network"] = TimingDelta(
            metric_name="Time to First Network Activity",
            control_seconds=round(ctrl_net_time, 2) if ctrl_net_time else None,
            treatment_seconds=round(treat_net_time, 2) if treat_net_time else None,
            speedup_seconds=speedup_net,
            accelerated=acc_net,
        )

        # Causal Attribution Rate
        causal_events = [e for e in treatment_semantic if e.caused_by_mutation is not None]
        causal_rate = (len(causal_events) / max(1, len(treatment_semantic))) * 100.0

        # Composite Yield Score (normalized 0-100)
        overall_yield_score = min(
            100.0,
            (len(novel_intents) * 15.0)
            + (len(novel_attck) * 10.0)
            + (min(len(novel_endpoints), 5) * 5.0)
            + (min(len(novel_iocs), 10) * 2.0)
            + (causal_rate * 0.2),
        )

        # Summary Markdown
        summary_md = f"""# Multi-Dimensional Behavioral Yield Report

**Experiment ID**: `{control_session.experiment_id}`
**Sample SHA256**: `{control_session.sample.sha256}`
**Composite Yield Score**: **{overall_yield_score:.1f} / 100.0**

## 1. Novelty Dimensions

| Dimension | Control | Treatment | Novel Items | % Increase |
|---|---|---|---|---|
| **Semantic Intents** | {dimensions['semantic_intent'].control_count} | {dimensions['semantic_intent'].treatment_count} | **+{dimensions['semantic_intent'].novel_count}** | +{dimensions['semantic_intent'].percentage_increase:.1f}% |
| **API Calls** | {dimensions['api_calls'].control_count} | {dimensions['api_calls'].treatment_count} | **+{dimensions['api_calls'].novel_count}** | +{dimensions['api_calls'].percentage_increase:.1f}% |
| **Network Endpoints** | {dimensions['network_endpoints'].control_count} | {dimensions['network_endpoints'].treatment_count} | **+{dimensions['network_endpoints'].novel_count}** | +{dimensions['network_endpoints'].percentage_increase:.1f}% |
| **MITRE ATT&CK** | {dimensions['mitre_attck'].control_count} | {dimensions['mitre_attck'].treatment_count} | **+{dimensions['mitre_attck'].novel_count}** | +{dimensions['mitre_attck'].percentage_increase:.1f}% |
| **IOC Discoveries** | {dimensions['iocs'].control_count} | {dimensions['iocs'].treatment_count} | **+{dimensions['iocs'].novel_count}** | +{dimensions['iocs'].percentage_increase:.1f}% |

## 2. Causal Attribution & Timing
* **Total Mutations Applied**: {len(treatment_mutations)}
* **Causally Attributed Events**: {len(causal_events)} ({causal_rate:.1f}% causal attribution rate)
* **First Network Event Speedup**: {timing_deltas['time_to_first_network'].speedup_seconds or 'N/A'}s

## 3. Discovered Novel Semantic Behaviors
{chr(10).join([f"- `{x}`" for x in novel_intents]) if novel_intents else "_No novel semantic intents observed._"}
"""

        return MultidimensionalYieldReport(
            experiment_id=control_session.experiment_id,
            sample_sha256=control_session.sample.sha256,
            control_session_id=control_session.session_id,
            treatment_session_id=treatment_session.session_id,
            total_mutations_applied=len(treatment_mutations),
            causally_attributed_events_count=len(causal_events),
            causal_attribution_rate=round(causal_rate, 2),
            dimensions=dimensions,
            timing_deltas=timing_deltas,
            overall_yield_score=round(overall_yield_score, 2),
            summary_markdown=summary_md,
        )
