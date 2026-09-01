"""Research Subsystem Ablation Matrix Runner for ADAM.

Systematically measures the marginal contribution of each core component:
- FULL_ADAM (All subsystems active)
- WITHOUT_DRL (Rules-only policy)
- WITHOUT_VMI (Standard userspace-only instrumentation)
- WITHOUT_DECEPTION_MEMORY (Cold prior policy)
- WITHOUT_PROVENANCE_CAUSALITY (Naive timer window attribution)
- WITHOUT_ADAPTIVE_BUDGET (Static fixed budget)
"""

from __future__ import annotations
import dataclasses
from typing import Dict, List, Optional


@dataclasses.dataclass
class AblationConfiguration:
    config_name: str
    drl_enabled: bool = True
    vmi_enabled: bool = True
    deception_memory_enabled: bool = True
    provenance_tracking_enabled: bool = True
    adaptive_budget_enabled: bool = True
    synthetic_deception_enabled: bool = True


@dataclasses.dataclass
class AblationRunResult:
    config_name: str
    composite_yield_score: float
    semantic_events_count: int
    mutations_applied: int
    causal_attribution_rate: float
    deception_backfire_count: int
    relative_performance_drop_pct: float = 0.0


class SubsystemAblationMatrixRunner:
    """Evaluates the contribution of each architectural subsystem."""

    STANDARD_CONFIGS = [
        AblationConfiguration(config_name="FULL_ADAM"),
        AblationConfiguration(config_name="WITHOUT_DRL", drl_enabled=False),
        AblationConfiguration(config_name="WITHOUT_VMI", vmi_enabled=False),
        AblationConfiguration(config_name="WITHOUT_DECEPTION_MEMORY", deception_memory_enabled=False),
        AblationConfiguration(config_name="WITHOUT_PROVENANCE", provenance_tracking_enabled=False),
        AblationConfiguration(config_name="WITHOUT_ADAPTIVE_BUDGET", adaptive_budget_enabled=False),
    ]

    @classmethod
    def evaluate_ablation_results(
        cls, results: List[AblationRunResult]
    ) -> Dict[str, object]:
        """Calculates marginal percentage performance drops relative to Full ADAM."""
        full_adam = next((r for r in results if r.config_name == "FULL_ADAM"), None)
        baseline_score = full_adam.composite_yield_score if full_adam else 100.0

        for r in results:
            if r.config_name != "FULL_ADAM":
                drop = ((baseline_score - r.composite_yield_score) / max(1e-5, baseline_score)) * 100.0
                r.relative_performance_drop_pct = round(drop, 2)

        return {
            "baseline_score": baseline_score,
            "results": [dataclasses.asdict(r) for r in results],
        }
