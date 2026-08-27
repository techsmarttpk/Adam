"""
adam/reporting/aggregate.py

Statistical aggregation and paired A/B benchmarking analysis.
Calculates paired yield delta (Delta Y), Wilcoxon signed-rank non-parametric tests,
95% confidence intervals, per-family breakdowns, and deception plausibility distributions.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PairedSampleMetrics(BaseModel):
    sample_sha256: str
    filename: str
    family_label: Optional[str] = None
    control_yield: float = Field(ge=0.0)
    treatment_yield: float = Field(ge=0.0)
    delta_yield: float
    control_events: int = Field(ge=0)
    treatment_events: int = Field(ge=0)
    control_decisions: int = Field(ge=0)
    treatment_decisions: int = Field(ge=0)


class WilcoxonResult(BaseModel):
    statistic_w: float
    z_score: float
    p_value: float
    n_pairs: int
    n_nonzero: int
    significant_at_05: bool


class ConfidenceInterval(BaseModel):
    mean: float
    ci_lower_95: float
    ci_upper_95: float
    std_err: float
    std_dev: float


class FamilyBreakdown(BaseModel):
    family_label: str
    sample_count: int
    mean_control_yield: float
    mean_treatment_yield: float
    mean_delta_yield: float


class PlausibilityPrimitiveStat(BaseModel):
    primitive_name: str
    execution_count: int
    mean_score: float
    min_score: float
    max_score: float
    flagged_low: bool = False


class BenchmarkAggregateReport(BaseModel):
    experiment_id: str
    total_pairs: int
    mean_delta_yield: float
    median_delta_yield: float
    confidence_interval_95: ConfidenceInterval
    wilcoxon_test: WilcoxonResult
    per_sample_pairs: List[PairedSampleMetrics] = Field(default_factory=list)
    family_breakdowns: List[FamilyBreakdown] = Field(default_factory=list)
    primitive_plausibility: List[PlausibilityPrimitiveStat] = Field(default_factory=list)


def calculate_wilcoxon_signed_rank(deltas: list[float]) -> WilcoxonResult:
    """
    Computes Wilcoxon signed-rank test for paired samples.
    Tests if treatment yield systematically exceeds control yield.
    """
    diffs = [d for d in deltas if abs(d) > 1e-9]
    n_nonzero = len(diffs)
    n_total = len(deltas)

    if n_nonzero == 0:
        return WilcoxonResult(
            statistic_w=0.0,
            z_score=0.0,
            p_value=1.0,
            n_pairs=n_total,
            n_nonzero=0,
            significant_at_05=False,
        )

    # Rank absolute differences
    abs_diffs = sorted(enumerate(diffs), key=lambda x: abs(x[1]))
    ranks: list[float] = [0.0] * n_nonzero

    # Assign average ranks for ties
    i = 0
    while i < n_nonzero:
        j = i
        while j < n_nonzero and abs(abs(abs_diffs[j][1]) - abs(abs_diffs[i][1])) < 1e-9:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            orig_idx = abs_diffs[k][0]
            ranks[orig_idx] = avg_rank
        i = j

    # Sum of ranks for positive differences (W+)
    w_plus = sum(rank for rank, diff in zip(ranks, diffs) if diff > 0)
    w_minus = sum(rank for rank, diff in zip(ranks, diffs) if diff < 0)
    w_stat = min(w_plus, w_minus)

    # Normal approximation for n >= 10
    mean_w = n_nonzero * (n_nonzero + 1) / 4.0
    var_w = n_nonzero * (n_nonzero + 1) * (2 * n_nonzero + 1) / 24.0
    std_w = math.sqrt(var_w) if var_w > 0 else 1.0

    z_score = (w_plus - mean_w) / std_w

    # Approximate two-tailed p-value using erf
    p_value = math.erfc(abs(z_score) / math.sqrt(2.0))

    return WilcoxonResult(
        statistic_w=float(w_stat),
        z_score=float(z_score),
        p_value=float(p_value),
        n_pairs=n_total,
        n_nonzero=n_nonzero,
        significant_at_05=p_value < 0.05 and z_score > 0,
    )


def compute_confidence_interval_95(values: list[float]) -> ConfidenceInterval:
    """Computes sample mean, standard deviation, and 95% confidence interval."""
    n = len(values)
    if n == 0:
        return ConfidenceInterval(mean=0.0, ci_lower_95=0.0, ci_upper_95=0.0, std_err=0.0, std_dev=0.0)

    mean_val = sum(values) / n
    if n == 1:
        return ConfidenceInterval(
            mean=mean_val,
            ci_lower_95=mean_val,
            ci_upper_95=mean_val,
            std_err=0.0,
            std_dev=0.0,
        )

    variance = sum((x - mean_val) ** 2 for x in values) / (n - 1)
    std_dev = math.sqrt(variance)
    std_err = std_dev / math.sqrt(n)

    # Standard 1.96 critical value for 95% CI
    ci_lower = mean_val - 1.96 * std_err
    ci_upper = mean_val + 1.96 * std_err

    return ConfidenceInterval(
        mean=float(mean_val),
        ci_lower_95=float(ci_lower),
        ci_upper_95=float(ci_upper),
        std_err=float(std_err),
        std_dev=float(std_dev),
    )


class StatisticalAggregator:
    """
    Orchestrates paired statistical benchmarking and reporting across control and treatment arms.
    """

    def __init__(self, plausibility_threshold: float = 0.50) -> None:
        self.plausibility_threshold = plausibility_threshold

    def analyze_benchmark(
        self,
        experiment_id: str,
        paired_samples: list[PairedSampleMetrics],
        primitive_executions: list[dict[str, Any]] | None = None,
    ) -> BenchmarkAggregateReport:
        if not paired_samples:
            raise ValueError("Cannot analyze empty paired sample set")

        deltas = [p.delta_yield for p in paired_samples]
        sorted_deltas = sorted(deltas)
        n = len(deltas)

        # Median
        if n % 2 == 1:
            median_delta = sorted_deltas[n // 2]
        else:
            median_delta = (sorted_deltas[n // 2 - 1] + sorted_deltas[n // 2]) / 2.0

        ci_95 = compute_confidence_interval_95(deltas)
        wilcoxon = calculate_wilcoxon_signed_rank(deltas)

        # Per-family breakdown
        families: dict[str, list[PairedSampleMetrics]] = {}
        for p in paired_samples:
            fam = p.family_label or "Unclassified"
            families.setdefault(fam, []).append(p)

        family_stats = []
        for fam, items in sorted(families.items()):
            f_count = len(items)
            f_ctrl = sum(x.control_yield for x in items) / f_count
            f_trt = sum(x.treatment_yield for x in items) / f_count
            f_delta = sum(x.delta_yield for x in items) / f_count
            family_stats.append(
                FamilyBreakdown(
                    family_label=fam,
                    sample_count=f_count,
                    mean_control_yield=float(f_ctrl),
                    mean_treatment_yield=float(f_trt),
                    mean_delta_yield=float(f_delta),
                )
            )

        # Plausibility distributions
        primitive_stats = []
        if primitive_executions:
            prim_groups: dict[str, list[float]] = {}
            for pe in primitive_executions:
                name = pe.get("primitive_name", "UNKNOWN")
                score = pe.get("plausibility_score", 1.0)
                prim_groups.setdefault(name, []).append(float(score))

            for name, scores in sorted(prim_groups.items()):
                mean_s = sum(scores) / len(scores)
                primitive_stats.append(
                    PlausibilityPrimitiveStat(
                        primitive_name=name,
                        execution_count=len(scores),
                        mean_score=float(mean_s),
                        min_score=float(min(scores)),
                        max_score=float(max(scores)),
                        flagged_low=mean_s < self.plausibility_threshold,
                    )
                )

        return BenchmarkAggregateReport(
            experiment_id=experiment_id,
            total_pairs=n,
            mean_delta_yield=ci_95.mean,
            median_delta_yield=float(median_delta),
            confidence_interval_95=ci_95,
            wilcoxon_test=wilcoxon,
            per_sample_pairs=paired_samples,
            family_breakdowns=family_stats,
            primitive_plausibility=primitive_stats,
        )
