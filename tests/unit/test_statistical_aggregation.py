"""
tests/unit/test_statistical_aggregation.py

Acceptance tests for StatisticalAggregator:
1. Paired delta yield calculations across Control and Treatment arms.
2. Wilcoxon signed-rank non-parametric test sanity checks.
3. 95% Confidence interval calculation.
4. Per-family aggregate yield breakdown.
5. Plausibility score distributions and low-score flagging.
"""

from __future__ import annotations

import pytest

from adam.reporting.aggregate import (
    PairedSampleMetrics,
    StatisticalAggregator,
    calculate_wilcoxon_signed_rank,
    compute_confidence_interval_95,
)


def test_confidence_interval_computation():
    values = [0.45, 0.50, 0.40, 0.55, 0.60, 0.48, 0.52]
    ci = compute_confidence_interval_95(values)
    assert ci.mean == pytest.approx(0.50, abs=0.01)
    assert ci.ci_lower_95 < ci.mean < ci.ci_upper_95
    assert ci.std_dev > 0


def test_wilcoxon_signed_rank_directional_significance():
    # Treatment is systematically higher than Control across all pairs
    deltas = [0.40, 0.35, 0.45, 0.50, 0.30, 0.42, 0.38, 0.48, 0.52, 0.39, 0.41, 0.44]
    w = calculate_wilcoxon_signed_rank(deltas)
    assert w.n_pairs == 12
    assert w.z_score > 0
    assert w.p_value < 0.05
    assert w.significant_at_05 is True


def test_statistical_aggregator_full_analysis():
    paired_samples = [
        PairedSampleMetrics(
            sample_sha256="1" * 64,
            filename="sample_ransomware_1.exe",
            family_label="Ransomware.LockBit",
            control_yield=0.35,
            treatment_yield=0.85,
            delta_yield=0.50,
            control_events=20,
            treatment_events=60,
            control_decisions=0,
            treatment_decisions=10,
        ),
        PairedSampleMetrics(
            sample_sha256="2" * 64,
            filename="sample_ransomware_2.exe",
            family_label="Ransomware.LockBit",
            control_yield=0.40,
            treatment_yield=0.90,
            delta_yield=0.50,
            control_events=22,
            treatment_events=65,
            control_decisions=0,
            treatment_decisions=12,
        ),
        PairedSampleMetrics(
            sample_sha256="3" * 64,
            filename="sample_stealer_1.exe",
            family_label="InfoStealer.RedLine",
            control_yield=0.25,
            treatment_yield=0.70,
            delta_yield=0.45,
            control_events=15,
            treatment_events=45,
            control_decisions=0,
            treatment_decisions=8,
        ),
    ]

    primitive_executions = [
        {"primitive_name": "PLANT_DECOY_DOCUMENTS", "plausibility_score": 0.90},
        {"primitive_name": "PLANT_DECOY_DOCUMENTS", "plausibility_score": 0.90},
        {"primitive_name": "ACCELERATE_SYSTEM_CLOCK", "plausibility_score": 0.60},
        {"primitive_name": "LOW_SCORING_PRIMITIVE", "plausibility_score": 0.30},
    ]

    aggregator = StatisticalAggregator(plausibility_threshold=0.50)
    report = aggregator.analyze_benchmark(
        experiment_id="exp_test_synthetic",
        paired_samples=paired_samples,
        primitive_executions=primitive_executions,
    )

    assert report.total_pairs == 3
    assert report.mean_delta_yield == pytest.approx(0.483, abs=0.01)
    assert len(report.family_breakdowns) == 2

    # Check that low scoring primitive was flagged
    low_prim = next(p for p in report.primitive_plausibility if p.primitive_name == "LOW_SCORING_PRIMITIVE")
    assert low_prim.flagged_low is True

    high_prim = next(p for p in report.primitive_plausibility if p.primitive_name == "PLANT_DECOY_DOCUMENTS")
    assert high_prim.flagged_low is False
