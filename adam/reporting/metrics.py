"""Evaluation and Analytical Metrics Framework.

Calculates True Positive Rate (TPR), False Positive Rate (FPR),
Detection Latency (Delta t), Intelligence Gain (IOCs per sample),
and Adversarial Robustness / Concept Drift resistance.
"""

from __future__ import annotations
import dataclasses
from typing import Dict, List, Optional


@dataclasses.dataclass
class EvaluationReport:
    total_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    tpr: float
    fpr: float
    accuracy: float
    mean_detection_latency_ms: float
    mean_intelligence_gain_iocs: float
    adversarial_generalization_rate: float


class MetricsCalculator:
    """Calculates streaming and batch evaluation metrics for the AMTD sandbox."""

    def __init__(self) -> None:
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
        self.latencies_ms: List[float] = []
        self.ioc_counts: List[int] = []
        self.adversarial_evasions_defeated = 0
        self.total_adversarial_samples = 0

    def record_sample_result(
        self,
        is_malicious: bool,
        detected_as_malicious: bool,
        detection_latency_ms: float,
        iocs_extracted: int,
        is_adversarial_variant: bool = False,
    ) -> None:
        if is_malicious and detected_as_malicious:
            self.tp += 1
        elif not is_malicious and detected_as_malicious:
            self.fp += 1
        elif not is_malicious and not detected_as_malicious:
            self.tn += 1
        else:
            self.fn += 1

        self.latencies_ms.append(detection_latency_ms)
        self.ioc_counts.append(iocs_extracted)

        if is_adversarial_variant:
            self.total_adversarial_samples += 1
            if detected_as_malicious:
                self.adversarial_evasions_defeated += 1

    def generate_evaluation_report(self) -> EvaluationReport:
        total = self.tp + self.fp + self.tn + self.fn
        tpr = self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0
        fpr = self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0
        accuracy = (self.tp + self.tn) / total if total > 0 else 0.0

        mean_latency = sum(self.latencies_ms) / len(self.latencies_ms) if self.latencies_ms else 0.0
        mean_iocs = sum(self.ioc_counts) / len(self.ioc_counts) if self.ioc_counts else 0.0

        adv_rate = (
            self.adversarial_evasions_defeated / self.total_adversarial_samples
            if self.total_adversarial_samples > 0
            else 1.0
        )

        return EvaluationReport(
            total_samples=total,
            true_positives=self.tp,
            false_positives=self.fp,
            true_negatives=self.tn,
            false_negatives=self.fn,
            tpr=round(tpr, 4),
            fpr=round(fpr, 4),
            accuracy=round(accuracy, 4),
            mean_detection_latency_ms=round(mean_latency, 2),
            mean_intelligence_gain_iocs=round(mean_iocs, 2),
            adversarial_generalization_rate=round(adv_rate, 4),
        )
