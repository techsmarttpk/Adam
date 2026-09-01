"""Counterfactual Policy Evaluator and Candidate Ranking Engine.

Evaluates alternative candidate actions for an observed intent:
1. Generates expected utility predictions for Candidate A, Candidate B, Candidate C.
2. Selects optimal action.
3. Compares prediction vs actual observed reality post-execution.
4. Generates an explainability ledger for forensic and paper analysis.
"""

from __future__ import annotations
import dataclasses
import time
from typing import Dict, List, Optional, Tuple


@dataclasses.dataclass
class CandidateEvaluation:
    action_name: str
    expected_yield: float
    expected_confidence: float
    plausibility_score: float
    selected: bool
    selection_rationale: str


@dataclasses.dataclass
class CounterfactualDecisionLedger:
    decision_id: str
    intent: str
    timestamp_ns: int
    candidates: List[CandidateEvaluation]
    chosen_action: str
    actual_yield_observed: Optional[float] = None
    prediction_error: Optional[float] = None


class CounterfactualEvaluator:
    """Provides explainable candidate evaluation and prediction-vs-reality tracking."""

    def __init__(self) -> None:
        self.ledgers: Dict[str, CounterfactualDecisionLedger] = {}

    def evaluate_candidates(
        self,
        decision_id: str,
        intent: str,
        candidates: List[str],
        memory_scores: Dict[str, float],
        plausibility_scores: Dict[str, float],
    ) -> Tuple[str, CounterfactualDecisionLedger]:
        """Evaluates all candidate actions and selects the one with the highest composite utility."""
        evaluations: List[CandidateEvaluation] = []
        best_action = candidates[0] if candidates else "NOOP"
        best_score = -1.0

        for cand in candidates:
            exp_yield = memory_scores.get(cand, 50.0)
            plaus = plausibility_scores.get(cand, 1.0)
            # Composite utility = (Expected Yield * 0.7) + (Plausibility * 30.0)
            composite_utility = (exp_yield * 0.7) + (plaus * 30.0)

            is_best = composite_utility > best_score
            if is_best:
                best_score = composite_utility
                best_action = cand

            evaluations.append(
                CandidateEvaluation(
                    action_name=cand,
                    expected_yield=round(exp_yield, 2),
                    expected_confidence=0.85,
                    plausibility_score=round(plaus, 2),
                    selected=False,  # Will update best after loop
                    selection_rationale=f"Utility {composite_utility:.1f} (Yield: {exp_yield}, Plausibility: {plaus})",
                )
            )

        # Mark selected
        for ev in evaluations:
            if ev.action_name == best_action:
                ev.selected = True

        ledger = CounterfactualDecisionLedger(
            decision_id=decision_id,
            intent=intent,
            timestamp_ns=time.perf_counter_ns(),
            candidates=evaluations,
            chosen_action=best_action,
        )

        self.ledgers[decision_id] = ledger
        return best_action, ledger

    def record_actual_yield(self, decision_id: str, actual_yield: float) -> Optional[float]:
        """Records actual observed yield and computes prediction error."""
        if decision_id in self.ledgers:
            ledger = self.ledgers[decision_id]
            ledger.actual_yield_observed = actual_yield
            # Find chosen candidate expected yield
            chosen_eval = next((e for e in ledger.candidates if e.selected), None)
            if chosen_eval:
                err = round(actual_yield - chosen_eval.expected_yield, 2)
                ledger.prediction_error = err
                return err
        return None
