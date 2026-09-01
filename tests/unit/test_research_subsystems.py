"""Unit and Integration Tests for ADAM Research-Grade Subsystems."""

import pytest
from datetime import datetime, timezone
from adam.contracts.enums import EventCategory, EventSource, MutationStatus, DeceptionArm, SessionStatus, NetworkMode
from adam.contracts.raw_event import RawEvent, ProcessContext
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.mutation import MutationResult, MutationChange
from adam.contracts.session import AnalysisSession, SampleMetadata, SessionConfig, SessionMetrics

from adam.core.provenance.tracker import CausalProvenanceEngine
from adam.core.environment.state_model import EnvironmentStateModel, CrossSourceConsistencyChecker
from adam.policy.memory.store import DeceptionMemoryStore
from adam.policy.backfire import DeceptionBackfireDetector
from adam.policy.chains.planner import DeceptionChainPlanner
from adam.policy.adaptive_budget import AdaptiveBudgetManager
from adam.policy.counterfactual import CounterfactualEvaluator
from adam.reporting.multidimensional_yield import MultidimensionalYieldAnalyzer
from adam.experiments.runner import ExperimentRunner
from adam.experiments.ablation import SubsystemAblationMatrixRunner, AblationRunResult


def test_causal_provenance_engine_scoping():
    engine = CausalProvenanceEngine(default_window_ms=5000)
    now = datetime.now(timezone.utc)

    mut = MutationResult(
        mutation_id="mut_001",
        session_id="sess_001",
        correlation_id="corr_001",
        decision_id="dec_001",
        primitive="SPAWN_FAKE_DC_ARTIFACTS",
        status=MutationStatus.APPLIED,
        applied_at=now,
        latency_ms=15.0,
        changes=[
            MutationChange(kind="REGISTRY", target="HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Domain", operation="SET", value="CORP.LOCAL"),
            MutationChange(kind="NETWORK", target="dns:DC01.CORP.LOCAL", operation="RESPOND", value="10.0.0.10"),
        ],
        plausibility_score=0.9,
    )
    engine.register_mutation(mut)

    # 1. Matching Raw Event
    matching_raw = RawEvent(
        event_id="raw_001",
        session_id="sess_001",
        source=EventSource.SYSMON,
        category=EventCategory.REGISTRY,
        occurred_at=now,
        observed_at=now,
        process=ProcessContext(pid=1234),
        attributes={"target_object": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Domain"},
    )
    causal_hit = engine.evaluate_raw_event_causality(matching_raw)
    assert causal_hit is not None
    assert causal_hit[0] == "mut_001"
    assert causal_hit[1] >= 0.9

    # 2. Semantic Event Attribution
    sem_event = SemanticEvent(
        semantic_id="sem_001",
        session_id="sess_001",
        correlation_id="corr_001",
        intent="RECON_DOMAIN_CONTROLLER",
        confidence=0.95,
        severity="HIGH",
        window_start=now,
        window_end=now,
        evidence=["raw_001"],
        detector="DomainDetector@1.0",
        features={"target_path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Domain"},
    )
    attributed = engine.attribute_semantic_event(sem_event)
    assert attributed == "mut_001"

    # 3. Provenance Chain DAG Query
    chain = engine.get_provenance_chain("sem_001")
    assert len(chain) >= 1
    assert any(c.source_id == "mut_001" for c in chain)


def test_environment_state_consistency_checker():
    env = EnvironmentStateModel()
    env.update_from_mutation(
        "SPAWN_FAKE_DC_ARTIFACTS",
        {"domain_name": "CORP.LOCAL", "dc_hostname": "DC01"},
    )

    assert env.domain_name == "CORP.LOCAL"
    assert "DC01.CORP.LOCAL" in env.dns_hosts_entries

    # Plausible check
    res = CrossSourceConsistencyChecker.evaluate_mutation_plausibility(
        env, "SPAWN_FAKE_DC_ARTIFACTS", {"domain_name": "CORP.LOCAL", "dc_hostname": "DC01"}
    )
    assert res.is_consistent
    assert res.score >= 0.8


def test_deception_memory_and_ranking():
    store = DeceptionMemoryStore()
    fp = store.compute_behavioral_fingerprint(
        intents_sequence=["RECON_DOMAIN_CONTROLLER", "LATERAL_SMB_ENUM"],
        accessed_categories=["REGISTRY", "NETWORK"],
        network_destinations_count=2,
    )

    store.record_outcome(
        fingerprint_hash=fp,
        intent="RECON_DOMAIN_CONTROLLER",
        mutation_action="SPAWN_FAKE_DC_ARTIFACTS",
        yield_score=85.0,
        new_semantic_events=4,
        new_iocs=2,
        deception_detected=False,
    )

    store.record_outcome(
        fingerprint_hash=fp,
        intent="RECON_DOMAIN_CONTROLLER",
        mutation_action="SIMULATE_AV_PRESENCE",
        yield_score=20.0,
        new_semantic_events=0,
        new_iocs=0,
        deception_detected=True,
    )

    ranked = store.rank_candidate_mutations(
        fingerprint_hash=fp,
        intent="RECON_DOMAIN_CONTROLLER",
        candidate_actions=["SIMULATE_AV_PRESENCE", "SPAWN_FAKE_DC_ARTIFACTS"],
    )

    assert ranked[0][0] == "SPAWN_FAKE_DC_ARTIFACTS"
    assert ranked[0][1] > ranked[1][1]


def test_deception_backfire_detection():
    detector = DeceptionBackfireDetector()
    now = datetime.now(timezone.utc)
    detector.set_active_mutation("mut_001", now)

    sleep_raw = RawEvent(
        event_id="raw_sleep",
        session_id="sess_001",
        source=EventSource.PROCMON,
        category=EventCategory.SYSTEM,
        occurred_at=now,
        observed_at=now,
        attributes={"operation": "NtDelayExecution", "details": "Sleep 30000ms"},
    )
    alert = detector.inspect_raw_event(sleep_raw)
    assert alert is not None
    assert alert.indicator_type == "SUDDEN_SLEEP_AFTER_MUTATION"
    assert detector.has_backfired_on_mutation("mut_001")


def test_deception_chain_planner():
    planner = DeceptionChainPlanner()
    step1 = planner.get_next_chain_action("RECON_DOMAIN_CONTROLLER")
    assert step1 is not None
    chain_name, action = step1
    assert chain_name == "DOMAIN_LATERAL_TRAP"
    assert action == "SPAWN_FAKE_DC_ARTIFACTS"

    step2 = planner.get_next_chain_action("LATERAL_SMB_ENUM")
    assert step2 is not None
    assert step2[1] == "MOUNT_FAKE_NETWORK_SHARE"


def test_adaptive_budget_manager():
    mgr = AdaptiveBudgetManager(global_max_mutations=2, default_per_action_budget=1)
    can_exec, _ = mgr.can_execute("SPAWN_FAKE_DC_ARTIFACTS")
    assert can_exec

    mgr.record_execution("SPAWN_FAKE_DC_ARTIFACTS")
    can_exec2, _ = mgr.can_execute("SPAWN_FAKE_DC_ARTIFACTS")
    assert not can_exec2  # Per-action budget hit

    # Update with high yield -> expands budget
    mgr.update_yield_feedback("SPAWN_FAKE_DC_ARTIFACTS", yield_score=75.0)
    can_exec3, _ = mgr.can_execute("SPAWN_FAKE_DC_ARTIFACTS")
    assert can_exec3


def test_counterfactual_evaluator():
    evaluator = CounterfactualEvaluator()
    chosen, ledger = evaluator.evaluate_candidates(
        decision_id="dec_001",
        intent="RECON_DOMAIN_CONTROLLER",
        candidates=["SPAWN_FAKE_DC_ARTIFACTS", "PLANT_DECOY_DOCUMENTS"],
        memory_scores={"SPAWN_FAKE_DC_ARTIFACTS": 90.0, "PLANT_DECOY_DOCUMENTS": 30.0},
        plausibility_scores={"SPAWN_FAKE_DC_ARTIFACTS": 0.9, "PLANT_DECOY_DOCUMENTS": 0.7},
    )
    assert chosen == "SPAWN_FAKE_DC_ARTIFACTS"
    assert ledger.chosen_action == "SPAWN_FAKE_DC_ARTIFACTS"

    err = evaluator.record_actual_yield("dec_001", actual_yield=85.0)
    assert err is not None
    assert ledger.actual_yield_observed == 85.0


def test_multidimensional_yield_analyzer():
    now = datetime.now(timezone.utc)
    sample = SampleMetadata(sha256="abc", md5="def", filename="sample.exe", size_bytes=1024, file_type="PE")
    cfg = SessionConfig(deception_enabled=False, policy_ruleset="default", vm_profile="win10", timeout_seconds=60, network_mode=NetworkMode.SIMULATED)

    ctrl_sess = AnalysisSession(session_id="ctrl_01", experiment_id="exp_01", arm=DeceptionArm.CONTROL, sample=sample, config=cfg, status=SessionStatus.COMPLETED, started_at=now, metrics=SessionMetrics())
    treat_sess = AnalysisSession(session_id="treat_01", experiment_id="exp_01", arm=DeceptionArm.TREATMENT, sample=sample, config=cfg, status=SessionStatus.COMPLETED, started_at=now, metrics=SessionMetrics())

    ctrl_sem = [
        SemanticEvent(semantic_id="sem_c1", session_id="ctrl_01", correlation_id="c1", intent="RECON_VM", confidence=0.8, severity="LOW", window_start=now, window_end=now, evidence=[], detector="d1", features={})
    ]
    treat_sem = [
        SemanticEvent(semantic_id="sem_t1", session_id="treat_01", correlation_id="t1", intent="RECON_VM", confidence=0.8, severity="LOW", window_start=now, window_end=now, evidence=[], detector="d1", features={}),
        SemanticEvent(semantic_id="sem_t2", session_id="treat_01", correlation_id="t2", intent="LATERAL_SMB_ENUM", confidence=0.9, severity="HIGH", window_start=now, window_end=now, evidence=[], detector="d2", features={}, caused_by_mutation="mut_01"),
    ]

    report = MultidimensionalYieldAnalyzer.analyze(
        control_session=ctrl_sess,
        control_raw=[],
        control_semantic=ctrl_sem,
        treatment_session=treat_sess,
        treatment_raw=[],
        treatment_semantic=treat_sem,
        treatment_mutations=[MutationResult(mutation_id="mut_01", session_id="treat_01", correlation_id="c1", decision_id="d1", primitive="p1", status=MutationStatus.APPLIED, applied_at=now, latency_ms=10.0, changes=[], plausibility_score=1.0)],
    )

    assert report.dimensions["semantic_intent"].novel_count == 1
    assert report.dimensions["semantic_intent"].novel_items == ["LATERAL_SMB_ENUM"]
    assert report.causal_attribution_rate == 50.0
    assert report.overall_yield_score > 0.0


def test_experiment_runner_and_ablation():
    # Statistical A/B testing
    ctrl = [10.0, 12.0, 11.0, 13.0, 10.5]
    treat = [45.0, 50.0, 48.0, 52.0, 47.0]
    res = ExperimentRunner.calculate_statistics(ctrl, treat, "Yield")
    assert res.statistically_significant
    assert res.cohens_d > 0.8

    # Ablation matrix
    ablation_runs = [
        AblationRunResult(config_name="FULL_ADAM", composite_yield_score=85.0, semantic_events_count=20, mutations_applied=4, causal_attribution_rate=75.0, deception_backfire_count=0),
        AblationRunResult(config_name="WITHOUT_DRL", composite_yield_score=60.0, semantic_events_count=12, mutations_applied=3, causal_attribution_rate=60.0, deception_backfire_count=1),
    ]
    eval_res = SubsystemAblationMatrixRunner.evaluate_ablation_results(ablation_runs)
    assert eval_res["baseline_score"] == 85.0
    assert eval_res["results"][1]["relative_performance_drop_pct"] > 25.0
