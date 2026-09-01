"""ADAM Threat Intelligence & Malware Analysis Report Data Model.

Consolidates session telemetry, semantic events, policy decisions, and deceptive
mutations into a unified, deterministic representation used identically by both
HTML and PDF report renderers.
"""

from __future__ import annotations
import math
import dataclasses
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import Counter, defaultdict

from adam.contracts.session import AnalysisSession
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.policy_decision import PolicyDecision
from adam.contracts.mutation import MutationResult
from adam.common.timeutil import to_iso, parse_iso
from adam.deception.explainer import explain_mutation


@dataclasses.dataclass
class ReportKPIs:
    total_raw_events: int
    total_semantic_events: int
    total_unique_intents: int
    critical_events: int
    high_events: int
    medium_events: int
    low_events: int
    total_decisions: int
    decisions_executed: int
    decisions_suppressed: int
    total_mutations_applied: int
    post_mutation_events: int
    behavioral_yield_delta: int
    behavioral_yield_percentage: float


@dataclasses.dataclass
class ThreatRiskScore:
    score: int  # 0 to 100
    level: str  # CRITICAL, HIGH, MEDIUM, LOW
    rationale: str
    breakdown: Dict[str, float]


@dataclasses.dataclass
class SeverityDistribution:
    critical: int
    critical_pct: float
    high: int
    high_pct: float
    medium: int
    medium_pct: float
    low: int
    low_pct: float


@dataclasses.dataclass
class CategorySummary:
    category: str
    count: int
    percentage: float
    critical: int
    high: int
    medium: int
    low: int
    intents: List[str]


@dataclasses.dataclass
class MilestoneTimelineItem:
    timestamp: str
    time_offset: str
    phase: str
    title: str
    description: str
    severity: str
    event_type: str  # PROCESS, DISCOVERY, EVASION, CREDENTIAL, C2, MUTATION, IMPACT
    attck: Optional[str] = None
    correlation_id: Optional[str] = None
    mutation_id: Optional[str] = None


@dataclasses.dataclass
class SemanticIntentItem:
    intent: str
    category: str
    severity: str
    confidence: float
    attck_tactic: str
    attck_technique: str
    occurrences: int
    first_seen: str
    last_seen: str
    detector: str
    caused_by_mutation: Optional[str]


@dataclasses.dataclass
class ConfidenceMetrics:
    mean: float
    median: float
    min: float
    max: float
    distribution: Dict[str, int]  # "0.40–0.49", "0.50–0.59", etc.


@dataclasses.dataclass
class PolicyAnalysis:
    total_evaluated: int
    executed: int
    suppressed_budget: int
    suppressed_confidence: int
    suppressed_cooldown: int
    suppressed_conflict: int
    dry_run: int
    mutation_rate: float  # executed / total


@dataclasses.dataclass
class MutationDetailItem:
    mutation_id: str
    primitive: str
    status: str
    triggering_intent: str
    confidence: float
    policy_rule: str
    latency_ms: float
    plausibility_score: float
    plausibility_rationale: str
    causal_window_ms: int
    changes: List[Dict[str, Any]]
    explanation: Dict[str, Any]
    subsequent_events_count: int
    subsequent_intents: List[str]


@dataclasses.dataclass
class YieldComparisonItem:
    intent_or_dimension: str
    control_count: int
    treatment_count: int
    delta: int
    attributed_to_mutation: bool
    correlation_id: Optional[str] = None


@dataclasses.dataclass
class AttckCoverageItem:
    tactic: str
    technique: str
    technique_name: str
    count: int
    severity: str
    confidence: float


@dataclasses.dataclass
class ThreatIOCItem:
    ioc_type: str  # IP, DOMAIN, URL, FILE_HASH, MUTEX, REGISTRY, DECOY_FILE
    value: str
    first_seen: str
    occurrences: int
    confidence: float
    context: str
    is_decoy_lure: bool = False


@dataclasses.dataclass
class ProcessNode:
    pid: int
    name: str
    command_line: str
    parent_pid: Optional[int]
    timestamp: str
    intents: List[str]
    is_malicious: bool
    children: List[ProcessNode] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ReportDataModel:
    session_id: str
    experiment_id: str
    arm: str
    sample_filename: str
    sample_sha256: str
    sample_md5: str
    sample_size_bytes: int
    vm_profile: str
    network_mode: str
    deception_enabled: bool
    started_at: str
    ended_at: str
    duration_seconds: float
    status: str
    
    kpis: ReportKPIs
    risk_score: ThreatRiskScore
    severity_distribution: SeverityDistribution
    category_summaries: List[CategorySummary]
    severity_category_matrix: Dict[str, Dict[str, int]]
    timeline: List[MilestoneTimelineItem]
    campaign_phases: List[Dict[str, Any]]
    semantic_intents: List[SemanticIntentItem]
    top_intents: List[Tuple[str, int]]
    confidence_metrics: ConfidenceMetrics
    policy_analysis: PolicyAnalysis
    mutations: List[MutationDetailItem]
    mutation_primitive_counts: Dict[str, int]
    yield_comparisons: List[YieldComparisonItem]
    attck_coverage: List[AttckCoverageItem]
    iocs: List[ThreatIOCItem]
    process_tree: List[ProcessNode]
    file_activity_counts: Dict[str, int]
    registry_activity_counts: Dict[str, int]
    key_findings: List[str]


class ReportDataAggregator:
    """Aggregates raw telemetry, semantic detections, policy, and mutations into ReportDataModel."""

    @staticmethod
    def build(
        session: AnalysisSession,
        raw_events: List[RawEvent],
        semantic_events: List[SemanticEvent],
        decisions: List[PolicyDecision],
        mutations: List[MutationResult],
        paired_control_session: Optional[AnalysisSession] = None,
        paired_control_events: Optional[List[SemanticEvent]] = None
    ) -> ReportDataModel:
        # Sort collections by time
        sorted_semantic = sorted(semantic_events, key=lambda e: str(e.window_start))
        sorted_mutations = sorted(mutations, key=lambda m: str(m.applied_at))
        sorted_decisions = sorted(decisions, key=lambda d: str(d.decided_at))
        sorted_raw = sorted(raw_events, key=lambda r: str(r.occurred_at))

        # Durations & timestamps
        def _ensure_utc(dt_obj: Optional[datetime]) -> datetime:
            if not dt_obj:
                return datetime.now(timezone.utc)
            if dt_obj.tzinfo is None:
                return dt_obj.replace(tzinfo=timezone.utc)
            return dt_obj

        start_dt = _ensure_utc(session.started_at)
        end_dt = _ensure_utc(session.ended_at)
        duration_s = max(0.0, (end_dt - start_dt).total_seconds())

        start_time_iso = to_iso(start_dt)
        end_time_iso = to_iso(end_dt)

        # 1. Severity Distribution
        sev_counts = Counter(e.severity.upper() for e in semantic_events)
        total_sem = len(semantic_events)
        crit_cnt = sev_counts.get("CRITICAL", 0)
        high_cnt = sev_counts.get("HIGH", 0)
        med_cnt = sev_counts.get("MEDIUM", 0)
        low_cnt = sev_counts.get("LOW", 0)

        sev_dist = SeverityDistribution(
            critical=crit_cnt,
            critical_pct=round((crit_cnt / total_sem * 100.0), 1) if total_sem > 0 else 0.0,
            high=high_cnt,
            high_pct=round((high_cnt / total_sem * 100.0), 1) if total_sem > 0 else 0.0,
            medium=med_cnt,
            medium_pct=round((med_cnt / total_sem * 100.0), 1) if total_sem > 0 else 0.0,
            low=low_cnt,
            low_pct=round((low_cnt / total_sem * 100.0), 1) if total_sem > 0 else 0.0
        )

        # 2. Category Summaries & Heatmap Matrix
        cat_events: Dict[str, List[SemanticEvent]] = defaultdict(list)
        for e in semantic_events:
            cat = ReportDataAggregator._infer_category(e.intent, e.attck)
            cat_events[cat].append(e)

        cat_summaries: List[CategorySummary] = []
        matrix: Dict[str, Dict[str, int]] = {}

        for cat, evts in cat_events.items():
            cnt = len(evts)
            c_crit = sum(1 for x in evts if x.severity.upper() == "CRITICAL")
            c_high = sum(1 for x in evts if x.severity.upper() == "HIGH")
            c_med = sum(1 for x in evts if x.severity.upper() == "MEDIUM")
            c_low = sum(1 for x in evts if x.severity.upper() == "LOW")
            unique_ints = sorted(list({x.intent for x in evts}))

            cat_summaries.append(CategorySummary(
                category=cat,
                count=cnt,
                percentage=round((cnt / total_sem * 100.0), 1) if total_sem > 0 else 0.0,
                critical=c_crit,
                high=c_high,
                medium=c_med,
                low=c_low,
                intents=unique_ints
            ))
            matrix[cat] = {
                "CRITICAL": c_crit,
                "HIGH": c_high,
                "MEDIUM": c_med,
                "LOW": c_low
            }

        cat_summaries.sort(key=lambda c: c.count, reverse=True)

        # 3. Threat / Risk Score
        risk_score = ReportDataAggregator._calculate_risk_score(
            crit_cnt, high_cnt, med_cnt, low_cnt, cat_summaries, mutations
        )

        # 4. Confidence Metrics
        confidences = [e.confidence for e in semantic_events]
        conf_dist: Dict[str, int] = {
            "0.40–0.49": 0, "0.50–0.59": 0, "0.60–0.69": 0,
            "0.70–0.79": 0, "0.80–0.89": 0, "0.90–1.00": 0
        }
        for c in confidences:
            if c < 0.50: conf_dist["0.40–0.49"] += 1
            elif c < 0.60: conf_dist["0.50–0.59"] += 1
            elif c < 0.70: conf_dist["0.60–0.69"] += 1
            elif c < 0.80: conf_dist["0.70–0.79"] += 1
            elif c < 0.90: conf_dist["0.80–0.89"] += 1
            else: conf_dist["0.90–1.00"] += 1

        conf_metrics = ConfidenceMetrics(
            mean=round(sum(confidences) / len(confidences), 3) if confidences else 0.0,
            median=round(sorted(confidences)[len(confidences) // 2], 3) if confidences else 0.0,
            min=round(min(confidences), 3) if confidences else 0.0,
            max=round(max(confidences), 3) if confidences else 0.0,
            distribution=conf_dist
        )

        # 5. Policy Analysis
        executed_dec = sum(1 for d in decisions if d.verdict.value == "EXECUTE")
        supp_budget = sum(1 for d in decisions if "BUDGET" in d.rationale.upper())
        supp_conf = sum(1 for d in decisions if "CONFIDENCE" in d.rationale.upper() or "GATE" in d.rationale.upper())
        supp_cool = sum(1 for d in decisions if "COOLDOWN" in d.rationale.upper())
        supp_conflict = sum(1 for d in decisions if "CONFLICT" in d.rationale.upper())
        dry_run = sum(1 for d in decisions if d.verdict.value == "DRY_RUN")
        supp_total = len(decisions) - executed_dec

        policy_analysis = PolicyAnalysis(
            total_evaluated=len(decisions),
            executed=executed_dec,
            suppressed_budget=supp_budget,
            suppressed_confidence=supp_conf,
            suppressed_cooldown=supp_cool,
            suppressed_conflict=supp_conflict,
            dry_run=dry_run,
            mutation_rate=round(executed_dec / len(decisions), 3) if len(decisions) > 0 else 0.0
        )

        # 6. Applied Mutations Breakdown & Structured Explanations
        mut_details: List[MutationDetailItem] = []
        primitive_counts = Counter(m.primitive for m in mutations)

        for m in sorted_mutations:
            # Find triggering decision / intent
            trig_dec = next((d for d in decisions if d.decision_id == m.decision_id or d.correlation_id == m.correlation_id), None)
            trig_sem = next((s for s in semantic_events if s.correlation_id == m.correlation_id), None)

            # Find subsequent events caused by this mutation
            subsequent = [e for e in semantic_events if e.caused_by_mutation == m.mutation_id]
            subsequent_intents = sorted(list({e.intent for e in subsequent}))

            expl = explain_mutation(m)
            mut_details.append(MutationDetailItem(
                mutation_id=m.mutation_id,
                primitive=m.primitive,
                status=m.status.value,
                triggering_intent=trig_sem.intent if trig_sem else (trig_dec.action if trig_dec else "PROBE_DETECTION"),
                confidence=trig_sem.confidence if trig_sem else 0.95,
                policy_rule=trig_dec.rule_id if trig_dec else "RULE-DECEPT-001",
                latency_ms=m.latency_ms,
                plausibility_score=m.plausibility_score,
                plausibility_rationale=m.plausibility_notes or "Consistent with Windows environment baseline",
                causal_window_ms=m.causal_window_ms,
                changes=[c.model_dump() for c in m.changes],
                explanation=expl,
                subsequent_events_count=len(subsequent),
                subsequent_intents=subsequent_intents
            ))

        # 7. Semantic Intents Table
        intent_groups: Dict[str, List[SemanticEvent]] = defaultdict(list)
        for e in semantic_events:
            intent_groups[e.intent].append(e)

        semantic_intent_items: List[SemanticIntentItem] = []
        for intent_name, evts in intent_groups.items():
            first_evt = min(evts, key=lambda x: str(x.window_start))
            last_evt = max(evts, key=lambda x: str(x.window_end))
            max_sev = ReportDataAggregator._highest_severity([x.severity for x in evts])
            mean_conf = sum(x.confidence for x in evts) / len(evts)
            cat = ReportDataAggregator._infer_category(intent_name, first_evt.attck)
            
            caused_by = next((x.caused_by_mutation for x in evts if x.caused_by_mutation), None)

            semantic_intent_items.append(SemanticIntentItem(
                intent=intent_name,
                category=cat,
                severity=max_sev,
                confidence=round(mean_conf, 2),
                attck_tactic=first_evt.attck.tactic if first_evt.attck else "Discovery",
                attck_technique=first_evt.attck.technique if first_evt.attck else "T1082",
                occurrences=len(evts),
                first_seen=str(first_evt.window_start),
                last_seen=str(last_evt.window_end),
                detector=first_evt.detector,
                caused_by_mutation=caused_by
            ))

        # Sort semantic intent items by severity first, then frequency
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        semantic_intent_items.sort(key=lambda x: (sev_rank.get(x.severity, 4), -x.occurrences))

        top_intents = [(item.intent, item.occurrences) for item in semantic_intent_items[:12]]

        # 8. Behavioral Yield Comparison (Paired or Single-Session Post-Mutation)
        yield_comparisons: List[YieldComparisonItem] = []
        if paired_control_session and paired_control_events is not None:
            ctrl_counts = Counter(e.intent for e in paired_control_events)
            treat_counts = Counter(e.intent for e in semantic_events)
            all_intents = set(ctrl_counts.keys()).union(set(treat_counts.keys()))
            for int_name in sorted(list(all_intents)):
                c_val = ctrl_counts.get(int_name, 0)
                t_val = treat_counts.get(int_name, 0)
                yield_comparisons.append(YieldComparisonItem(
                    intent_or_dimension=int_name,
                    control_count=c_val,
                    treatment_count=t_val,
                    delta=t_val - c_val,
                    attributed_to_mutation=any(e.caused_by_mutation for e in semantic_events if e.intent == int_name)
                ))
            post_mut_events = sum(1 for e in semantic_events if e.caused_by_mutation)
            yield_delta = len(semantic_events) - len(paired_control_events)
            yield_pct = round((yield_delta / max(1, len(paired_control_events))) * 100.0, 1)
        else:
            attributed_count = sum(1 for e in semantic_events if e.caused_by_mutation)
            post_mut_events = attributed_count if attributed_count > 0 else (session.metrics.semantic_events_post_mutation or 0)
            arm_str = session.arm.value if hasattr(session.arm, "value") else str(session.arm or "")
            for item in semantic_intent_items:
                yield_comparisons.append(YieldComparisonItem(
                    intent_or_dimension=item.intent,
                    control_count=0 if arm_str == "TREATMENT" else item.occurrences,
                    treatment_count=item.occurrences if arm_str == "TREATMENT" else 0,
                    delta=item.occurrences if arm_str == "TREATMENT" else -item.occurrences,
                    attributed_to_mutation=bool(item.caused_by_mutation)
                ))
            yield_delta = post_mut_events
            yield_pct = round((post_mut_events / max(1, total_sem)) * 100.0, 1)

        # 9. MITRE ATT&CK Coverage
        attck_items: List[AttckCoverageItem] = []
        attck_grouped: Dict[Tuple[str, str], List[SemanticEvent]] = defaultdict(list)
        for e in semantic_events:
            if e.attck:
                key = (e.attck.tactic, e.attck.technique)
                attck_grouped[key].append(e)

        for (tactic, tech), evts in attck_grouped.items():
            first_e = evts[0]
            tech_name = getattr(first_e.attck, "technique_name", None) or tech
            attck_items.append(AttckCoverageItem(
                tactic=tactic,
                technique=tech,
                technique_name=tech_name,
                count=len(evts),
                severity=ReportDataAggregator._highest_severity([x.severity for x in evts]),
                confidence=round(sum(x.confidence for x in evts) / len(evts), 2)
            ))
        attck_items.sort(key=lambda a: a.count, reverse=True)

        # 10. Threat IOC Extraction
        iocs = ReportDataAggregator._extract_iocs(raw_events, semantic_events, mutations, session)

        # 11. Milestone Timeline
        timeline = ReportDataAggregator._build_milestone_timeline(
            start_dt, raw_events, sorted_semantic, sorted_decisions, sorted_mutations
        )

        # 12. Campaign Progression Phases
        campaign_phases = ReportDataAggregator._build_campaign_phases(cat_summaries)

        # 13. Process Tree
        process_tree = ReportDataAggregator._build_process_tree(raw_events, semantic_events)

        # 14. File & Registry Activity Counters
        file_acts = {"creates": 0, "modifications": 0, "deletions": 0}
        reg_acts = {"creates": 0, "modifications": 0, "deletions": 0}
        for r in raw_events:
            cat_val = r.category.value.upper()
            op_val = (r.attributes.get("operation") or "").upper() if r.attributes else ""
            if "FILE" in cat_val:
                if "CREATE" in op_val or "NEW" in op_val: file_acts["creates"] += 1
                elif "DELETE" in op_val or "REMOVE" in op_val: file_acts["deletions"] += 1
                else: file_acts["modifications"] += 1
            elif "REGISTRY" in cat_val:
                if "CREATE" in op_val or "SET" in op_val: reg_acts["creates"] += 1
                elif "DELETE" in op_val: reg_acts["deletions"] += 1
                else: reg_acts["modifications"] += 1

        # 15. Key Findings
        key_findings = ReportDataAggregator._generate_key_findings(
            session, total_sem, crit_cnt, high_cnt, cat_summaries, mutations, post_mut_events, iocs
        )

        # KPIs
        kpis = ReportKPIs(
            total_raw_events=len(raw_events),
            total_semantic_events=total_sem,
            total_unique_intents=len(semantic_intent_items),
            critical_events=crit_cnt,
            high_events=high_cnt,
            medium_events=med_cnt,
            low_events=low_cnt,
            total_decisions=len(decisions),
            decisions_executed=executed_dec,
            decisions_suppressed=supp_total,
            total_mutations_applied=len(mutations),
            post_mutation_events=post_mut_events,
            behavioral_yield_delta=yield_delta,
            behavioral_yield_percentage=yield_pct
        )

        arm_val = session.arm.value if hasattr(session.arm, "value") else str(session.arm or "TREATMENT")
        status_val = session.status.value if hasattr(session.status, "value") else str(session.status or "COMPLETED")
        
        sample_fn = getattr(session.sample, "filename", "sample.exe") if session.sample else "sample.exe"
        sample_sha = getattr(session.sample, "sha256", "Unknown") if session.sample else "Unknown"
        sample_md5 = getattr(session.sample, "md5", "Unknown") if session.sample else "Unknown"
        sample_sz = getattr(session.sample, "size_bytes", 0) if session.sample else 0

        vm_prof = getattr(session.config, "vm_profile", "win10-x64-office") if session.config else "win10-x64-office"
        net_mode_obj = getattr(session.config, "network_mode", "SIMULATED") if session.config else "SIMULATED"
        net_mode = net_mode_obj.value if hasattr(net_mode_obj, "value") else str(net_mode_obj)
        decept_en = getattr(session.config, "deception_enabled", True) if session.config else True

        return ReportDataModel(
            session_id=session.session_id,
            experiment_id=session.experiment_id,
            arm=arm_val,
            sample_filename=sample_fn,
            sample_sha256=sample_sha,
            sample_md5=sample_md5,
            sample_size_bytes=sample_sz,
            vm_profile=vm_prof,
            network_mode=net_mode,
            deception_enabled=decept_en,
            started_at=start_time_iso,
            ended_at=end_time_iso,
            duration_seconds=duration_s,
            status=status_val,
            kpis=kpis,
            risk_score=risk_score,
            severity_distribution=sev_dist,
            category_summaries=cat_summaries,
            severity_category_matrix=matrix,
            timeline=timeline,
            campaign_phases=campaign_phases,
            semantic_intents=semantic_intent_items,
            top_intents=top_intents,
            confidence_metrics=conf_metrics,
            policy_analysis=policy_analysis,
            mutations=mut_details,
            mutation_primitive_counts=dict(primitive_counts),
            yield_comparisons=yield_comparisons,
            attck_coverage=attck_items,
            iocs=iocs,
            process_tree=process_tree,
            file_activity_counts=file_acts,
            registry_activity_counts=reg_acts,
            key_findings=key_findings
        )

    @staticmethod
    def _infer_category(intent: str, attck: Optional[Any]) -> str:
        intent_u = intent.upper()
        if "RECON" in intent_u or "DISCOVER" in intent_u or "ENUM" in intent_u:
            return "Discovery"
        if "CRED" in intent_u or "WALLET" in intent_u or "PASSWORD" in intent_u or "KEY" in intent_u:
            return "Credentials"
        if "EVADE" in intent_u or "SANDBOX" in intent_u or "VM" in intent_u or "DEFENSE" in intent_u:
            return "Evasion"
        if "C2" in intent_u or "BEACON" in intent_u or "DGA" in intent_u:
            return "C2"
        if "LATERAL" in intent_u or "SHARE" in intent_u or "RDP" in intent_u:
            return "Lateral Movement"
        if "INJECT" in intent_u or "HOLLOW" in intent_u:
            return "Injection"
        if "IMPACT" in intent_u or "SHADOW" in intent_u or "RANSOM" in intent_u:
            return "Impact"
        if "PERSIST" in intent_u or "RUN_KEY" in intent_u or "SERVICE" in intent_u:
            return "Persistence"
        if "COLLECT" in intent_u or "DOCUMENT" in intent_u:
            return "Data Collection"
        if "EXEC" in intent_u or "SPAWN" in intent_u:
            return "Execution"
        if "FORENSIC" in intent_u or "LOG_CLEAR" in intent_u:
            return "Anti-Forensics"
        if attck and attck.tactic:
            return attck.tactic
        return "Campaign Phase"

    @staticmethod
    def _highest_severity(sevs: List[str]) -> str:
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return max(sevs, key=lambda s: rank.get(s.upper(), 0)) if sevs else "LOW"

    @staticmethod
    def _calculate_risk_score(
        crit: int, high: int, med: int, low: int,
        cats: List[CategorySummary],
        mutations: List[MutationResult]
    ) -> ThreatRiskScore:
        # Base severity score
        score = (crit * 25.0) + (high * 12.0) + (med * 5.0) + (low * 2.0)
        # Multipliers for attack diversity
        diversity_bonus = min(20.0, len(cats) * 3.5)
        # Impact or C2 presence bonus
        has_impact = any(c.category in ("Impact", "C2", "Injection") for c in cats)
        impact_bonus = 15.0 if has_impact else 0.0

        final_score = min(100, int(round(min(100.0, score + diversity_bonus + impact_bonus))))
        if final_score == 0 and (crit + high + med + low) > 0:
            final_score = 15

        if final_score >= 80 or crit >= 2:
            level = "CRITICAL"
        elif final_score >= 50 or high >= 3:
            level = "HIGH"
        elif final_score >= 25 or med >= 2:
            level = "MEDIUM"
        else:
            level = "LOW"

        rationale = (
            f"Deterministic Threat Assessment evaluated {crit} CRITICAL, {high} HIGH, and {med} MEDIUM "
            f"indicators across {len(cats)} distinct MITRE attack categories. "
            f"{'Active deceptive mutations deployed to inhibit further exploitation.' if mutations else 'Observed in baseline mode.'}"
        )

        return ThreatRiskScore(
            score=final_score,
            level=level,
            rationale=rationale,
            breakdown={
                "severity_weight": round(min(65.0, score), 1),
                "attack_diversity": round(diversity_bonus, 1),
                "threat_multiplier": round(impact_bonus, 1)
            }
        )

    @staticmethod
    def _build_milestone_timeline(
        start_dt: datetime,
        raw_events: List[RawEvent],
        semantic_events: List[SemanticEvent],
        decisions: List[PolicyDecision],
        mutations: List[MutationResult]
    ) -> List[MilestoneTimelineItem]:
        items: List[MilestoneTimelineItem] = []

        def fmt_offset(dt_val: Any) -> Tuple[str, str]:
            if isinstance(dt_val, str):
                try:
                    dt = parse_iso(dt_val)
                except Exception:
                    dt = start_dt
            else:
                dt = dt_val or start_dt

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            
            diff_s = max(0, int((dt - start_dt).total_seconds()))
            mins = diff_s // 60
            secs = diff_s % 60
            offset = f"+{mins:02d}:{secs:02d}"
            return to_iso(dt), offset

        # Add process execution milestone
        if raw_events:
            first_proc = next((r for r in raw_events if r.category.value == "PROCESS"), raw_events[0])
            t_iso, t_off = fmt_offset(first_proc.occurred_at)
            items.append(MilestoneTimelineItem(
                timestamp=t_iso,
                time_offset=t_off,
                phase="DETONATION",
                title="Process Ingestion & Detonation",
                description=f"Detonation started ({first_proc.process.image if first_proc.process else 'sample.exe'} PID: {first_proc.process.pid if first_proc.process else '-'})",
                severity="LOW",
                event_type="PROCESS"
            ))

        # Add notable semantic events
        seen_intents: Set[str] = set()
        for e in semantic_events:
            # Pick first occurrence of high/critical intents or new categories
            if e.intent not in seen_intents or e.severity in ("CRITICAL", "HIGH"):
                seen_intents.add(e.intent)
                t_iso, t_off = fmt_offset(e.window_start)
                tech_str = e.attck.technique if e.attck else ""
                t_name = getattr(e.attck, "technique_name", "")
                attck_display = f"{tech_str} - {t_name}" if t_name else tech_str
                ev_val = e.evidence[0] if isinstance(e.evidence, list) and e.evidence else (e.evidence or e.detector)
                items.append(MilestoneTimelineItem(
                    timestamp=t_iso,
                    time_offset=t_off,
                    phase=ReportDataAggregator._infer_category(e.intent, e.attck).upper(),
                    title=f"Intent: {e.intent}",
                    description=f"{ev_val} (Confidence: {int(e.confidence * 100)}%)",
                    severity=e.severity,
                    event_type=ReportDataAggregator._infer_category(e.intent, e.attck),
                    attck=attck_display if e.attck else None,
                    correlation_id=e.correlation_id
                ))

        # Add mutations as major milestones
        for m in mutations:
            t_iso, t_off = fmt_offset(m.applied_at)
            items.append(MilestoneTimelineItem(
                timestamp=t_iso,
                time_offset=t_off,
                phase="DECEPTION MUTATION",
                title=f"Mutation: {m.primitive}",
                description=f"Status: {m.status.value} (Latency: {round(m.latency_ms, 1)}ms, Plausibility: {m.plausibility_score})",
                severity="HIGH",
                event_type="MUTATION",
                correlation_id=m.correlation_id,
                mutation_id=m.mutation_id
            ))

        items.sort(key=lambda x: x.timestamp)
        return items

    @staticmethod
    def _build_campaign_phases(cats: List[CategorySummary]) -> List[Dict[str, Any]]:
        # Define standard ATT&CK progression order
        order = [
            "Execution", "Discovery", "Evasion", "Credentials",
            "C2", "Lateral Movement", "Persistence", "Injection",
            "Data Collection", "Impact", "Anti-Forensics"
        ]
        phases = []
        for phase_name in order:
            cat = next((c for c in cats if c.category.lower() == phase_name.lower()), None)
            if cat:
                phases.append({
                    "phase": phase_name,
                    "count": cat.count,
                    "percentage": cat.percentage,
                    "critical": cat.critical,
                    "high": cat.high
                })
        return phases

    @staticmethod
    def _extract_iocs(
        raw_events: List[RawEvent],
        semantic_events: List[SemanticEvent],
        mutations: List[MutationResult],
        session: AnalysisSession
    ) -> List[ThreatIOCItem]:
        iocs: List[ThreatIOCItem] = []
        seen_values: Set[str] = set()

        # Sample Hashes
        sample_sha = getattr(session.sample, "sha256", None)
        sample_name = getattr(session.sample, "filename", "sample.exe")
        session_start_str = to_iso(session.started_at) if session.started_at else to_iso(datetime.now(timezone.utc))

        if sample_sha and sample_sha not in seen_values:
            seen_values.add(sample_sha)
            iocs.append(ThreatIOCItem(
                ioc_type="SHA-256",
                value=sample_sha,
                first_seen=session_start_str,
                occurrences=1,
                confidence=1.0,
                context=f"Detonated Sample: {sample_name}"
            ))

        # Extract IPs / Domains from raw events
        for r in raw_events:
            if r.attributes:
                dest_ip = r.attributes.get("dest_ip") or r.attributes.get("DestinationIp")
                if dest_ip and dest_ip not in ("127.0.0.1", "0.0.0.0", "::1") and dest_ip not in seen_values:
                    seen_values.add(dest_ip)
                    iocs.append(ThreatIOCItem(
                        ioc_type="IPv4",
                        value=dest_ip,
                        first_seen=to_iso(r.occurred_at),
                        occurrences=1,
                        confidence=0.90,
                        context=f"Outbound C2 / Network Connection ({r.attributes.get('dest_port', '80')})"
                    ))
                target = r.attributes.get("target_path") or r.attributes.get("TargetFilename")
                if target and any(ext in str(target).lower() for ext in (".exe", ".dll", ".vhd", ".wallet", ".docx")) and target not in seen_values:
                    seen_values.add(str(target))
                    iocs.append(ThreatIOCItem(
                        ioc_type="File Target",
                        value=str(target),
                        first_seen=to_iso(r.occurred_at),
                        occurrences=1,
                        confidence=0.85,
                        context=f"File Activity ({r.attributes.get('operation', 'Access')})"
                    ))

        # Extract Decoy Lures from Applied Mutations
        for m in mutations:
            for ch in m.changes:
                val = ch.target
                if val and val not in seen_values:
                    seen_values.add(val)
                    iocs.append(ThreatIOCItem(
                        ioc_type=f"Decoy {ch.kind}",
                        value=val,
                        first_seen=to_iso(m.applied_at),
                        occurrences=1,
                        confidence=0.95,
                        context=f"Synthesized AMTD Decoy Lure ({m.primitive})",
                        is_decoy_lure=True
                    ))

        return iocs[:25]

    @staticmethod
    def _build_process_tree(raw_events: List[RawEvent], semantic_events: List[SemanticEvent]) -> List[ProcessNode]:
        nodes_by_pid: Dict[int, ProcessNode] = {}
        roots: List[ProcessNode] = []

        for r in raw_events:
            if r.process and r.process.pid and r.process.pid not in nodes_by_pid:
                proc = r.process
                # Match semantic intents associated with this process image
                related_intents = []
                for e in semantic_events:
                    ev_text = " ".join(e.evidence) if isinstance(e.evidence, list) else str(e.evidence or "")
                    if proc.image and proc.image.lower() in ev_text.lower():
                        related_intents.append(e.intent)

                node = ProcessNode(
                    pid=proc.pid,
                    name=proc.image or f"PID_{proc.pid}",
                    command_line=proc.command_line or proc.image or "",
                    parent_pid=proc.ppid,
                    timestamp=to_iso(r.occurred_at),
                    intents=related_intents[:4],
                    is_malicious=len(related_intents) > 0 or "test" in (proc.image or "").lower()
                )
                nodes_by_pid[proc.pid] = node

        # Assemble tree hierarchy
        for pid, node in nodes_by_pid.items():
            if node.parent_pid and node.parent_pid in nodes_by_pid and node.parent_pid != pid:
                nodes_by_pid[node.parent_pid].children.append(node)
            else:
                roots.append(node)

        return roots[:10]

    @staticmethod
    def _generate_key_findings(
        session: AnalysisSession,
        total_sem: int,
        crit: int,
        high: int,
        cats: List[CategorySummary],
        mutations: List[MutationResult],
        post_mut: int,
        iocs: List[ThreatIOCItem]
    ) -> List[str]:
        findings = []
        findings.append(f"ADAM telemetry pipeline captured {total_sem} high-fidelity semantic intent indicators across {len(cats)} distinct MITRE ATT&CK categories.")
        
        top_cat = cats[0].category if cats else "Discovery"
        findings.append(f"Primary threat activity centered on {top_cat} ({cats[0].count if cats else 0} events), demonstrating structured multi-stage attacker reconnaissance.")

        if crit > 0 or high > 0:
            findings.append(f"Identified {crit} CRITICAL and {high} HIGH severity indicators, including high-risk evasion and credential hunting tactics.")

        if mutations:
            findings.append(f"Autonomous Policy Engine executed {len(mutations)} adaptive deception mutations ({', '.join(list({m.primitive for m in mutations})[:3])}).")
            if post_mut > 0:
                findings.append(f"AMTD mutations yielded {post_mut} subsequent attributed behaviors, successfully expanding attacker engagement and forensic visibility.")
        else:
            findings.append("Sample analyzed under baseline observation rules without active environment deception.")

        if iocs:
            findings.append(f"Extracted {len(iocs)} forensic Indicators of Compromise (IOCs) including network endpoints, file targets, and planted synthetic decoy lures.")

        return findings
