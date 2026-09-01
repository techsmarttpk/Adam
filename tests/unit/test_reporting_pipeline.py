import pytest
import os
from datetime import datetime, timezone
from adam.contracts.session import AnalysisSession, SampleMetadata, SessionConfig, SessionMetrics
from adam.contracts.enums import SessionStatus, DeceptionArm, NetworkMode, EventCategory, EventSource
from adam.contracts.raw_event import RawEvent, ProcessContext
from adam.contracts.semantic_event import SemanticEvent, AttckContext
from adam.contracts.policy_decision import PolicyDecision, PolicyVerdict
from adam.contracts.mutation import MutationResult, MutationStatus, MutationChange
from adam.reporting.model import ReportDataAggregator, ReportDataModel
from adam.reporting.pdf_generator import MalwareReportPDFGenerator


@pytest.fixture
def sample_analysis_session() -> AnalysisSession:
    return AnalysisSession(
        session_id="sess_test_malware_report_001",
        experiment_id="exp_ransomware_ablation_2026",
        arm=DeceptionArm.TREATMENT,
        sample=SampleMetadata(
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            filename="LockBit_Variant_7.exe",
            size_bytes=1048576,
            file_type="PE32 executable (GUI) Intel 80386, for MS Windows"
        ),
        config=SessionConfig(
            deception_enabled=True,
            policy_ruleset="rules/default",
            vm_profile="win10-x64-office",
            timeout_seconds=300,
            network_mode=NetworkMode.SIMULATED
        ),
        status=SessionStatus.COMPLETED,
        started_at=datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc),
        ended_at=datetime(2026, 9, 1, 12, 5, 30, tzinfo=timezone.utc),
        metrics=SessionMetrics(
            raw_events=150,
            semantic_events=8,
            decisions_evaluated=6,
            mutations_applied=2,
            semantic_events_post_mutation=5
        )
    )


@pytest.fixture
def synthetic_session_telemetry():
    now = datetime(2026, 9, 1, 12, 0, 10, tzinfo=timezone.utc)
    
    # 1. Raw Events
    raw_events = [
        RawEvent(
            event_id="raw_001",
            session_id="sess_test_malware_report_001",
            occurred_at=now,
            observed_at=now,
            source=EventSource.SYSMON,
            category=EventCategory.PROCESS,
            process=ProcessContext(pid=4088, image="LockBit_Variant_7.exe", command_line="LockBit_Variant_7.exe --stealth"),
            attributes={"operation": "ProcessCreate", "details": "Started main detonation process"}
        ),
        RawEvent(
            event_id="raw_002",
            session_id="sess_test_malware_report_001",
            occurred_at=datetime(2026, 9, 1, 12, 1, 0, tzinfo=timezone.utc),
            observed_at=datetime(2026, 9, 1, 12, 1, 0, tzinfo=timezone.utc),
            source=EventSource.WIRESHARK,
            category=EventCategory.NETWORK,
            process=ProcessContext(pid=4088, image="LockBit_Variant_7.exe"),
            attributes={"operation": "Connect", "dest_ip": "198.51.100.42", "dest_port": 443}
        )
    ]

    # 2. Semantic Events across multiple severity tiers
    semantic_events = [
        SemanticEvent(
            semantic_id="sem_001",
            session_id="sess_test_malware_report_001",
            correlation_id="corr_001",
            window_start=now,
            window_end=now,
            intent="RECON_ACTIVE_DIRECTORY",
            confidence=0.95,
            severity="HIGH",
            detector="ReconDetector",
            evidence=["nltest /dclist:CORP executed"],
            features={},
            attck=AttckContext(tactic="Discovery", technique="T1087")
        ),
        SemanticEvent(
            semantic_id="sem_002",
            session_id="sess_test_malware_report_001",
            correlation_id="corr_002",
            window_start=datetime(2026, 9, 1, 12, 1, 30, tzinfo=timezone.utc),
            window_end=datetime(2026, 9, 1, 12, 1, 30, tzinfo=timezone.utc),
            intent="EVADE_VM_HYPERVISOR_CHECK",
            confidence=0.98,
            severity="CRITICAL",
            detector="EvasionDetector",
            evidence=["SystemBiosVersion checked in registry"],
            features={},
            attck=AttckContext(tactic="Defense Evasion", technique="T1497")
        ),
        SemanticEvent(
            semantic_id="sem_003",
            session_id="sess_test_malware_report_001",
            correlation_id="corr_003",
            window_start=datetime(2026, 9, 1, 12, 2, 45, tzinfo=timezone.utc),
            window_end=datetime(2026, 9, 1, 12, 2, 45, tzinfo=timezone.utc),
            intent="LATERAL_SHARE_TRAVERSAL",
            confidence=0.88,
            severity="HIGH",
            detector="LateralDetector",
            evidence=["Accessing synthetic financial share"],
            features={},
            attck=AttckContext(tactic="Lateral Movement", technique="T1021"),
            caused_by_mutation="mut_001"
        )
    ]

    # 3. Policy Decisions
    decisions = [
        PolicyDecision(
            decision_id="dec_001",
            session_id="sess_test_malware_report_001",
            correlation_id="corr_001",
            triggered_by="sem_001",
            decided_at=now,
            rule_id="RULE-RECON-001",
            rule_version="1.0",
            action="SPAWN_FAKE_DC_ARTIFACTS",
            verdict=PolicyVerdict.EXECUTE,
            priority=100,
            parameters={},
            evaluation_ms=1.4,
            rationale="Active reconnaissance detected; deploy synthetic domain controllers"
        ),
        PolicyDecision(
            decision_id="dec_002",
            session_id="sess_test_malware_report_001",
            correlation_id="corr_002",
            triggered_by="sem_002",
            decided_at=datetime(2026, 9, 1, 12, 1, 30, tzinfo=timezone.utc),
            rule_id="RULE-EVADE-001",
            rule_version="1.0",
            action="SPOOF_HARDWARE_IDENTITY",
            verdict=PolicyVerdict.EXECUTE,
            priority=150,
            parameters={},
            evaluation_ms=2.1,
            rationale="Anti-VM evasion detected; spoof Dell workstation signatures"
        )
    ]

    # 4. Mutations
    mutations = [
        MutationResult(
            mutation_id="mut_001",
            session_id="sess_test_malware_report_001",
            correlation_id="corr_001",
            decision_id="dec_001",
            primitive="SPAWN_FAKE_DC_ARTIFACTS",
            status=MutationStatus.APPLIED,
            applied_at=now,
            latency_ms=14.2,
            plausibility_score=0.95,
            plausibility_notes="Registry and DNS mapped to synthetic DC",
            revertible=True,
            causal_window_ms=30000,
            changes=[
                MutationChange(kind="REGISTRY", target="HKLM\\System\\Tcpip\\Parameters\\Domain", operation="SET", value="CORP.LOCAL"),
                MutationChange(kind="NETWORK", target="dns:DC01.CORP.LOCAL", operation="RESPOND", value="10.0.0.10")
            ]
        ),
        MutationResult(
            mutation_id="mut_002",
            session_id="sess_test_malware_report_001",
            correlation_id="corr_002",
            decision_id="dec_002",
            primitive="SPOOF_HARDWARE_IDENTITY",
            status=MutationStatus.APPLIED,
            applied_at=datetime(2026, 9, 1, 12, 1, 31, tzinfo=timezone.utc),
            latency_ms=8.5,
            plausibility_score=0.92,
            plausibility_notes="Physical Dell workstation BIOS string spoofed",
            revertible=True,
            causal_window_ms=30000,
            changes=[
                MutationChange(kind="REGISTRY", target="HKLM\\HARDWARE\\DESCRIPTION\\System\\SystemBiosVersion", operation="SET", value="DELL - 1072009")
            ]
        )
    ]

    return raw_events, semantic_events, decisions, mutations


def test_report_data_aggregator_model_construction(sample_analysis_session, synthetic_session_telemetry):
    raw_events, semantic_events, decisions, mutations = synthetic_session_telemetry

    report: ReportDataModel = ReportDataAggregator.build(
        session=sample_analysis_session,
        raw_events=raw_events,
        semantic_events=semantic_events,
        decisions=decisions,
        mutations=mutations
    )

    # Validate Core KPIs
    assert report.session_id == sample_analysis_session.session_id
    assert report.kpis.total_raw_events == 2
    assert report.kpis.total_semantic_events == 3
    assert report.kpis.critical_events == 1
    assert report.kpis.high_events == 2
    assert report.kpis.total_mutations_applied == 2
    assert report.kpis.post_mutation_events == 1  # sem_003 was caused_by_mutation

    # Validate Threat Risk Assessment
    assert report.risk_score.level in ("CRITICAL", "HIGH")
    assert report.risk_score.score >= 50

    # Validate Severity Distribution
    assert report.severity_distribution.critical == 1
    assert report.severity_distribution.high == 2

    # Validate Categories & Matrix
    cats = {c.category for c in report.category_summaries}
    assert "Discovery" in cats or "Evasion" in cats
    # Either Discovery or Evasion should be in matrix
    assert any(cat in report.severity_category_matrix for cat in ("Discovery", "Evasion"))

    # Validate Timeline Milestones
    assert len(report.timeline) >= 4  # 1 Process + 2 Intents + 2 Mutations
    assert any(m.phase == "DECEPTION MUTATION" for m in report.timeline)

    # Validate Forensic IOCs
    assert len(report.iocs) >= 3
    assert any(ioc.ioc_type == "SHA-256" for ioc in report.iocs)
    assert any(ioc.is_decoy_lure for ioc in report.iocs)


def test_malware_report_pdf_vector_generation(sample_analysis_session, synthetic_session_telemetry):
    raw_events, semantic_events, decisions, mutations = synthetic_session_telemetry

    report: ReportDataModel = ReportDataAggregator.build(
        session=sample_analysis_session,
        raw_events=raw_events,
        semantic_events=semantic_events,
        decisions=decisions,
        mutations=mutations
    )

    pdf_bytes = MalwareReportPDFGenerator.generate_pdf(report)
    assert pdf_bytes is not None
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF")
