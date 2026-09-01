"""Unit tests for AI Synthetic Deception, C2 Interception & Threat Intelligence."""

import pytest
from adam.deception.synthetic.user_simulator import UserSimulator
from adam.deception.synthetic.decoys import SyntheticDecoyEngine
from adam.deception.synthetic.fingerprint import DynamicFingerprintEngine
from adam.deception.c2.sinkhole import C2Sinkhole, C2ProtocolType
from adam.deception.c2.tls_extractor import TLSSessionKeyExtractor
from adam.deception.c2.traffic_normalizer import TrafficNormalizer
from adam.reporting.intelligence import ThreatIntelligenceSynthesizer
from adam.reporting.metrics import MetricsCalculator


def test_user_simulator_bezier_curves():
    sim = UserSimulator(screen_width=1920, screen_height=1080, seed=42)
    traj = sim.generate_bezier_trajectory(start=(100, 100), end=(800, 600), duration_ms=500, steps=20)
    assert len(traj) == 21
    assert traj[0].x == 100
    assert traj[0].y == 100
    assert traj[-1].x == 800
    assert traj[-1].y == 600

    session_pts = sim.generate_random_user_session(duration_seconds=2)
    assert len(session_pts) > 10


def test_synthetic_decoys_tripwires():
    engine = SyntheticDecoyEngine(session_id="test_sess")
    # Canary file access
    alert = engine.record_file_access("C:\\Users\\Analyst\\.ssh\\id_rsa")
    assert alert is not None
    assert alert["type"] == "TRIPWIRE_CANARY_FILE_TOUCHED"
    assert "canary_token" in alert

    # Unknown file
    assert engine.record_file_access("C:\\Windows\\notepad.exe") is None


def test_dynamic_fingerprint_engine():
    engine = DynamicFingerprintEngine(seed=42)
    assert engine.get_cpuid_leaf_0x1_ecx() & (1 << 31) == 0  # Hypervisor bit cleared

    smbios = engine.get_smbios_tables()
    assert "SystemManufacturer" in smbios
    assert int(smbios["NumberOfCores"]) >= 4


def test_c2_sinkhole_and_emulation():
    sinkhole = C2Sinkhole(sinkhole_ip="192.168.100.1")
    resolved_ip = sinkhole.resolve_dns_query("malicious-dga-domain.biz")
    assert resolved_ip == "192.168.100.1"

    # Stage 1 response
    resp1 = sinkhole.handle_http_beacon(
        client_ip="192.168.100.50",
        target_domain="malicious-dga-domain.biz",
        path="/api/v1/ping",
        headers={},
        body=b"STAGE1_CHECKIN",
    )
    assert resp1.status_code == 200
    assert resp1.task_type == "WHOAMI"

    # Stage 2 response (Cobalt Strike emulation)
    resp2 = sinkhole.handle_http_beacon(
        client_ip="192.168.100.50",
        target_domain="malicious-dga-domain.biz",
        path="/api/v1/update",
        headers={},
        body=b"SYSINFO_REPORT",
    )
    assert resp2.protocol == C2ProtocolType.COBALT_STRIKE
    assert resp2.task_type == "DOWNLOAD_EXEC"


def test_tls_extractor_and_traffic_normalizer():
    extractor = TLSSessionKeyExtractor()
    dummy_mem = b"A" * 64
    keys = extractor.extract_tls_keys_from_memory(pid=2000, raw_process_memory=dummy_mem)
    assert len(keys) == 1
    client_rnd = keys[0].client_random

    decrypted = extractor.decrypt_payload_stream(
        flow_id="flow_1",
        client_ip="10.0.0.5",
        server_ip="192.168.100.1",
        server_port=443,
        sni_hostname="c2.evil.com",
        encrypted_stream=b"CIPHERTEXT_1234567890",
        client_random=client_rnd,
    )
    assert decrypted is not None
    assert b"DECRYPTED_C2_COMMAND" in decrypted.decrypted_content

    # Traffic Normalizer
    normalizer = TrafficNormalizer()
    for t in [1.0, 3.0, 5.0, 7.0, 9.0]:
        normalizer.record_packet("c2.evil.com", t)
    profile = normalizer.analyze_beaconing_pattern("c2.evil.com")
    assert profile is not None
    assert profile.mean_interval_s == 2.0
    assert profile.is_beaconing_detected is True


def test_threat_intelligence_and_metrics():
    synth = ThreatIntelligenceSynthesizer(session_id="session_intel_test")
    synth.record_artifact("C2_DOMAIN", "c2.stealth-actor.ru", confidence=0.95, description="Primary C2")
    synth.record_artifact("MUTEX", "Global\\EvilMtx123", confidence=0.9, description="Malware mutex")

    # Generate YARA rule
    yara = synth.generate_yara_rule("AgentTeslaVariant", payload_bytes=b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
    assert "rule ADAM_Evolved_AgentTeslaVariant" in yara
    assert "c2.stealth-actor.ru" in yara
    assert "$payload_hex" in yara

    # Export STIX 2.1
    stix_bundle = synth.export_stix21_bundle()
    assert stix_bundle["type"] == "bundle"
    assert len(stix_bundle["objects"]) >= 2

    # Metrics Calculator
    metrics = MetricsCalculator()
    metrics.record_sample_result(
        is_malicious=True,
        detected_as_malicious=True,
        detection_latency_ms=350.0,
        iocs_extracted=5,
        is_adversarial_variant=True,
    )
    metrics.record_sample_result(
        is_malicious=False,
        detected_as_malicious=False,
        detection_latency_ms=120.0,
        iocs_extracted=0,
    )
    report = metrics.generate_evaluation_report()
    assert report.total_samples == 2
    assert report.tpr == 1.0
    assert report.fpr == 0.0
    assert report.adversarial_generalization_rate == 1.0
