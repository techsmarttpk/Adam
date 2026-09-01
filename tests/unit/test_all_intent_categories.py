import pytest
import asyncio
from datetime import datetime, timezone
from adam.contracts.enums import EventCategory, EventSource, PolicyVerdict, MutationStatus
from adam.contracts.raw_event import RawEvent, ProcessContext
from adam.contracts.semantic_event import SemanticEvent
from adam.fusion.correlate import EventCorrelator
from adam.fusion.engine import FusionEngine
from adam.policy.engine import PolicyEngine
from adam.common.config import PolicySettings, FusionSettings, BusSettings
from adam.common.bus import EventBus
from adam.fusion.detectors import (
    recon, credentials, execution, persistence, evasion,
    injection, payload, c2, lateral, collection,
    impact, anti_forensics, config_search, campaign
)

@pytest.fixture
def correlator():
    return EventCorrelator(window_seconds=10.0)

def test_all_14_categories_detectors(correlator):
    now = datetime.now(timezone.utc)
    
    # 1. Discovery
    raw_os = RawEvent(
        event_id="raw_os_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=101, command_line="winver"), attributes={}
    )
    events = recon.detect_extended_recon(correlator, raw_os)
    assert len(events) >= 1
    assert events[0].intent == "RECON_OS_VERSION"
    assert events[0].features.get("phase") == "DISCOVERY"

    # 2. Credential Access
    raw_cloud = RawEvent(
        event_id="raw_cloud_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\Users\\user\\.aws\\credentials"}
    )
    events = credentials.detect_extended_credentials(correlator, raw_cloud)
    assert len(events) >= 1
    assert events[0].intent == "CRED_CLOUD_CREDENTIAL_SEARCH"
    assert events[0].severity == "CRITICAL"

    # 3. Execution
    raw_msbuild = RawEvent(
        event_id="raw_msb_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=102, image="C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe", command_line="msbuild.exe payload.xml"), attributes={}
    )
    events = execution.detect_execution_interpreter(correlator, raw_msbuild)
    assert len(events) >= 1
    assert events[0].intent == "EXEC_MSBUILD"

    # 4. Persistence
    raw_sideload = RawEvent(
        event_id="raw_side_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\Program Files\\App\\version.dll"}
    )
    events = persistence.detect_extended_persistence(correlator, raw_sideload)
    assert len(events) >= 1
    assert events[0].intent == "PERSIST_DLL_SIDELOAD"

    # 5. Defense Evasion
    raw_amsi = RawEvent(
        event_id="raw_amsi_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=103, command_line="powershell [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"), attributes={}
    )
    events = evasion.detect_extended_defense_evasion(correlator, raw_amsi)
    assert len(events) >= 1
    assert events[0].intent == "EVADE_AMSI_BYPASS"

    # 6. Process Injection
    raw_hollow = RawEvent(
        event_id="raw_hollow_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=104, command_line="process hollowing svchost.exe"), attributes={}
    )
    events = injection.detect_process_injection(correlator, raw_hollow)
    assert len(events) >= 1
    assert events[0].intent == "INJECT_PROCESS_HOLLOWING"
    assert events[0].severity == "CRITICAL"

    # 7. Payload / Unpacking
    raw_unpack = RawEvent(
        event_id="raw_unp_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=105, command_line="upx -d malware.exe"), attributes={}
    )
    events = payload.detect_payload_unpacking(correlator, raw_unpack)
    assert len(events) >= 1
    assert events[0].intent == "PAYLOAD_UNPACKING"

    # 8. Command and Control
    raw_dga = RawEvent(
        event_id="raw_dga_1", session_id="sess_1", source=EventSource.WIRESHARK, category=EventCategory.NETWORK,
        occurred_at=now, observed_at=now, attributes={"destination_hostname": "xk83jf92md01ks83.biz", "destination_port": 443}
    )
    events = c2.detect_extended_c2(correlator, raw_dga)
    assert len(events) >= 1
    assert events[0].intent == "C2_DGA_ACTIVITY"
    assert events[0].severity == "CRITICAL"

    # 9. Lateral Movement
    raw_wmi = RawEvent(
        event_id="raw_wmi_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=106, command_line="wmic /node:192.168.1.50 process call create 'cmd.exe'"), attributes={}
    )
    events = lateral.detect_extended_lateral(correlator, raw_wmi)
    assert len(events) >= 1
    assert events[0].intent == "LATERAL_WMI_REMOTE_EXEC"
    assert events[0].severity == "CRITICAL"

    # 10. Data Collection
    raw_doc = RawEvent(
        event_id="raw_doc_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\Users\\victim\\Documents\\confidential.docx"}
    )
    events = collection.detect_data_collection(correlator, raw_doc)
    assert len(events) >= 1
    assert events[0].intent == "COLLECT_DOCUMENTS"

    # 11. Impact / Ransomware
    raw_wipe = RawEvent(
        event_id="raw_wipe_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=107, command_line="cipher /w:C:\\"), attributes={}
    )
    events = impact.detect_extended_impact_and_ransomware(correlator, raw_wipe)
    assert len(events) >= 1
    assert events[0].intent == "IMPACT_FILE_DESTRUCTION"
    assert events[0].severity == "CRITICAL"

    # 12. Anti-Forensics
    raw_selfdel = RawEvent(
        event_id="raw_sdel_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=108, command_line="cmd.exe /c del %0 & ping 127.0.0.1"), attributes={}
    )
    events = anti_forensics.detect_anti_forensics(correlator, raw_selfdel)
    assert len(events) >= 1
    assert events[0].intent == "ANTI_FORENSICS_SELF_DELETE"
    assert events[0].severity == "CRITICAL"

    # 13. Malware Configuration Search
    raw_cfg = RawEvent(
        event_id="raw_cfg_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\ProgramData\\c2_config.json"},
        process=ProcessContext(pid=109, command_line="malware.exe")
    )
    events = config_search.detect_malware_configuration_search(correlator, raw_cfg)
    assert len(events) >= 1
    assert events[0].intent == "CONFIG_C2_CONFIG_SEARCH"

    # 14. Application Recon
    raw_office = RawEvent(
        event_id="raw_off_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"}
    )
    events = recon.detect_app_environment_recon(correlator, raw_office)
    assert len(events) >= 1
    assert events[0].intent == "RECON_OFFICE"

@pytest.mark.asyncio
async def test_policy_suppression_and_budget_enforcement():
    bus = EventBus(BusSettings(queue_size=100))
    policy = PolicyEngine(PolicySettings(ruleset_path="rules/default", global_confidence_gate=0.60, max_mutations_per_session=2), bus)
    now = datetime.now(timezone.utc)
    
    # 1. Low confidence -> SUPPRESSED_CONFIDENCE
    event_low_conf = SemanticEvent(
        semantic_id="sem_low", session_id="sess_suppress", correlation_id="corr_1",
        intent="CRED_BROWSER_STORE", confidence=0.40, severity="HIGH",
        window_start=now, window_end=now, evidence=["ev1"], detector="Test", features={}
    )
    decisions = await policy.evaluate(event_low_conf)
    assert len(decisions) == 1
    assert decisions[0].verdict == PolicyVerdict.SUPPRESSED_CONFIDENCE

    # 2. Normal execution 1
    event_ok1 = SemanticEvent(
        semantic_id="sem_ok1", session_id="sess_suppress", correlation_id="corr_2",
        intent="CRED_BROWSER_STORE", confidence=0.88, severity="HIGH",
        window_start=now, window_end=now, evidence=["ev2"], detector="Test", features={}
    )
    decisions1 = await policy.evaluate(event_ok1)
    assert len(decisions1) == 1
    assert decisions1[0].verdict == PolicyVerdict.EXECUTE

    # 3. Cooldown active -> SUPPRESSED_COOLDOWN (immediate repeat of same rule)
    decisions_cooldown = await policy.evaluate(event_ok1)
    assert len(decisions_cooldown) == 1
    assert decisions_cooldown[0].verdict == PolicyVerdict.SUPPRESSED_COOLDOWN or decisions_cooldown[0].verdict == PolicyVerdict.SUPPRESSED_BUDGET

@pytest.mark.asyncio
async def test_compound_campaign_inference():
    bus = EventBus(BusSettings(queue_size=100))
    fusion = FusionEngine(FusionSettings(window_seconds=10.0), bus)
    now = datetime.now(timezone.utc)
    session_id = "sess_campaign_test"

    # Multi-event sequence: Ransomware preparation + Volume shadow copy delete + file encrypt
    e1 = RawEvent(
        event_id="raw_r_1", session_id=session_id, source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=501, command_line="vssadmin delete shadows /all /quiet"), attributes={}
    )
    e2 = RawEvent(
        event_id="raw_r_2", session_id=session_id, source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\Users\\user\\Documents\\data.docx.locked"}
    )

    sem1 = await fusion.ingest(e1)
    sem2 = await fusion.ingest(e2)
    
    intents = [s.intent for s in sem1 + sem2]
    assert "IMPACT_SHADOW_COPY_DELETE" in intents
    assert "IMPACT_MASS_FILE_ENCRYPT" in intents
    assert "CAMPAIGN_RANSOMWARE" in intents
