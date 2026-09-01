import pytest
import asyncio
from datetime import datetime, timezone
from adam.contracts.enums import EventCategory, EventSource, PolicyVerdict, MutationStatus
from adam.contracts.raw_event import RawEvent, ProcessContext
from adam.contracts.semantic_event import SemanticEvent
from adam.contracts.policy_decision import PolicyDecision
from adam.fusion.correlate import EventCorrelator
from adam.fusion.engine import FusionEngine
from adam.fusion.registry import DETECTOR_REGISTRY
from adam.fusion.detectors.credentials import (
    detect_wallet_search,
    detect_browser_store_access,
    detect_session_cookie_search,
    detect_private_key_search,
    detect_windows_cred_manager,
    detect_password_manager_search,
    detect_config_file_harvest
)
from adam.fusion.detectors.recon import (
    detect_domain_recon,
    detect_share_recon,
    detect_installed_av_recon,
    detect_system_info_recon,
    detect_network_config_recon,
    detect_process_discovery,
    detect_user_discovery,
    detect_file_directory_discovery
)
from adam.fusion.detectors.evasion import (
    detect_sandbox_hardware_check,
    detect_sandbox_registry_check,
    detect_sandbox_process_check,
    detect_sandbox_user_activity_check,
    detect_sandbox_time_delay_check
)
from adam.fusion.detectors.execution import detect_execution_interpreter
from adam.fusion.detectors.persistence import (
    detect_run_key_persistence,
    detect_scheduled_task_persistence,
    detect_service_persistence,
    detect_wmi_subscription_persistence
)
from adam.fusion.detectors.impact import detect_shadow_copy_delete, detect_ransom_note_drop
from adam.fusion.detectors.c2 import detect_c2_beacon
from adam.fusion.detectors.lateral import detect_lateral_smb
from adam.policy.engine import PolicyEngine
from adam.common.config import PolicySettings, FusionSettings, BusSettings
from adam.common.bus import EventBus

@pytest.fixture
def correlator():
    return EventCorrelator(window_seconds=10.0)

def test_credential_detectors_granularity(correlator):
    now = datetime.now(timezone.utc)
    
    # 1. Wallet Search -> CRED_WALLET_SEARCH (T1552.001)
    raw_wallet = RawEvent(
        event_id="raw_wallet_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\Users\\victim\\AppData\\Roaming\\Electrum\\wallets\\default_wallet"}
    )
    events = detect_wallet_search(correlator, raw_wallet)
    assert len(events) == 1
    assert events[0].intent == "CRED_WALLET_SEARCH"
    assert events[0].attck.technique == "T1552.001"
    
    # 2. Browser Store -> CRED_BROWSER_STORE (T1555.003)
    raw_browser = RawEvent(
        event_id="raw_browser_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\Users\\victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"}
    )
    events = detect_browser_store_access(correlator, raw_browser)
    assert len(events) == 1
    assert events[0].intent == "CRED_BROWSER_STORE"
    assert events[0].attck.technique == "T1555.003"
    
    # 3. Session Cookie -> CRED_SESSION_COOKIE_SEARCH (T1539)
    raw_cookie = RawEvent(
        event_id="raw_cookie_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\Users\\victim\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"}
    )
    events = detect_session_cookie_search(correlator, raw_cookie)
    assert len(events) == 1
    assert events[0].intent == "CRED_SESSION_COOKIE_SEARCH"
    assert events[0].attck.technique == "T1539"
    
    # 4. Private Key -> CRED_PRIVATE_KEY_SEARCH (T1552.004)
    raw_key = RawEvent(
        event_id="raw_key_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\Users\\victim\\.ssh\\id_rsa"}
    )
    events = detect_private_key_search(correlator, raw_key)
    assert len(events) == 1
    assert events[0].intent == "CRED_PRIVATE_KEY_SEARCH"
    assert events[0].attck.technique == "T1552.004"
    
    # 5. Windows Credential Manager -> CRED_WINDOWS_CREDENTIAL_MANAGER (T1555.004)
    raw_cmdkey = RawEvent(
        event_id="raw_cmdkey_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=1001, command_line="cmdkey /list"),
        attributes={}
    )
    events = detect_windows_cred_manager(correlator, raw_cmdkey)
    assert len(events) == 1
    assert events[0].intent == "CRED_WINDOWS_CREDENTIAL_MANAGER"
    assert events[0].attck.technique == "T1555.004"

def test_discovery_detectors_granularity(correlator):
    now = datetime.now(timezone.utc)
    
    # 1. Domain Controller -> RECON_DOMAIN_CONTROLLER (T1018)
    raw_dc = RawEvent(
        event_id="raw_dc_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=1002, command_line="nltest /dclist:CORP"),
        attributes={}
    )
    events = detect_domain_recon(correlator, raw_dc)
    assert len(events) == 1
    assert events[0].intent == "RECON_DOMAIN_CONTROLLER"
    assert events[0].attck.technique == "T1018"
    
    # 2. Network Shares -> RECON_NETWORK_SHARES (T1135)
    raw_share = RawEvent(
        event_id="raw_share_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=1003, command_line="net view \\\\corp-dc01"),
        attributes={}
    )
    events = detect_share_recon(correlator, raw_share)
    assert len(events) == 1
    assert events[0].intent == "RECON_NETWORK_SHARES"
    assert events[0].attck.technique == "T1135"
    
    # 3. Installed AV -> RECON_INSTALLED_AV (T1518.001)
    raw_av = RawEvent(
        event_id="raw_av_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=1004, command_line="wmic /namespace:\\\\root\\securitycenter2 path antivirusproduct get displayname"),
        attributes={}
    )
    events = detect_installed_av_recon(correlator, raw_av)
    assert len(events) == 1
    assert events[0].intent == "RECON_INSTALLED_AV"
    assert events[0].attck.technique == "T1518.001"
    
    # 4. System Info -> RECON_SYSTEM_INFO (T1082)
    raw_sys = RawEvent(
        event_id="raw_sys_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=1005, command_line="systeminfo"),
        attributes={}
    )
    events = detect_system_info_recon(correlator, raw_sys)
    assert len(events) == 1
    assert events[0].intent == "RECON_SYSTEM_INFO"
    assert events[0].attck.technique == "T1082"

def test_evasion_detectors_granularity(correlator):
    now = datetime.now(timezone.utc)
    
    # Hardware check -> SANDBOX_HARDWARE_CHECK (T1497.001)
    raw_hw = RawEvent(
        event_id="raw_hw_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.REGISTRY,
        occurred_at=now, observed_at=now, attributes={"target_object": "HKLM\\HARDWARE\\DESCRIPTION\\System\\SystemBiosVersion", "details": "QEMU Virtual BIOS"}
    )
    events = detect_sandbox_hardware_check(correlator, raw_hw)
    assert len(events) == 1
    assert events[0].intent == "SANDBOX_HARDWARE_CHECK"
    assert events[0].attck.technique == "T1497.001"
    
    # Time delay check -> SANDBOX_TIME_DELAY_CHECK (T1497.003)
    raw_time = RawEvent(
        event_id="raw_time_1", session_id="sess_1", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=1006, command_line="powershell Start-Sleep -Seconds 60"),
        attributes={}
    )
    events = detect_sandbox_time_delay_check(correlator, raw_time)
    assert len(events) == 1
    assert events[0].intent == "SANDBOX_TIME_DELAY_CHECK"
    assert events[0].attck.technique == "T1497.003"

@pytest.mark.asyncio
async def test_policy_closed_loop_and_causal_attribution():
    bus = EventBus(BusSettings(queue_size=100))
    fusion = FusionEngine(FusionSettings(window_seconds=5.0), bus)
    policy = PolicyEngine(PolicySettings(ruleset_path="rules/default", global_confidence_gate=0.60), bus)
    now = datetime.now(timezone.utc)
    
    # 1. Regression Test A: CRED_WALLET_SEARCH -> RULE-CRED-002 -> PLANT_DECOY_WALLET
    raw_wallet = RawEvent(
        event_id="raw_w_test", session_id="sess_test", source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\Users\\user\\wallet.dat"}
    )
    sem_events = await fusion.ingest(raw_wallet)
    assert len(sem_events) >= 1
    w_event = [e for e in sem_events if e.intent == "CRED_WALLET_SEARCH"][0]
    
    decisions = await policy.evaluate(w_event)
    assert len(decisions) == 1
    assert decisions[0].rule_id == "RULE-CRED-002"
    assert decisions[0].verdict == PolicyVerdict.EXECUTE
    assert decisions[0].action == "PLANT_DECOY_WALLET"
    
    # 2. Regression Test B: RECON_DOMAIN_CONTROLLER -> RULE-RECON-001 -> SPAWN_FAKE_DC_ARTIFACTS
    raw_dc = RawEvent(
        event_id="raw_dc_test", session_id="sess_test", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=2001, command_line="nltest /dclist:CORP"),
        attributes={}
    )
    sem_dc_events = await fusion.ingest(raw_dc)
    dc_event = [e for e in sem_dc_events if e.intent == "RECON_DOMAIN_CONTROLLER"][0]
    
    dc_decisions = await policy.evaluate(dc_event)
    assert len(dc_decisions) == 1
    assert dc_decisions[0].rule_id == "RULE-RECON-001"
    assert dc_decisions[0].verdict == PolicyVerdict.EXECUTE
    assert dc_decisions[0].action == "SPAWN_FAKE_DC_ARTIFACTS"
    
    # 3. New Test C: CRED_BROWSER_STORE -> RULE-CRED-001 -> INJECT_FAKE_BROWSER_CREDS
    raw_chrome = RawEvent(
        event_id="raw_c_test", session_id="sess_test", source=EventSource.SYSMON, category=EventCategory.FILE,
        occurred_at=now, observed_at=now, attributes={"target_object": "C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"}
    )
    sem_c_events = await fusion.ingest(raw_chrome)
    c_event = [e for e in sem_c_events if e.intent == "CRED_BROWSER_STORE"][0]
    
    c_decisions = await policy.evaluate(c_event)
    assert len(c_decisions) == 1
    assert decisions[0].rule_id == "RULE-CRED-002"
    assert c_decisions[0].rule_id == "RULE-CRED-001"
    assert c_decisions[0].verdict == PolicyVerdict.EXECUTE
    assert c_decisions[0].action == "INJECT_FAKE_BROWSER_CREDS"
    
    # 4. Verify Causal Window Attribution (caused_by_mutation)
    fusion.set_active_mutation("mut_provenance_99")
    follow_on_raw = RawEvent(
        event_id="raw_follow_1", session_id="sess_test", source=EventSource.SYSMON, category=EventCategory.PROCESS,
        occurred_at=now, observed_at=now, process=ProcessContext(pid=2002, command_line="cmdkey /list"),
        attributes={}
    )
    follow_sem_events = await fusion.ingest(follow_on_raw)
    assert len(follow_sem_events) >= 1
    assert follow_sem_events[0].caused_by_mutation == "mut_provenance_99"
