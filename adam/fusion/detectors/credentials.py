import uuid
from typing import List
from adam.contracts.enums import EventCategory
from adam.contracts.raw_event import RawEvent
from adam.contracts.semantic_event import SemanticEvent, ActorContext, AttckContext
from adam.fusion.correlate import EventCorrelator
from adam.fusion.registry import register_detector

def _create_sem_event(event: RawEvent, intent: str, confidence: float, severity: str, tactic: str, technique: str, detector: str, features: dict) -> SemanticEvent:
    actor = ActorContext(pid=event.process.pid, image=event.process.image, guid=event.process.guid) if event.process else None
    feat = dict(features)
    feat.setdefault("phase", "CREDENTIAL_ACCESS")
    return SemanticEvent(
        semantic_id=f"sem_{uuid.uuid4().hex[:12]}",
        session_id=event.session_id,
        correlation_id=f"corr_{event.event_id[4:14]}",
        intent=intent,
        confidence=confidence,
        severity=severity,
        window_start=event.occurred_at,
        window_end=event.occurred_at,
        actor=actor,
        evidence=[event.event_id],
        attck=AttckContext(tactic=tactic, technique=technique),
        detector=detector,
        features=feat
    )

@register_detector
def detect_browser_store_access(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects attempts to access browser stored credentials (T1555.003)."""
    events = []
    target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower().replace("/", "\\")
    cmd = (event.process.command_line or "").lower() if event.process else ""
    if event.category == EventCategory.FILE:
        if ("login data" in target or "logins.json" in target or "key4.db" in target) or (("chrome" in target or "edge" in target or "firefox" in target) and ("user data" in target or "profiles" in target)):
            events.append(_create_sem_event(event, "CRED_BROWSER_STORE", 0.88, "HIGH", "TA0006", "T1555.003", "BrowserCredStoreDetector@1.0", {"file_target": target}))
    elif event.category == EventCategory.PROCESS and event.process:
        if "login data" in cmd or "logins.json" in cmd or "key4.db" in cmd or ("user data" in cmd and "login" in cmd):
            events.append(_create_sem_event(event, "CRED_BROWSER_STORE", 0.88, "HIGH", "TA0006", "T1555.003", "BrowserCredStoreDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_session_cookie_search(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects attempts to harvest browser session cookies and tokens (T1539)."""
    events = []
    if event.category == EventCategory.FILE:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if ("network\\cookies" in target or "cookies.sqlite" in target or "cookies" in target) and ("user data" in target or "profiles" in target):
            events.append(_create_sem_event(event, "CRED_SESSION_COOKIE_SEARCH", 0.85, "HIGH", "TA0006", "T1539", "SessionCookieDetector@1.0", {"file_target": target}))
    elif event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "network\\cookies" in cmd or "cookies.sqlite" in cmd:
            events.append(_create_sem_event(event, "CRED_SESSION_COOKIE_SEARCH", 0.85, "HIGH", "TA0006", "T1539", "SessionCookieDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_wallet_search(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects search/discovery of cryptocurrency wallet files (T1552.001)."""
    events = []
    if event.category == EventCategory.FILE:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if "wallet.dat" in target or "electrum\\wallets" in target or "exodus\\exodus.wallet" in target:
            events.append(_create_sem_event(event, "CRED_WALLET_SEARCH", 0.92, "HIGH", "TA0006", "T1552.001", "CryptoWalletDetector@1.0", {"file_target": target}))
    elif event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "wallet.dat" in cmd or "electrum" in cmd or "exodus.wallet" in cmd:
            events.append(_create_sem_event(event, "CRED_WALLET_SEARCH", 0.92, "HIGH", "TA0006", "T1552.001", "CryptoWalletDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_private_key_search(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects search for private keys / SSH / certificate files (T1552.004)."""
    events = []
    if event.category == EventCategory.FILE:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if target.endswith(".pem") or target.endswith(".key") or "id_rsa" in target or "id_ed25519" in target:
            events.append(_create_sem_event(event, "CRED_PRIVATE_KEY_SEARCH", 0.90, "HIGH", "TA0006", "T1552.004", "PrivateKeyDetector@1.0", {"file_target": target}))
    elif event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "id_rsa" in cmd or ".pem" in cmd or "id_ed25519" in cmd or ".ppk" in cmd:
            events.append(_create_sem_event(event, "CRED_PRIVATE_KEY_SEARCH", 0.90, "HIGH", "TA0006", "T1552.004", "PrivateKeyDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_windows_cred_manager(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects enumeration or dumping of Windows Credential Manager (T1555.004)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "cmdkey" in cmd and ("/list" in cmd or "/l" in cmd):
            events.append(_create_sem_event(event, "CRED_WINDOWS_CREDENTIAL_MANAGER", 0.95, "HIGH", "TA0006", "T1555.004", "WinCredManagerDetector@1.0", {"command_line": cmd}))
    elif event.category == EventCategory.FILE:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if "appdata\\roaming\\microsoft\\credentials" in target or "appdata\\local\\microsoft\\credentials" in target:
            events.append(_create_sem_event(event, "CRED_WINDOWS_CREDENTIAL_MANAGER", 0.90, "HIGH", "TA0006", "T1555.004", "WinCredManagerDetector@1.0", {"file_target": target}))
    return events

@register_detector
def detect_password_manager_search(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects search for password manager database vaults (T1555.005)."""
    events = []
    if event.category == EventCategory.FILE:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if target.endswith(".kdbx") or "1password" in target or "bitwarden" in target or "keepass" in target:
            events.append(_create_sem_event(event, "CRED_PASSWORD_MANAGER_SEARCH", 0.90, "HIGH", "TA0006", "T1555.005", "PasswordManagerDetector@1.0", {"file_target": target}))
    elif event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if ".kdbx" in cmd or "keepass" in cmd or "1password" in cmd or "bitwarden" in cmd:
            events.append(_create_sem_event(event, "CRED_PASSWORD_MANAGER_SEARCH", 0.90, "HIGH", "TA0006", "T1555.005", "PasswordManagerDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_config_file_harvest(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects searching for sensitive config files containing credentials (T1552.001)."""
    events = []
    if event.category == EventCategory.FILE:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if target.endswith("unattend.xml") or target.endswith("sysprep.inf") or target.endswith("web.config") or target.endswith("appsettings.json") or target.endswith(".env"):
            events.append(_create_sem_event(event, "CRED_CONFIG_FILE_HARVEST", 0.88, "MEDIUM", "TA0006", "T1552.001", "ConfigFileHarvestDetector@1.0", {"file_target": target}))
    elif event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "unattend.xml" in cmd or "sysprep.inf" in cmd or "web.config" in cmd or ".env" in cmd:
            events.append(_create_sem_event(event, "CRED_CONFIG_FILE_HARVEST", 0.88, "MEDIUM", "TA0006", "T1552.001", "ConfigFileHarvestDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_extended_credentials(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects advanced & high-privilege credential theft intents (LSASS, SAM, NTDS, SSH, Cloud, API, RDP, Email)."""
    events = []
    
    # 1. LSASS Access (T1003.001) - CRITICAL
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        image = (event.process.image or "").lower()
        if ("procdump" in cmd and "lsass" in cmd) or ("comsvcs" in cmd and "minidump" in cmd) or "sekurlsa" in cmd or "mimikatz" in cmd:
            events.append(_create_sem_event(event, "CRED_LSASS_ACCESS", 0.98, "CRITICAL", "TA0006", "T1003.001", "LSASSAccessDetector@1.0", {"command_line": cmd}))
        elif "lsass.exe" in image and event.attributes.get("granted_access") in ("0x1010", "0x1fffff", "0x1410"):
            events.append(_create_sem_event(event, "CRED_LSASS_ACCESS", 0.95, "CRITICAL", "TA0006", "T1003.001", "LSASSAccessDetector@1.0", {"access": event.attributes.get("granted_access")}))

    # 2. SAM Registry Hive Dump (T1003.002) - CRITICAL
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "reg save" in cmd and ("hklm\\sam" in cmd or "hklm\\system" in cmd or "hklm\\security" in cmd):
            events.append(_create_sem_event(event, "CRED_SAM_ACCESS", 0.98, "CRITICAL", "TA0006", "T1003.002", "SAMAccessDetector@1.0", {"command_line": cmd}))

    # 3. NTDS.dit Access (T1003.003) - CRITICAL
    if (event.category == EventCategory.PROCESS and event.process) or event.category == EventCategory.FILE:
        cmd = (event.process.command_line or "").lower() if event.process else ""
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if "ntdsutil" in cmd or "ntds.dit" in cmd or "ntds.dit" in target:
            events.append(_create_sem_event(event, "CRED_NTDS_ACCESS", 0.98, "CRITICAL", "TA0006", "T1003.003", "NTDSAccessDetector@1.0", {"target": target or cmd}))

    # 4. SSH Config Search (T1552.004) - HIGH
    if event.category == EventCategory.FILE or (event.category == EventCategory.PROCESS and event.process):
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        cmd = (event.process.command_line or "").lower() if event.process else ""
        if ".ssh\\config" in target or "known_hosts" in target or "known_hosts" in cmd or ".ssh\\config" in cmd:
            events.append(_create_sem_event(event, "CRED_SSH_CONFIG_SEARCH", 0.90, "HIGH", "TA0006", "T1552.004", "SSHConfigSearchDetector@1.0", {"target": target or cmd}))

    # 5. RDP Artifact Search (T1552) - HIGH
    if event.category == EventCategory.FILE or (event.category == EventCategory.PROCESS and event.process):
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        cmd = (event.process.command_line or "").lower() if event.process else ""
        if target.endswith(".rdp") or "default.rdp" in target or "default.rdp" in cmd or "mstsc" in cmd and "/v:" in cmd:
            events.append(_create_sem_event(event, "CRED_RDP_ARTIFACT_SEARCH", 0.88, "HIGH", "TA0006", "T1552", "RDPArtifactSearchDetector@1.0", {"target": target or cmd}))

    # 6. Email Artifact Search (T1552) - HIGH
    if event.category == EventCategory.FILE:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if target.endswith(".pst") or target.endswith(".ost") or target.endswith(".eml") or target.endswith(".msg"):
            events.append(_create_sem_event(event, "CRED_EMAIL_ARTIFACT_SEARCH", 0.90, "HIGH", "TA0006", "T1552", "EmailArtifactSearchDetector@1.0", {"file_target": target}))

    # 7. API Token Search (T1552.001) - HIGH
    if event.category == EventCategory.FILE:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if "token" in target or "api_key" in target or "jwt" in target or "bearer" in target:
            events.append(_create_sem_event(event, "CRED_API_TOKEN_SEARCH", 0.85, "HIGH", "TA0006", "T1552.001", "APITokenSearchDetector@1.0", {"file_target": target}))

    # 8. Cloud Credential Search (T1552.005) - CRITICAL
    if event.category == EventCategory.FILE:
        target = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
        if ".aws\\credentials" in target or ".azure\\credentials" in target or "gcloud\\credentials.db" in target:
            events.append(_create_sem_event(event, "CRED_CLOUD_CREDENTIAL_SEARCH", 0.95, "CRITICAL", "TA0006", "T1552.005", "CloudCredentialSearchDetector@1.0", {"file_target": target}))
    elif event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "aws_access_key_id" in cmd or "az account get-access-token" in cmd or "gcloud auth" in cmd:
            events.append(_create_sem_event(event, "CRED_CLOUD_CREDENTIAL_SEARCH", 0.95, "CRITICAL", "TA0006", "T1552.005", "CloudCredentialSearchDetector@1.0", {"command_line": cmd}))

    return events
