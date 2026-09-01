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
    feat.setdefault("phase", "DISCOVERY")
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
def detect_domain_recon(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects Domain Controller discovery (T1018)."""
    events = []
    if event.category == EventCategory.REGISTRY:
        target = (event.attributes.get("target_object", "") or "").lower()
        if "tcpip\\parameters\\domain" in target or "tcpip\\parameters\\dhcpdomain" in target:
            events.append(_create_sem_event(event, "RECON_DOMAIN_CONTROLLER", 0.85, "HIGH", "TA0007", "T1018", "DomainReconDetector@1.0", {"registry_target": target}))
    elif event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "nltest" in cmd and ("/dclist" in cmd or "/dsgetdc" in cmd):
            events.append(_create_sem_event(event, "RECON_DOMAIN_CONTROLLER", 0.95, "HIGH", "TA0007", "T1018", "DomainReconDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_share_recon(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects network share discovery and enumeration (T1135)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "net" in cmd and ("view" in cmd or "share" in cmd):
            events.append(_create_sem_event(event, "RECON_NETWORK_SHARES", 0.90, "HIGH", "TA0007", "T1135", "ShareReconDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_installed_av_recon(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects security software and antivirus discovery (T1518.001)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if ("wmic" in cmd and "antivirusproduct" in cmd) or ("powershell" in cmd and "get-mppreference" in cmd) or "get-mpcomputerstatus" in cmd or "fltmc" in cmd:
            events.append(_create_sem_event(event, "RECON_INSTALLED_AV", 0.92, "HIGH", "TA0007", "T1518.001", "InstalledAVDetector@1.0", {"command_line": cmd}))
    elif event.category == EventCategory.REGISTRY:
        target = (event.attributes.get("target_object", "") or "").lower()
        if "microsoft\\windows defender" in target or "symantec" in target or "eset" in target or "kaspersky" in target or "sentinelone" in target or "crowdstrike" in target:
            events.append(_create_sem_event(event, "RECON_INSTALLED_AV", 0.85, "HIGH", "TA0007", "T1518.001", "InstalledAVDetector@1.0", {"registry_target": target}))
    return events

@register_detector
def detect_system_info_recon(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects system information discovery (T1082)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "systeminfo" in cmd or ("wmic" in cmd and "os get" in cmd) or "msinfo32" in cmd:
            events.append(_create_sem_event(event, "RECON_SYSTEM_INFO", 0.88, "LOW", "TA0007", "T1082", "SystemInfoDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_network_config_recon(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects network configuration discovery (T1016)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "ipconfig" in cmd or "route print" in cmd or ("netsh" in cmd and "interface" in cmd) or "get-netipaddress" in cmd:
            events.append(_create_sem_event(event, "RECON_NETWORK_CONFIG", 0.88, "LOW", "TA0007", "T1016", "NetworkConfigDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_process_discovery(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects running process discovery / tasklisting (T1057)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if "tasklist" in cmd or ("wmic" in cmd and "process list" in cmd) or "get-process" in cmd or "ps.exe" in cmd:
            events.append(_create_sem_event(event, "RECON_PROCESS_DISCOVERY", 0.85, "MEDIUM", "TA0007", "T1057", "ProcessDiscoveryDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_user_discovery(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects system owner / user discovery (T1033)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if ("whoami" in cmd and len(cmd.split()) <= 2) or "query user" in cmd or "quser" in cmd or ("net" in cmd and "user" in cmd):
            events.append(_create_sem_event(event, "RECON_USER_DISCOVERY", 0.90, "MEDIUM", "TA0007", "T1033", "UserDiscoveryDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_file_directory_discovery(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects file and directory enumeration (T1083)."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        if ".docx" in cmd or ".pdf" in cmd or ("documents" in cmd and ("dir" in cmd or "get-childitem" in cmd or "find" in cmd)):
            events.append(_create_sem_event(event, "COLLECT_DOCUMENTS", 0.88, "HIGH", "TA0009", "T1005", "CollectDocumentsDetector@1.0", {"command_line": cmd}))
        elif ("dir " in cmd and ("/s" in cmd or "/b" in cmd)) or ("tree " in cmd) or ("get-childitem" in cmd):
            events.append(_create_sem_event(event, "RECON_FILE_DIRECTORY", 0.80, "LOW", "TA0007", "T1083", "FileDirectoryDiscoveryDetector@1.0", {"command_line": cmd}))
    return events

@register_detector
def detect_extended_recon(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects additional discovery intents: security tools, running services, os version, hostname, domain, etc."""
    events = []
    if event.category == EventCategory.PROCESS and event.process:
        cmd = (event.process.command_line or "").lower()
        
        # RECON_SECURITY_TOOLS
        if "sc query" in cmd and "windefend" in cmd or "netsh advfirewall show" in cmd:
            events.append(_create_sem_event(event, "RECON_SECURITY_TOOLS", 0.90, "HIGH", "TA0007", "T1518.001", "SecurityToolsReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_RUNNING_SERVICES
        elif "net start" in cmd or "get-service" in cmd or ("sc" in cmd and "query" in cmd):
            events.append(_create_sem_event(event, "RECON_RUNNING_SERVICES", 0.88, "HIGH", "TA0007", "T1007", "ServicesReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_OS_VERSION
        elif "ver" == cmd.strip() or "winver" in cmd:
            events.append(_create_sem_event(event, "RECON_OS_VERSION", 0.85, "MEDIUM", "TA0007", "T1082", "OSVersionReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_HOSTNAME
        elif "hostname" in cmd:
            events.append(_create_sem_event(event, "RECON_HOSTNAME", 0.85, "MEDIUM", "TA0007", "T1082", "HostnameReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_DOMAIN_MEMBERSHIP
        elif "net config workstation" in cmd or "dsquery" in cmd:
            events.append(_create_sem_event(event, "RECON_DOMAIN_MEMBERSHIP", 0.90, "HIGH", "TA0007", "T1018", "DomainMembershipReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_LOGGED_ON_USERS
        elif "qwinsta" in cmd or "query session" in cmd:
            events.append(_create_sem_event(event, "RECON_LOGGED_ON_USERS", 0.85, "MEDIUM", "TA0007", "T1033", "LoggedOnUsersReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_SHARED_FOLDERS
        elif "net share" in cmd or "get-smbshare" in cmd:
            events.append(_create_sem_event(event, "RECON_SHARED_FOLDERS", 0.90, "HIGH", "TA0007", "T1135", "SharedFoldersReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_PRINTERS
        elif "get-printer" in cmd or "wmic printer" in cmd or "prnmngr" in cmd:
            events.append(_create_sem_event(event, "RECON_PRINTERS", 0.85, "MEDIUM", "TA0007", "T1082", "PrintersReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_INSTALLED_SOFTWARE
        elif ("uninstall" in cmd and "registry" in cmd) or ("wmic" in cmd and "product get" in cmd) or "get-package" in cmd:
            events.append(_create_sem_event(event, "RECON_INSTALLED_SOFTWARE", 0.88, "MEDIUM", "TA0007", "T1518", "InstalledSoftwareReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_SECURITY_POLICY
        elif "secedit" in cmd or "gpresult" in cmd:
            events.append(_create_sem_event(event, "RECON_SECURITY_POLICY", 0.88, "MEDIUM", "TA0007", "T1201", "SecurityPolicyReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_FIREWALL_CONFIG
        elif "netsh advfirewall" in cmd or "get-netfirewallrule" in cmd:
            events.append(_create_sem_event(event, "RECON_FIREWALL_CONFIG", 0.88, "MEDIUM", "TA0007", "T1562.004", "FirewallConfigReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_ADMIN_PRIVILEGE
        elif ("net session" in cmd or "whoami /priv" in cmd or "whoami /groups" in cmd):
            events.append(_create_sem_event(event, "RECON_ADMIN_PRIVILEGE", 0.90, "MEDIUM", "TA0007", "T1033", "AdminPrivilegeReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_TIMEZONE
        elif "tzutil" in cmd or "get-timezone" in cmd or "wmic timezone" in cmd:
            events.append(_create_sem_event(event, "RECON_TIMEZONE", 0.85, "MEDIUM", "TA0007", "T1614", "TimezoneReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_LANGUAGE_LOCALE
        elif "get-culture" in cmd or "get-uiculture" in cmd or "dism /online /get-intl" in cmd:
            events.append(_create_sem_event(event, "RECON_LANGUAGE_LOCALE", 0.85, "LOW", "TA0007", "T1614.001", "LanguageLocaleReconDetector@1.0", {"command_line": cmd}))
            
        # RECON_NETWORK_TOPOLOGY
        elif "arp -a" in cmd or "nbtstat" in cmd or "nslookup" in cmd:
            events.append(_create_sem_event(event, "RECON_NETWORK_TOPOLOGY", 0.88, "MEDIUM", "TA0007", "T1016", "NetworkTopologyReconDetector@1.0", {"command_line": cmd}))

    elif event.category == EventCategory.REGISTRY:
        target = (event.attributes.get("target_object", "") or "").lower()
        if "control\\timezoneinformation" in target:
            events.append(_create_sem_event(event, "RECON_TIMEZONE", 0.85, "MEDIUM", "TA0007", "T1614", "TimezoneReconDetector@1.0", {"registry_target": target}))
        elif "control\\nls\\language" in target or "control\\nls\\locale" in target:
            events.append(_create_sem_event(event, "RECON_LANGUAGE_LOCALE", 0.85, "LOW", "TA0007", "T1614.001", "LanguageLocaleReconDetector@1.0", {"registry_target": target}))
        elif "software\\microsoft\\windows\\currentversion\\uninstall" in target:
            events.append(_create_sem_event(event, "RECON_INSTALLED_SOFTWARE", 0.85, "MEDIUM", "TA0007", "T1518", "InstalledSoftwareReconDetector@1.0", {"registry_target": target}))
            
    return events

@register_detector
def detect_app_environment_recon(correlator: EventCorrelator, event: RawEvent) -> List[SemanticEvent]:
    """Detects targeted application/environment discovery."""
    events = []
    target_str = ""
    if event.category == EventCategory.FILE:
        target_str = (event.attributes.get("target_object", "") or event.attributes.get("path", "")).lower()
    elif event.category == EventCategory.REGISTRY:
        target_str = (event.attributes.get("target_object", "") or "").lower()
    elif event.category == EventCategory.PROCESS and event.process:
        target_str = (event.process.command_line or "").lower()

    if not target_str:
        return events

    # RECON_OFFICE
    if "microsoft office" in target_str or "office\\16.0" in target_str or "outlook.exe" in target_str or "winword.exe" in target_str:
        events.append(_create_sem_event(event, "RECON_OFFICE", 0.88, "MEDIUM", "TA0007", "T1518", "OfficeReconDetector@1.0", {"target": target_str}))
    # RECON_BROWSER
    elif "chrome.exe" in target_str or "msedge.exe" in target_str or "firefox.exe" in target_str or "brave.exe" in target_str:
        events.append(_create_sem_event(event, "RECON_BROWSER", 0.88, "MEDIUM", "TA0007", "T1518", "BrowserReconDetector@1.0", {"target": target_str}))
    # RECON_EMAIL_CLIENT
    elif "thunderbird" in target_str or "foxmail" in target_str or "mailbird" in target_str:
        events.append(_create_sem_event(event, "RECON_EMAIL_CLIENT", 0.88, "MEDIUM", "TA0007", "T1518", "EmailClientReconDetector@1.0", {"target": target_str}))
    # RECON_DATABASE
    elif "sqlservr" in target_str or "mysqld" in target_str or "postgres" in target_str or "oracle.exe" in target_str or "dbeaver" in target_str:
        events.append(_create_sem_event(event, "RECON_DATABASE", 0.90, "HIGH", "TA0007", "T1518", "DatabaseReconDetector@1.0", {"target": target_str}))
    # RECON_VPN_CLIENT
    elif "openvpn" in target_str or "cisco anyconnect" in target_str or "forticlient" in target_str or "wireguard" in target_str:
        events.append(_create_sem_event(event, "RECON_VPN_CLIENT", 0.90, "HIGH", "TA0007", "T1518", "VPNClientReconDetector@1.0", {"target": target_str}))
    # RECON_REMOTE_ACCESS
    elif "teamviewer" in target_str or "anydesk" in target_str or "vncviewer" in target_str or "mstsc" in target_str:
        events.append(_create_sem_event(event, "RECON_REMOTE_ACCESS", 0.90, "HIGH", "TA0007", "T1518", "RemoteAccessReconDetector@1.0", {"target": target_str}))
    # RECON_SECURITY_SOFTWARE
    elif "wireshark" in target_str or "ghidra" in target_str or "x64dbg" in target_str or "processhacker" in target_str:
        events.append(_create_sem_event(event, "RECON_SECURITY_SOFTWARE", 0.92, "HIGH", "TA0007", "T1518.001", "SecuritySoftwareReconDetector@1.0", {"target": target_str}))
    # RECON_DEVELOPER_TOOLS
    elif "git.exe" in target_str or "visual studio" in target_str or "vscode" in target_str or "docker" in target_str or "kubectl" in target_str:
        events.append(_create_sem_event(event, "RECON_DEVELOPER_TOOLS", 0.88, "MEDIUM", "TA0007", "T1518", "DeveloperToolsReconDetector@1.0", {"target": target_str}))

    return events
