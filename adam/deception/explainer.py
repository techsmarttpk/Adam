from typing import Dict, Any, List
from adam.contracts.mutation import MutationResult, MutationChange

def explain_mutation(mutation: MutationResult) -> Dict[str, Any]:
    """
    Generates a structured, human-readable representation of what ADAM created
    for a given deception primitive or measurement mutation.
    """
    primitive = mutation.primitive
    changes = mutation.changes

    # Default explanation structure
    explanation = {
        "title": primitive.replace("_", " ").title(),
        "primitive": primitive,
        "status": mutation.status.value,
        "plausibility_score": mutation.plausibility_score,
        "plausibility_notes": mutation.plausibility_notes,
        "revertible": mutation.revertible,
        "causal_window_ms": mutation.causal_window_ms,
        "summary": "Deception primitive applied to sandbox environment.",
        "artifacts": {}
    }

    if primitive == "SPAWN_FAKE_DC_ARTIFACTS":
        domain = "CORP.LOCAL"
        dc_host = "DC01.CORP.LOCAL"
        ip = "10.0.0.10"
        for c in changes:
            if c.kind == "REGISTRY" and "Domain" in c.target and c.value:
                domain = c.value
            elif c.kind == "NETWORK" and c.value:
                ip = c.value
        explanation.update({
            "title": "Generated Domain Environment",
            "summary": f"Synthesized Active Directory Domain Controller '{dc_host}' ({ip}) for domain '{domain}'.",
            "artifacts": {
                "Domain": domain,
                "Domain Controller": dc_host,
                "Address": ip,
                "Registry Artifacts": [c.target for c in changes if c.kind == "REGISTRY"],
                "Filesystem Artifacts": [c.target for c in changes if c.kind == "FILE"],
                "Network Artifacts": [f"DNS Mapping: {dc_host} -> {ip}"]
            }
        })

    elif primitive == "INJECT_FAKE_BROWSER_CREDS":
        explanation.update({
            "title": "Generated Browser Credential Decoys",
            "summary": "Synthesized SQLite credential vault with simulated user logins into Chrome / Edge profile directory.",
            "artifacts": {
                "Browser": "Google Chrome (Default Profile)",
                "Vault File": "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
                "Schema": "SQLite 3 Encrypted Vault",
                "Simulated Decoy Entries": "admin@corp.local, executive_vpn, payroll_portal",
                "Filesystem Artifacts": [c.target for c in changes if c.kind == "FILE"]
            }
        })

    elif primitive == "MOUNT_FAKE_NETWORK_SHARE":
        explanation.update({
            "title": "Synthetic Corporate Network Share",
            "summary": "Instantiated local mock SMB share structure populated with sensitive financial audit review spreadsheets.",
            "artifacts": {
                "Server": "\\\\127.0.0.1\\Financials",
                "Share Path": "C:\\Corporate_Shares\\Financials",
                "Decoy Documents": ["Q3_Internal_Audit.xlsx"],
                "Filesystem Artifacts": [c.target for c in changes if c.kind == "FILE"]
            }
        })

    elif primitive == "PLANT_DECOY_WALLET":
        explanation.update({
            "title": "Synthetic Cryptocurrency Wallet",
            "summary": "Planted simulated Electrum / Bitcoin hierarchical deterministic (HD) wallet key store.",
            "artifacts": {
                "Wallet Client": "Electrum Bitcoin Wallet",
                "Target Directory": "%APPDATA%\\Electrum\\wallets",
                "Wallet File": "default_wallet",
                "Decoy Key Signature": "xpub661MyMwAqRbcF... (Standard Decoy Keystore)",
                "Filesystem Artifacts": [c.target for c in changes if c.kind == "FILE"]
            }
        })

    elif primitive == "PLANT_DECOY_PRIVATE_KEYS":
        explanation.update({
            "title": "Synthetic OpenSSH Keypair",
            "summary": "Deployed synthetic 2048-bit RSA private key file to user SSH configuration directory.",
            "artifacts": {
                "Key Type": "OpenSSH RSA Private Key (PEM format)",
                "Path": "%USERPROFILE%\\.ssh\\id_rsa",
                "Filesystem Artifacts": [c.target for c in changes if c.kind == "FILE"]
            }
        })

    elif primitive == "PLANT_DECOY_CLOUD_CREDENTIALS":
        explanation.update({
            "title": "Synthetic Cloud Access Credentials",
            "summary": "Deployed mock AWS IAM access key credentials to user profile cloud CLI configuration.",
            "artifacts": {
                "Cloud Provider": "Amazon Web Services (AWS)",
                "File Path": "%USERPROFILE%\\.aws\\credentials",
                "Access Key ID": "AKIAIOSFODNN7EXAMPLE",
                "Secret Access Key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "Filesystem Artifacts": [c.target for c in changes if c.kind == "FILE"]
            }
        })

    elif primitive == "SPOOF_HARDWARE_IDENTITY" or primitive == "HIDE_VM_ARTIFACTS":
        explanation.update({
            "title": "Hardware Identity & BIOS Masking",
            "summary": "Rewrote hypervisor BIOS and GPU registry keys to emulate a physical Dell Precision workstation.",
            "artifacts": {
                "Spoofed System BIOS": "DELL - 1072009 (American Megatrends Inc. 50011)",
                "Spoofed Video BIOS": "NVIDIA Quadro P2000 VGA BIOS",
                "Registry Targets": [c.target for c in changes if c.kind == "REGISTRY"]
            }
        })

    elif primitive == "SIMULATE_AV_PRESENCE":
        explanation.update({
            "title": "Antivirus Presence Simulation",
            "summary": "Configured Windows Defender product status and security center active flags.",
            "artifacts": {
                "Product": "Microsoft Windows Defender",
                "ProductStatus": "1 (Active & Up-to-Date)",
                "Registry Targets": [c.target for c in changes if c.kind == "REGISTRY"]
            }
        })

    elif primitive == "FABRICATE_C2_RESPONSE":
        explanation.update({
            "title": "Synthetic C2 Response Channel",
            "summary": "Synthesized realistic HTTP C2 tasking payload and check-in acknowledgement.",
            "artifacts": {
                "C2 Protocol": "HTTP / JSON REST",
                "Channel Target": "c2_channel:dynamic_http",
                "Injected Response": "HTTP/1.1 200 OK - Task: PING_ACK",
                "Network Changes": [c.target for c in changes if c.kind == "NETWORK"]
            }
        })

    elif primitive == "ACTIVATE_C2_SINKHOLE":
        explanation.update({
            "title": "Active C2 Telemetry Sinkhole",
            "summary": "Redirected outbound malicious network flows and DGA host queries to local sandbox telemetry listener.",
            "artifacts": {
                "Sinkhole Target": "127.0.0.1:8443",
                "Firewall Rule": "Redirect all non-local egress to telemetry probe",
                "Network Changes": [c.target for c in changes if c.kind == "NETWORK"]
            }
        })

    elif primitive == "CREATE_DECOY_RECOVERY_TARGET":
        explanation.update({
            "title": "Synthetic Volume Shadow Recovery Target",
            "summary": "Instantiated mock shadow volume target to safely absorb ransomware deletion commands.",
            "artifacts": {
                "Target Path": "C:\\SystemRecovery\\DecoyBackups\\shadow_volume_copy_01.vhd",
                "Storage State": "Active Simulated Shadow Volume",
                "Filesystem Artifacts": [c.target for c in changes if c.kind == "FILE"]
            }
        })

    elif primitive == "SYNTHESIZE_RDP_TARGETS":
        explanation.update({
            "title": "Synthetic RDP Server Targets",
            "summary": "Injected Most Recently Used (MRU) Terminal Server client connection entries.",
            "artifacts": {
                "MRU Target": "10.0.0.50:3389 (Internal App Server)",
                "Registry Targets": [c.target for c in changes if c.kind == "REGISTRY"]
            }
        })

    elif primitive == "SPAWN_DECOY_PROCESSES":
        explanation.update({
            "title": "Decoy Background Processes",
            "summary": "Spawned realistic enterprise user background processes (notepad, calc, browser).",
            "artifacts": {
                "Spawned Images": ["svchost.exe", "notepad.exe", "calc.exe"],
                "Process Changes": [c.target for c in changes if c.kind == "PROCESS"]
            }
        })

    elif primitive == "SYNTHESIZE_USER_PROFILE":
        explanation.update({
            "title": "Synthetic User Profile Activity",
            "summary": "Generated corporate operations memos and recent document history in user profile.",
            "artifacts": {
                "Profile Documents": ["%USERPROFILE%\\Documents\\Q4_Team_Memo.docx"],
                "Filesystem Artifacts": [c.target for c in changes if c.kind == "FILE"]
            }
        })

    elif primitive == "SYNTHESIZE_SOFTWARE_INVENTORY":
        explanation.update({
            "title": "Synthetic Software Inventory",
            "summary": "Populated Windows Uninstall registry keys with standard enterprise software suites.",
            "artifacts": {
                "Installed Suite": "Global Enterprise Suite 2026",
                "Registry Targets": [c.target for c in changes if c.kind == "REGISTRY"]
            }
        })

    elif "MEASUREMENT" in [c.kind for c in changes] or primitive.startswith("ACTIVATE_") or primitive.startswith("ENABLE_") or primitive.startswith("PRESERVE_"):
        explanation.update({
            "title": f"Observation Measurement: {primitive}",
            "summary": "Activated hypervisor / kernel deep observation primitive to preserve forensic telemetry.",
            "artifacts": {
                "Measurement Type": primitive,
                "Hypervisor Hook": "Extended Page Table (EPT) Dirty-Page Monitor",
                "Telemetry Integrity": "100% (Observation Preserved)"
            }
        })

    return explanation
