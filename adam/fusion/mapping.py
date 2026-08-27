"""
Mapping utilities for translating Fusion Engine detections into policy intents.
"""

from __future__ import annotations

from typing import Any


def map_detection_to_intent(detection: Any) -> tuple[str, str, str]:
    """
    Dynamically maps a fusion engine detection to a specific policy intent, tactic, and technique.
    """
    tid = getattr(detection, "technique_id", "T1082")
    evidence = getattr(detection, "evidence", [])
    evidence_text = " ".join(
        (getattr(ev, "command_line", "") or "") + " " + (getattr(ev, "process_name", "") or "")
        for ev in evidence
    ).lower()

    if tid == "T1071":
        return ("C2_BEACON", "TA0011", "T1071")
    elif tid == "T1547":
        return ("PERSIST_RUN_KEY", "TA0003", "T1547")
    elif tid == "T1003":
        if "wallet" in evidence_text or "exodus" in evidence_text or "crypto" in evidence_text:
            return ("CRED_WALLET_SEARCH", "TA0006", "T1003")
        else:
            return ("CRED_BROWSER_STORE", "TA0006", "T1003")
    elif tid == "T1562":
        if "sleep" in evidence_text or "timeout" in evidence_text:
            return ("EVADE_SLEEP_SKIP", "TA0005", "T1562")
        else:
            return ("EVADE_SANDBOX_DETECTED", "TA0005", "T1562")
    elif tid == "T1082":  # Reconnaissance
        if "domain" in evidence_text or "ldap" in evidence_text:
            return ("RECON_DOMAIN_CONTROLLER", "TA0007", "T1082")
        elif "av" in evidence_text or "windefend" in evidence_text or "security" in evidence_text:
            return ("RECON_INSTALLED_AV", "TA0007", "T1082")
        elif "vm" in evidence_text or "virtual" in evidence_text or "vbox" in evidence_text:
            return ("RECON_VIRTUALISATION", "TA0007", "T1082")
        elif "share" in evidence_text or "net view" in evidence_text:
            return ("RECON_NETWORK_SHARES", "TA0007", "T1082")
        elif "uptime" in evidence_text or "systeminfo" in evidence_text:
            return ("RECON_SYSTEM_UPTIME", "TA0007", "T1082")
        elif "debug" in evidence_text or "windbg" in evidence_text:
            return ("RECON_DEBUGGER", "TA0007", "T1082")
        else:
            return ("RECON_USER_ARTIFACTS", "TA0007", "T1082")
    else:
        return ("RECON_USER_ARTIFACTS", "TA0007", str(tid))
