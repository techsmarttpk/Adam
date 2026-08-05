from __future__ import annotations

from ..models import RawEvent, SemanticEvent
from .base import BaseDetector


class PrivilegeEscalationDetector(BaseDetector):
    """
    Detects privilege escalation behaviour.

    MITRE ATT&CK:
        T1068 - Exploitation for Privilege Escalation
    """

    TECHNIQUE_ID = "T1068"

    STRONG_INDICATORS = [
        "token::elevate",
        "getsystem",
        "seimpersonateprivilege",
        "juicypotato",
        "printspoofer",
    ]

    MEDIUM_INDICATORS = [
        "fodhelper.exe",
        "computerdefaults.exe",
        "eventvwr.exe",
        "uac bypass",
        "runas",
        "schtasks /create",
    ]

    WEAK_INDICATORS = [
        "elevate",
        "admin",
        "system",
        "bypass uac",
    ]

    SCORE_THRESHOLD = 6

    def match(self, events: list[RawEvent]) -> list[RawEvent] | None:

        score, matched = self.score_events(events)

        if score >= self.SCORE_THRESHOLD:
            return matched

        return None

    def build(self, matched: list[RawEvent]) -> SemanticEvent:

        return SemanticEvent(
            timestamp=matched[0].timestamp,
            category="Privilege Escalation",
            technique_id=self.TECHNIQUE_ID,
            severity="HIGH",
            confidence=0.92,
            description="Potential privilege escalation behaviour detected.",
            evidence=matched,
        )