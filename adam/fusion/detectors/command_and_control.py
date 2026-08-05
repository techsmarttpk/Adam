from __future__ import annotations

from ..models import RawEvent, SemanticEvent
from .base import BaseDetector


class CommandAndControlDetector(BaseDetector):
    """
    Detects Command and Control activity.

    MITRE ATT&CK:
        T1071 - Application Layer Protocol
    """

    TECHNIQUE_ID = "T1071"

    STRONG_INDICATORS = [
        "curl http",
        "wget http",
        "powershell iwr",
        "powershell invoke-webrequest",
        "certutil -urlcache",
        "bitsadmin",
        "nc.exe",
        "netcat",
    ]

    MEDIUM_INDICATORS = [
        "http://",
        "https://",
        "ftp://",
        "dns",
        "beacon",
        "callback",
        "reverse shell",
    ]

    WEAK_INDICATORS = [
        "socket",
        "connect",
        "downloadstring",
        "webclient",
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
            category="Command and Control",
            technique_id=self.TECHNIQUE_ID,
            severity="HIGH",
            confidence=0.91,
            description="Potential command and control communication detected.",
            evidence=matched,
        )