from __future__ import annotations

from ..models import RawEvent, SemanticEvent
from .base import BaseDetector


class LateralMovementDetector(BaseDetector):
    """
    Detects lateral movement across hosts.

    MITRE ATT&CK:
        T1021 - Remote Services
    """

    TECHNIQUE_ID = "T1021"

    STRONG_INDICATORS = [
        "psexec.exe",
        "wmic process call create",
        "winrs",
        "mstsc.exe",
        "invoke-command",
    ]

    MEDIUM_INDICATORS = [
        "\\\\",
        "net use",
        "admin$",
        "c$",
        "copy-item",
        "sc.exe \\\\",
    ]

    WEAK_INDICATORS = [
        "remote desktop",
        "rpc",
        "smb",
        "wmi",
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
            category="Lateral Movement",
            technique_id=self.TECHNIQUE_ID,
            severity="HIGH",
            confidence=0.91,
            description="Potential lateral movement activity detected.",
            evidence=matched,
        )