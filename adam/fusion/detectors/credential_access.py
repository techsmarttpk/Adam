from __future__ import annotations

from ..models import RawEvent, SemanticEvent
from .base import BaseDetector


class CredentialAccessDetector(BaseDetector):
    """
    Detects OS credential dumping behaviour.

    MITRE ATT&CK:
        T1003 - OS Credential Dumping
    """

    TECHNIQUE_ID = "T1003"


    RULES = [
        (
            5,
            [
                "mimikatz.exe",
                "invoke-mimikatz",
                "minidumpwritedump",
            ],
        ),
        (
            3,
            [
                "procdump.exe",
                "lsass.exe",
                "comsvcs.dll",
                "reg save hklm\\sam",
                "reg save hklm\\system",
            ],
        ),
        (
            2,
            [
                "sekurlsa",
                "privilege::debug",
                "lsadump",
            ],
        ),
    ]

    STRONG_INDICATORS = RULES[0][1]
    MEDIUM_INDICATORS = RULES[1][1]
    WEAK_INDICATORS = RULES[2][1]

    SCORE_THRESHOLD = 6

    def match(self, events):
        score, matched = self.score_events(events)
        if score >= self.SCORE_THRESHOLD:
            return matched
        return None

    def build(self, matched: list[RawEvent]) -> SemanticEvent:

        return SemanticEvent(
            timestamp=matched[0].timestamp,
            category="Credential Access",
            technique_id=self.TECHNIQUE_ID,
            severity="HIGH",
            confidence=0.94,
            description="Potential OS credential dumping detected.",
            evidence=matched,
        )