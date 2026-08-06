from __future__ import annotations

from ..models import RawEvent, SemanticEvent
from .base import BaseDetector


class ImpactDetector(BaseDetector):
    """
    Detects destructive or ransomware-like behaviour.

    MITRE ATT&CK:
        T1486 - Data Encrypted for Impact
    """

    TECHNIQUE_ID = "T1486"

    STRONG_INDICATORS = [
        "vssadmin delete shadows",
        "cipher /w",
        "bcdedit",
        "wbadmin delete catalog",
        "encryptor.exe",
    ]

    MEDIUM_INDICATORS = [
        ".locked",
        ".encrypted",
        ".crypt",
        "ransom",
        "delete shadows",
    ]

    WEAK_INDICATORS = [
        "rename",
        "overwrite",
        "wipe",
        "format",
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
            category="Impact",
            technique_id=self.TECHNIQUE_ID,
            severity="CRITICAL",
            confidence=0.96,
            description="Potential destructive or ransomware activity detected.",
            evidence=matched,
        )