from __future__ import annotations

from ..models import RawEvent, SemanticEvent
from .base import BaseDetector


class CollectionDetector(BaseDetector):
    """
    Detects collection of sensitive files and information.

    MITRE ATT&CK:
        T1005 - Data from Local System
    """

    TECHNIQUE_ID = "T1005"

    STRONG_INDICATORS = [
        "copy-item",
        "robocopy",
        "xcopy",
        "esentutl",
        "7z.exe",
        "rar.exe",
    ]

    MEDIUM_INDICATORS = [
        "documents",
        "desktop",
        "downloads",
        "finance",
        "confidential",
        "backup",
        "archive",
    ]

    WEAK_INDICATORS = [
        ".docx",
        ".xlsx",
        ".pdf",
        ".pptx",
        ".zip",
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
            category="Collection",
            technique_id=self.TECHNIQUE_ID,
            severity="MEDIUM",
            confidence=0.89,
            description="Potential collection of sensitive data detected.",
            evidence=matched,
        )