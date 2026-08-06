from __future__ import annotations

from datetime import datetime

from .base import BaseDetector
from ..models import SemanticEvent


class ReconDetector(BaseDetector):

    RECON_COMMANDS = {
        "whoami.exe",
        "hostname.exe",
        "ipconfig.exe",
        "systeminfo.exe",
        "tasklist.exe",
        "net.exe",
        "wmic.exe",
        "arp.exe",
        "route.exe",
        "netstat.exe",
    }

    MIN_COMMANDS = 3

    def match(self, events):

        matched = []
        seen = set()

        for event in events:

            if event.process_name in self.RECON_COMMANDS:
                matched.append(event)
                seen.add(event.process_name)

        if len(seen) >= self.MIN_COMMANDS:
            return matched

        return None

    def build(self, events):

        return SemanticEvent(
        timestamp=datetime.now(),

        category="Reconnaissance",

        technique_id="T1082",

        severity="LOW",

        confidence=0.80,

        description="Multiple system discovery commands detected.",

        evidence=events,
    )