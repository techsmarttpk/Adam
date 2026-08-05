from datetime import datetime

from .base import BaseDetector
from ..models import SemanticEvent


class PersistenceDetector(BaseDetector):
    """
    Detects common Windows persistence mechanisms.
    MITRE ATT&CK: T1547 - Boot or Logon Autostart Execution
    """

    REGISTRY_RUN_KEYS = [
        r"currentversion\run",
        r"currentversion\runonce"
    ]

    def match(self, events):
        matched = []

        for event in events:
            process = (event.process_name or "").lower()

            command = (
                event.payload.get("command_line", "")
                if event.payload else ""
            ).lower()

            # Registry Run Keys
            if process == "reg.exe":
                if any(key in command for key in self.REGISTRY_RUN_KEYS):
                    matched.append(event)

            # Scheduled Tasks
            elif process == "schtasks.exe":
                matched.append(event)

            # Windows Service Creation
            elif process == "sc.exe":
                if "create" in command:
                    matched.append(event)

        return matched if matched else None

    def build(self, events):

        evidence = []

        for event in events:
            evidence.append({
                "timestamp": event.timestamp.isoformat(),
                "process": event.process_name,
                "command": event.payload.get("command_line", "")
            })

        return SemanticEvent(
            timestamp=datetime.utcnow(),
            category="Persistence",
            technique_id="T1547",
            severity="MEDIUM",
            confidence=0.88,
            description="Possible persistence mechanism detected.",
            evidence=events
    )