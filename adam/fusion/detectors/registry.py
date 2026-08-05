from __future__ import annotations

from .base import BaseDetector
from .recon import ReconDetector
from .persistence import PersistenceDetector
from .credential_access import CredentialAccessDetector
from .defense_evasion import DefenseEvasionDetector
from .privilege_escalation import PrivilegeEscalationDetector
from .lateral_movement import LateralMovementDetector
from .collection import CollectionDetector
from .command_and_control import CommandAndControlDetector
from .exfiltration import ExfiltrationDetector
from .impact import ImpactDetector


class DetectorRegistry:
    """
    Stores and manages all available behavioral detectors.

    The Event Fusion Engine executes every detector registered here
    against each correlated group of events.

    To add a new detector:
        1. Import it.
        2. Register it below.
    """

    def __init__(self) -> None:
        self._detectors: list[BaseDetector] = []

        # --------------------------------------------------
        # Built-in Detectors
        # --------------------------------------------------

        self.register(ReconDetector())

        self.register(PersistenceDetector())

        self.register(CredentialAccessDetector())

        self.register(DefenseEvasionDetector())

        self.register(PrivilegeEscalationDetector())

        self.register(LateralMovementDetector())

        self.register(CollectionDetector())

        self.register(CommandAndControlDetector())

        self.register(ExfiltrationDetector())

        self.register(ImpactDetector())

    def register(self, detector: BaseDetector) -> None:
        """Register a detector."""
        self._detectors.append(detector)

    def unregister(self, detector: BaseDetector) -> None:
        """Remove a detector."""
        if detector in self._detectors:
            self._detectors.remove(detector)

    def clear(self) -> None:
        """Remove all registered detectors."""
        self._detectors.clear()

    def __iter__(self):
        return iter(self._detectors)

    def __len__(self):
        return len(self._detectors)