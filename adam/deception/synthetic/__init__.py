"""AI-Driven Synthetic Deception and Environment Emulation Subsystem."""

from adam.deception.synthetic.user_simulator import UserSimulator, MouseTrajectoryPoint
from adam.deception.synthetic.decoys import SyntheticDecoyEngine, DecoyFile, DecoyRegistryKey
from adam.deception.synthetic.fingerprint import DynamicFingerprintEngine, HardwareProfile

__all__ = [
    "UserSimulator",
    "MouseTrajectoryPoint",
    "SyntheticDecoyEngine",
    "DecoyFile",
    "DecoyRegistryKey",
    "DynamicFingerprintEngine",
    "HardwareProfile",
]
