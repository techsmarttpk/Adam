"""Dynamic OS & Hardware Fingerprint Spoofing Engine.

Dynamically alters BIOS identifiers, CPU core topologies, hypervisor flags,
and ACPI tables to defeat anti-virtualization and VM-detection checks (e.g. RedPill, NoPill).
"""

from __future__ import annotations
import dataclasses
import random
from typing import Dict, List, Optional


@dataclasses.dataclass
class HardwareProfile:
    profile_id: str
    manufacturer: str
    model: str
    bios_version: str
    bios_date: str
    cpu_model: str
    cpu_cores: int
    ram_gb: int
    mac_address: str
    disk_serial: str
    hypervisor_present_bit: bool = False


class DynamicFingerprintEngine:
    """Spoofs and rotates system hardware profiles to defeat VM detection."""

    REALISTIC_PROFILES = [
        HardwareProfile(
            profile_id="dell_optiplex_7090",
            manufacturer="Dell Inc.",
            model="OptiPlex 7090",
            bios_version="1.14.0",
            bios_date="04/18/2023",
            cpu_model="11th Gen Intel(R) Core(TM) i7-11700 @ 2.50GHz",
            cpu_cores=8,
            ram_gb=16,
            mac_address="F8:DB:88:21:44:9A",
            disk_serial="S4EVNF0R123456",
            hypervisor_present_bit=False,
        ),
        HardwareProfile(
            profile_id="hp_elitebook_840",
            manufacturer="HP",
            model="HP EliteBook 840 G8",
            bios_version="T76 Ver. 01.11.00",
            bios_date="11/02/2023",
            cpu_model="11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz",
            cpu_cores=4,
            ram_gb=16,
            mac_address="94:E6:F7:3B:12:88",
            disk_serial="W301A87Z19942",
            hypervisor_present_bit=False,
        ),
        HardwareProfile(
            profile_id="lenovo_thinkpad_t14",
            manufacturer="LENOVO",
            model="ThinkPad T14 Gen 2",
            bios_version="N34ET52W (1.52 )",
            bios_date="08/22/2024",
            cpu_model="AMD Ryzen 7 PRO 5850U with Radeon Graphics",
            cpu_cores=8,
            ram_gb=32,
            mac_address="48:2A:E3:6C:55:01",
            disk_serial="NVME_S5G2NE0M987654",
            hypervisor_present_bit=False,
        ),
    ]

    def __init__(self, seed: Optional[int] = None) -> None:
        self.rng = random.Random(seed)
        self.active_profile = self.REALISTIC_PROFILES[0]

    def rotate_profile(self) -> HardwareProfile:
        """Rotates active hardware profile."""
        self.active_profile = self.rng.choice(self.REALISTIC_PROFILES)
        return self.active_profile

    def get_cpuid_leaf_0x1_ecx(self) -> int:
        """Bit 31 is the hypervisor present bit. Return 0 to indicate bare metal."""
        # Clean bare-metal bit 31
        return 0x7FFAFBBF & ~(1 << 31)

    def get_smbios_tables(self) -> Dict[str, str]:
        p = self.active_profile
        return {
            "SystemManufacturer": p.manufacturer,
            "SystemProductName": p.model,
            "BIOSVersion": p.bios_version,
            "BIOSReleaseDate": p.bios_date,
            "ProcessorVersion": p.cpu_model,
            "NumberOfCores": str(p.cpu_cores),
            "PhysicalMemorySizeGB": str(p.ram_gb),
            "DiskDriveSerialNumber": p.disk_serial,
            "NetworkAdapterMAC": p.mac_address,
        }
