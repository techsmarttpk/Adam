"""Multi-Source Environment State and Cross-Source Consistency Engine.

Maintains coherent ground-truth state of the guest environment across:
1. Active Directory / Domain Architecture
2. Network Interfaces and DNS mappings
3. File System & Mapped SMB Shares
4. Registry Hives & Credentials
5. Security Services / AV Products
6. Active Process Layout & User Simulation

Calculates evidence-driven Plausibility Scores by verifying consistency across all 6 layers.
"""

from __future__ import annotations
import dataclasses
import time
from typing import Dict, List, Optional, Set, Tuple


@dataclasses.dataclass
class ConsistencyCheckResult:
    is_consistent: bool
    score: float  # 0.0 to 1.0
    layer: str  # REGISTRY, DNS, FILESYSTEM, SMB, SERVICES, PROCESS
    discrepancies: List[str]
    evidence: Dict[str, object]


class EnvironmentStateModel:
    """Represents the multi-layered state of the guest operating system."""

    def __init__(self) -> None:
        # Layer 1: Domain & Identity
        self.domain_name: Optional[str] = None
        self.primary_dc_hostname: Optional[str] = None
        self.netbios_name: Optional[str] = None

        # Layer 2: Network & DNS
        self.dns_hosts_entries: Dict[str, str] = {}  # hostname -> ip
        self.listening_ports: Set[int] = set()

        # Layer 3: File System & Shares
        self.existing_paths: Set[str] = set()
        self.mounted_smb_shares: Dict[str, str] = {}  # share_name -> local_path

        # Layer 4: Registry Hives
        self.registry_keys: Dict[str, str] = {}  # key_path -> value

        # Layer 5: Security Products
        self.active_security_products: Dict[str, bool] = {}  # "Defender": True

        # Layer 6: Processes & User State
        self.running_processes: Set[str] = set()
        self.user_active: bool = False

    def update_from_mutation(self, action: str, parameters: Dict[str, object]) -> None:
        """Updates environment state model based on an applied mutation."""
        if action == "SPAWN_FAKE_DC_ARTIFACTS":
            domain = str(parameters.get("domain_name", "CORP.LOCAL"))
            dc = str(parameters.get("dc_hostname", "DC01"))
            self.domain_name = domain
            self.primary_dc_hostname = f"{dc}.{domain}"
            self.netbios_name = domain.split(".")[0]
            self.dns_hosts_entries[f"{dc}.{domain}"] = "10.0.0.10"
            self.registry_keys["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Domain"] = domain
            self.existing_paths.add(f"C:\\Windows\\SYSVOL\\sysvol\\{domain}")

        elif action == "MOUNT_FAKE_NETWORK_SHARE":
            share = str(parameters.get("share_name", "FinanceShare"))
            path = f"\\\\10.0.0.10\\{share}"
            self.mounted_smb_shares[share] = path
            self.existing_paths.add(path)

        elif action == "SIMULATE_AV_PRESENCE":
            self.active_security_products["Windows Defender"] = True
            self.registry_keys["HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\ProductStatus"] = "1"
            self.running_processes.add("MsMpEng.exe")

        elif action == "PLANT_DECOY_DOCUMENTS":
            doc_path = str(parameters.get("file_path", "C:\\Users\\Analyst\\Documents\\payroll_2026.xlsx"))
            self.existing_paths.add(doc_path)


class CrossSourceConsistencyChecker:
    """Verifies that synthetic environmental mutations maintain cross-source coherence."""

    @staticmethod
    def evaluate_mutation_plausibility(
        state: EnvironmentStateModel,
        action: str,
        parameters: Dict[str, object],
    ) -> ConsistencyCheckResult:
        """Evaluates whether an action would create an observable contradiction in the guest."""
        discrepancies: List[str] = []
        layer = "SYSTEM"
        score = 1.0

        if action == "SPAWN_FAKE_DC_ARTIFACTS":
            layer = "DOMAIN_NETWORK"
            domain = str(parameters.get("domain_name", "CORP.LOCAL"))
            dc = str(parameters.get("dc_hostname", "DC01"))
            expected_host = f"{dc}.{domain}"

            # Check 1: DNS/Hosts must match registry domain
            if state.dns_hosts_entries and expected_host not in state.dns_hosts_entries:
                discrepancies.append(f"Domain set to {domain} but no DNS/hosts resolution entry for {expected_host}")
                score -= 0.25

            # Check 2: SYSVOL directory structure check
            sysvol_path = f"C:\\Windows\\SYSVOL\\sysvol\\{domain}"
            if state.existing_paths and sysvol_path not in state.existing_paths:
                discrepancies.append(f"SYSVOL directory missing for domain {domain}")
                score -= 0.15

        elif action == "MOUNT_FAKE_NETWORK_SHARE":
            layer = "SMB_FILESYSTEM"
            share = str(parameters.get("share_name", "FinanceShare"))
            # If domain controller exists, share must point to active DC or mapped subnet
            if state.domain_name and "10.0.0.10" not in str(state.mounted_smb_shares.get(share, "")):
                discrepancies.append("Share host IP does not match domain controller subnet topology.")
                score -= 0.2

        elif action == "SIMULATE_AV_PRESENCE":
            layer = "SERVICES_REGISTRY"
            # Registry flag without running security service or process is a tell
            if "MsMpEng.exe" not in state.running_processes and not state.active_security_products.get("Windows Defender"):
                discrepancies.append("Defender registry key set but MsMpEng service process not running.")
                score -= 0.3

        score = max(0.1, min(1.0, score))
        return ConsistencyCheckResult(
            is_consistent=(len(discrepancies) == 0),
            score=round(score, 2),
            layer=layer,
            discrepancies=discrepancies,
            evidence={
                "action": action,
                "domain": state.domain_name,
                "hosts": list(state.dns_hosts_entries.keys()),
                "shares": list(state.mounted_smb_shares.keys()),
            },
        )
