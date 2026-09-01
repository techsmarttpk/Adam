"""Synthetic Decoy Engine for High-Value Files, Browser History, and Registry Lures.

Generates realistic honeypot files, canary tokens, recent documents, and browser histories.
Monitors tripwire access events when evasive malware probes files or credential caches.
"""

from __future__ import annotations
import dataclasses
import hashlib
import time
from typing import Dict, List, Optional, Set


@dataclasses.dataclass
class DecoyFile:
    file_path: str
    file_type: str  # PDF, DOCX, XLSX, WALLET, SSH_KEY, CONFIG
    size_bytes: int
    canary_token: str
    tripwire_triggered: bool = False
    access_count: int = 0


@dataclasses.dataclass
class DecoyRegistryKey:
    key_path: str
    value_name: str
    value_data: str
    canary_token: str
    tripwire_triggered: bool = False


class SyntheticDecoyEngine:
    """Provisions and monitors high-value honey files and registry lures."""

    DEFAULT_FILES = [
        ("C:\\Users\\Analyst\\Desktop\\Financial_Report_Q3.xlsx", "XLSX"),
        ("C:\\Users\\Analyst\\Documents\\VPN_Credentials_2026.docx", "DOCX"),
        ("C:\\Users\\Analyst\\.ssh\\id_rsa", "SSH_KEY"),
        ("C:\\Users\\Analyst\\AppData\\Roaming\\Bitcoin\\wallet.dat", "WALLET"),
        ("C:\\Users\\Analyst\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", "CONFIG"),
        ("C:\\Users\\Analyst\\Desktop\\Corporate_Passcodes.pdf", "PDF"),
    ]

    DEFAULT_REGISTRY_LURES = [
        ("HKCU\\Software\\WinSCP\\Sessions\\Default%20Server", "Password", "canary_enc_pass_12345"),
        ("HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\\ProdBastion", "HostName", "bastion.internal-corp.net"),
        ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "OneDriveSync", "C:\\Windows\\System32\\onedrivesync.exe"),
    ]

    def __init__(self, session_id: str = "sess_001") -> None:
        self.session_id = session_id
        self.files: Dict[str, DecoyFile] = {}
        self.registry_lures: Dict[str, DecoyRegistryKey] = {}
        self.triggered_alerts: List[Dict[str, object]] = []
        self._seed_default_decoys()

    def _seed_default_decoys(self) -> None:
        for path, ftype in self.DEFAULT_FILES:
            token = hashlib.sha256(f"{self.session_id}:{path}".encode()).hexdigest()[:16]
            self.files[path] = DecoyFile(
                file_path=path,
                file_type=ftype,
                size_bytes=1024 * 12,
                canary_token=token,
            )

        for path, val_name, val_data in self.DEFAULT_REGISTRY_LURES:
            reg_id = f"{path}\\{val_name}"
            token = hashlib.sha256(f"{self.session_id}:{reg_id}".encode()).hexdigest()[:16]
            self.registry_lures[reg_id] = DecoyRegistryKey(
                key_path=path,
                value_name=val_name,
                value_data=val_data,
                canary_token=token,
            )

    def record_file_access(self, file_path: str, access_type: str = "READ") -> Optional[Dict[str, object]]:
        """Handles tripwire access to canary files."""
        if file_path in self.files:
            decoy = self.files[file_path]
            decoy.tripwire_triggered = True
            decoy.access_count += 1
            alert = {
                "timestamp_ns": time.perf_counter_ns(),
                "file_path": file_path,
                "file_type": decoy.file_type,
                "canary_token": decoy.canary_token,
                "access_type": access_type,
                "type": "TRIPWIRE_CANARY_FILE_TOUCHED",
            }
            self.triggered_alerts.append(alert)
            return alert
        return None

    def record_registry_access(self, key_path: str, value_name: str) -> Optional[Dict[str, object]]:
        """Handles tripwire access to canary registry keys."""
        reg_id = f"{key_path}\\{value_name}"
        if reg_id in self.registry_lures:
            lure = self.registry_lures[reg_id]
            lure.tripwire_triggered = True
            alert = {
                "timestamp_ns": time.perf_counter_ns(),
                "key_path": key_path,
                "value_name": value_name,
                "canary_token": lure.canary_token,
                "type": "TRIPWIRE_CANARY_REGISTRY_ACCESSED",
            }
            self.triggered_alerts.append(alert)
            return alert
        return None
