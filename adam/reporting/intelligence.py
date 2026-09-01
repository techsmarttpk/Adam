"""Threat Intelligence Synthesis Engine: Dynamic YARA Rule Generator and STIX 2.1 Exporter.

Packages extracted C2 URLs, IP addresses, DGA seeds, mutexes, and unpacked memory payloads
into standardized STIX 2.1 bundles and auto-generated YARA signatures for enterprise SIEM/SOAR ingestion.
"""

from __future__ import annotations
import dataclasses
import hashlib
import json
import time
from typing import Dict, List, Optional


@dataclasses.dataclass
class ThreatArtifact:
    artifact_type: str  # C2_DOMAIN, C2_IP, MUTEX, REGISTRY, PAYLOAD_HASH, UNPACKED_CODE
    value: str
    confidence: float
    description: str


class ThreatIntelligenceSynthesizer:
    """Synthesizes YARA rules and STIX 2.1 / MISP intelligence bundles from sandbox execution."""

    def __init__(self, session_id: str = "sess_001") -> None:
        self.session_id = session_id
        self.artifacts: List[ThreatArtifact] = []

    def record_artifact(
        self, artifact_type: str, value: str, confidence: float = 0.9, description: str = ""
    ) -> ThreatArtifact:
        art = ThreatArtifact(
            artifact_type=artifact_type,
            value=value,
            confidence=confidence,
            description=description,
        )
        self.artifacts.append(art)
        return art

    def generate_yara_rule(self, rule_name: str, payload_bytes: Optional[bytes] = None) -> str:
        """Generates dynamic YARA detection rule targeting extracted memory payloads & mutexes."""
        safe_rule_name = "".join(c if c.isalnum() else "_" for c in rule_name)
        timestamp = time.strftime("%Y-%m-%d")

        strings_section = []
        condition_terms = []

        # Add string patterns from discovered mutexes / domains
        for i, art in enumerate(self.artifacts):
            if art.artifact_type in ("MUTEX", "C2_DOMAIN", "REGISTRY"):
                var_name = f"$str_{i}"
                strings_section.append(f'        {var_name} = "{art.value}" ascii wide')
                condition_terms.append(var_name)

        # Add hex byte signature if payload was extracted
        if payload_bytes and len(payload_bytes) >= 16:
            hex_slice = " ".join(f"{b:02x}" for b in payload_bytes[:16])
            strings_section.append(f'        $payload_hex = {{ {hex_slice} }}')
            condition_terms.append("$payload_hex")

        if not strings_section:
            strings_section.append('        $dummy = "adam_autonomous_detection"')
            condition_terms.append("$dummy")

        cond_str = " or ".join(condition_terms) if condition_terms else "all of them"

        yara_text = f"""rule ADAM_Evolved_{safe_rule_name} {{
    meta:
        description = "Auto-generated YARA rule from ADAM Self-Evolving Sandbox session {self.session_id}"
        author = "ADAM Autonomous AMTD Forensics"
        date = "{timestamp}"
        confidence = "HIGH"
    strings:
{chr(10).join(strings_section)}
    condition:
        {cond_str}
}}
"""
        return yara_text

    def export_stix21_bundle(self) -> Dict[str, object]:
        """Exports IOCs in standard STIX 2.1 JSON bundle format."""
        bundle_id = f"bundle--{hashlib.md5(f'stix:{self.session_id}'.encode()).hexdigest()}"
        stix_objects: List[Dict[str, object]] = []

        # Create Report SDO
        report_id = f"report--{hashlib.md5(f'rep:{self.session_id}'.encode()).hexdigest()}"
        report_sdo = {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "name": f"ADAM Autonomous Analysis Report - {self.session_id}",
            "description": "Extracted Indicators of Compromise from real-time AMTD kernel mutation",
            "published": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "object_refs": [],
        }

        for i, art in enumerate(self.artifacts):
            ind_id = f"indicator--{hashlib.md5(f'ind:{self.session_id}:{i}'.encode()).hexdigest()}"
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "name": f"Extracted {art.artifact_type}: {art.value}",
                "description": art.description,
                "pattern": f"[{art.artifact_type.lower()}:value = '{art.value}']",
                "pattern_type": "stix",
                "confidence": int(art.confidence * 100),
            }
            stix_objects.append(indicator)
            report_sdo["object_refs"].append(ind_id)

        stix_objects.insert(0, report_sdo)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": stix_objects,
        }
