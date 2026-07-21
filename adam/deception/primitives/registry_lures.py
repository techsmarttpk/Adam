"""
Registry/domain-identity lures. First concrete primitive: the
FakeDomainControllerDeception referenced throughout ARCHITECTURE.md
(§2.2 worked example, §7.5 sample MutationResult, §5.6.8 catalogue).
"""

from __future__ import annotations

from typing import Any

from adam.contracts.enums import ChangeKind
from adam.contracts.mutation import Change
from adam.deception.catalogue import register_primitive
from adam.deception.plausibility import combine, score_naming_consistency, score_timestamp_consistency
from adam.deception.primitives.base import DeceptionPrimitive


@register_primitive("SPAWN_FAKE_DC_ARTIFACTS")
class FakeDomainControllerDeception(DeceptionPrimitive):
    """
    Responds to RECON_DOMAIN_CONTROLLER by making the guest look like it's
    joined to a domain: a registry domain value, a SYSVOL share, and a DNS
    response for the fake DC hostname.

    Expected `parameters` (from PolicyDecision.parameters / RULE-014):
        domain_name: str   e.g. "CORP.LOCAL"
        dc_hostname: str   e.g. "DC01"
        netbios: str       e.g. "CORP"
        populate_sysvol: bool
    """

    name = "FakeDomainControllerDeception"
    version = "1.0"

    async def _build_changes(self, parameters: dict[str, Any]) -> list[Change]:
        domain = parameters["domain_name"]
        dc_host = parameters["dc_hostname"]

        changes = [
            Change(
                kind=ChangeKind.REGISTRY,
                target=r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain",
                operation="SET",
                value=domain,
            ),
            Change(
                kind=ChangeKind.NETWORK,
                target=f"dns:{dc_host}.{domain}",
                operation="RESPOND",
                value="10.0.0.10",
            ),
        ]
        if parameters.get("populate_sysvol", False):
            changes.append(
                Change(
                    kind=ChangeKind.FILE,
                    target=rf"C:\Windows\SYSVOL\sysvol\{domain}" + "\\",
                    operation="CREATE",
                    value=None,
                )
            )
        return changes

    def _plausibility(self, parameters: dict[str, Any]) -> tuple[float, str]:
        # Registry keys written mid-run are inherently a mild tell — a
        # timestamp-aware sample could notice the mtime is post-boot.
        ts_score = score_timestamp_consistency(is_post_boot_write=True)
        name_score = score_naming_consistency(matches_locale_convention=True)
        score = combine(ts_score, name_score)
        notes = (
            "Registry key mtime is post-boot; a timestamp-aware sample "
            "could detect this."
        )
        return score, notes
