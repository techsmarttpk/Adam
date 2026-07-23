from __future__ import annotations
from typing import Any
from adam.contracts.enums import ChangeKind, MutationStatus
from adam.contracts.mutation import Change, MutationResult
from adam.deception.catalogue import register_primitive
from adam.deception.plausibility import combine, score_naming_consistency, score_timestamp_consistency
from adam.deception.primitives.base import DeceptionPrimitive

@register_primitive("SIMULATE_AV_PRESENCE")
class SimulateAVPresence(DeceptionPrimitive):
    name = "SimulateAVPresence"
    version = "1.0"

    async def _build_changes(self, parameters: dict[str, Any]) -> list[Change]:
        return [
            Change(
                kind=ChangeKind.PROCESS,
                target="avp.exe",
                operation="CREATE",
                value="dummy_av_process"
            ),
            Change(
                kind=ChangeKind.REGISTRY,
                target=r"HKLM\SOFTWARE\KasperskyLab\AVP6",
                operation="SET",
                value="Installed"
            )
        ]

    def _plausibility(self, parameters: dict[str, Any]) -> tuple[float, str]:
        ts_score = score_timestamp_consistency(is_post_boot_write=True)
        name_score = score_naming_consistency(matches_locale_convention=True)
        score = combine(ts_score, name_score)
        return score, "AV presence simulated via process and registry"

    async def revert_async(self, mutation: MutationResult) -> MutationResult:
        for change in reversed(mutation.changes):
            if change.kind == ChangeKind.PROCESS:
                await self._channel.apply_mutation(change.kind.value, change.target, "TERMINATE", None)
            elif change.kind == ChangeKind.REGISTRY:
                await self._channel.apply_mutation(change.kind.value, change.target, "DELETE", None)
        mutation.status = MutationStatus.REVERTED
        return mutation


@register_primitive("ACCELERATE_SYSTEM_CLOCK")
class AccelerateSystemClock(DeceptionPrimitive):
    """
    Accelerates the guest OS system time to bypass malware sleep/delay execution.
    
    NOTE ON REVERT: Unlike discrete file/registry changes, accelerating continuous
    guest time cannot be undone by deleting artifacts. Reverting here means resetting
    or resynchronizing the system clock back to real host time (or NTP sync).
    """
    name = "AccelerateSystemClock"
    version = "1.0"

    async def _build_changes(self, parameters: dict[str, Any]) -> list[Change]:
        return [
            Change(
                kind=ChangeKind.PROCESS,
                target="system_clock",
                operation="SET",
                value="fast_forward_3600s",
            )
        ]

    def _plausibility(self, parameters: dict[str, Any]) -> tuple[float, str]:
        ts_score = score_timestamp_consistency(is_post_boot_write=True)
        name_score = score_naming_consistency(matches_locale_convention=True)
        score = combine(ts_score, name_score)
        return score, "Accelerated guest system clock to bypass sleep evasion"

    async def revert_async(self, mutation: MutationResult) -> MutationResult:
        for change in reversed(mutation.changes):
            await self._channel.apply_mutation(change.kind.value, change.target, "RESET", "resync_host_time")
        mutation.status = MutationStatus.REVERTED
        return mutation
