from __future__ import annotations
from typing import Any
from adam.contracts.enums import ChangeKind, MutationStatus
from adam.contracts.mutation import Change, MutationResult
from adam.deception.catalogue import register_primitive
from adam.deception.plausibility import combine, score_naming_consistency, score_timestamp_consistency
from adam.deception.primitives.base import DeceptionPrimitive

@register_primitive("HIDE_VM_ARTIFACTS")
class HideVMArtifacts(DeceptionPrimitive):
    name = "HideVMArtifacts"
    version = "1.0"

    async def _build_changes(self, parameters: dict[str, Any]) -> list[Change]:
        return [
            Change(
                kind=ChangeKind.REGISTRY,
                target=r"HKLM\HARDWARE\DESCRIPTION\System\VideoBiosVersion",
                operation="MASK",
                value="VirtualBox"
            )
        ]

    def _plausibility(self, parameters: dict[str, Any]) -> tuple[float, str]:
        return 0.9, "Masked VirtualBox artifacts"

    async def revert_async(self, mutation: MutationResult) -> MutationResult:
        for change in mutation.changes:
            await self._channel.apply_mutation(change.kind.value, change.target, "UNMASK", change.value)
        mutation.status = MutationStatus.REVERTED
        return mutation
