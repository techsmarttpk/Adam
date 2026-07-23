from __future__ import annotations
from typing import Any
import random
import uuid
from adam.contracts.enums import ChangeKind, MutationStatus
from adam.contracts.mutation import Change, MutationResult
from adam.deception.catalogue import register_primitive
from adam.deception.plausibility import combine, score_naming_consistency, score_timestamp_consistency
from adam.deception.primitives.base import DeceptionPrimitive

@register_primitive("PLANT_DECOY_DOCUMENTS")
class PlantDecoyDocuments(DeceptionPrimitive):
    name = "PlantDecoyDocuments"
    version = "1.0"

    async def _build_changes(self, parameters: dict[str, Any]) -> list[Change]:
        changes = []
        for i in range(3):
            filename = f"passwords_{uuid.uuid4().hex[:4]}.txt"
            changes.append(Change(
                kind=ChangeKind.FILE,
                target=rf"C:\Users\Admin\Documents\{filename}",
                operation="CREATE",
                value=f"timestamp={1000 + i}"
            ))
        return changes

    def _plausibility(self, parameters: dict[str, Any]) -> tuple[float, str]:
        return 0.9, "Varying mtimes on decoy documents"

    async def revert_async(self, mutation: MutationResult) -> MutationResult:
        for change in mutation.changes:
            await self._channel.apply_mutation(change.kind.value, change.target, "DELETE", None)
        mutation.status = MutationStatus.REVERTED
        return mutation
