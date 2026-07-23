from __future__ import annotations
from typing import Any
from adam.contracts.enums import ChangeKind, MutationStatus
from adam.contracts.mutation import Change, MutationResult
from adam.deception.catalogue import register_primitive
from adam.deception.plausibility import combine, score_naming_consistency, score_timestamp_consistency
from adam.deception.primitives.base import DeceptionPrimitive

@register_primitive("MOUNT_FAKE_NETWORK_SHARE")
class MountFakeNetworkShare(DeceptionPrimitive):
    name = "MountFakeNetworkShare"
    version = "1.0"

    async def _build_changes(self, parameters: dict[str, Any]) -> list[Change]:
        return [
            Change(
                kind=ChangeKind.REGISTRY,
                target=r"HKCU\Network\Z",
                operation="SET",
                value=r"\\Server\Share"
            ),
            Change(
                kind=ChangeKind.NETWORK,
                target=r"\\Server\Share",
                operation="MOUNT",
                value="FakeShare"
            )
        ]

    def _plausibility(self, parameters: dict[str, Any]) -> tuple[float, str]:
        return 0.8, "Mounted fake network share"

    async def revert_async(self, mutation: MutationResult) -> MutationResult:
        for change in mutation.changes:
            if change.kind == ChangeKind.REGISTRY:
                await self._channel.apply_mutation(change.kind.value, change.target, "DELETE", None)
            elif change.kind == ChangeKind.NETWORK:
                await self._channel.apply_mutation(change.kind.value, change.target, "UNMOUNT", None)
        mutation.status = MutationStatus.REVERTED
        return mutation
