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

    async def apply_async(
        self, session_id: str, correlation_id: str, decision_id: str, parameters: dict[str, Any]
    ) -> MutationResult:
        """
        Overrides the base class to batch all FILE CREATE operations into a
        single PowerShell invocation via :meth:`GuestMutationChannel.apply_mutation_batch`.

        Eliminating 3 separate ``powershell.exe`` cold-starts (~11-14 s each)
        is the primary motivation: under detonation CPU load the sequential
        approach consistently exceeds the 30 s per-mutation timeout.  The
        batched script creates all 3 files in one process lifetime.

        Falls back to the per-file :meth:`~DeceptionPrimitive.apply_async` base
        implementation when the channel does not expose ``apply_mutation_batch``
        (e.g. plain ``AsyncMock`` in legacy unit tests or the VBox backend),
        preserving backward-compatibility without duplicating the status/error
        wiring logic.
        """
        import time as _time
        import uuid as _uuid

        start = _time.perf_counter()
        changes = await self._build_changes(parameters)

        try:
            batch_fn = getattr(self._channel, "apply_mutation_batch", None)
            if callable(batch_fn):
                # Fast path: one PowerShell process for all FILE CREATE changes.
                file_creates = [(c.target, c.value) for c in changes]
                await batch_fn(file_creates)
            else:
                # Fallback: sequential per-file calls (legacy channels / mocks).
                for change in changes:
                    await self._channel.apply_mutation(
                        change.kind.value, change.target, change.operation, change.value
                    )
            status = MutationStatus.APPLIED
            error = None
        except Exception as exc:  # noqa: BLE001 — isolation boundary (§14.3)
            status = MutationStatus.FAILED
            error = str(exc)

        score, notes = self._plausibility(parameters)
        latency_ms = (_time.perf_counter() - start) * 1000

        return MutationResult(
            mutation_id=f"mut_{_uuid.uuid4().hex[:12]}",
            session_id=session_id,
            correlation_id=correlation_id,
            decision_id=decision_id,
            primitive=f"{self.name}@{self.version}",
            status=status,
            latency_ms=latency_ms,
            changes=changes,
            plausibility_score=score,
            plausibility_notes=notes,
            revertible=True,
            error=error,
        )

    def _plausibility(self, parameters: dict[str, Any]) -> tuple[float, str]:
        ts_score = score_timestamp_consistency(is_post_boot_write=False)
        name_score = score_naming_consistency(matches_locale_convention=True)
        score = combine(ts_score, name_score)
        return score, "Varying mtimes on decoy documents"

    async def revert_async(self, mutation: MutationResult) -> MutationResult:
        for change in reversed(mutation.changes):
            await self._channel.apply_mutation(change.kind.value, change.target, "DELETE", None)
        mutation.status = MutationStatus.REVERTED
        return mutation



@register_primitive("PLANT_DECOY_WALLET")
class PlantDecoyWallet(DeceptionPrimitive):
    name = "PlantDecoyWallet"
    version = "1.0"

    async def _build_changes(self, parameters: dict[str, Any]) -> list[Change]:
        return [
            Change(
                kind=ChangeKind.FILE,
                target=r"C:\Users\Admin\AppData\Roaming\Bitcoin\wallet.dat",
                operation="CREATE",
                value="size=131072,timestamp=1000",
            ),
            Change(
                kind=ChangeKind.FILE,
                target=r"C:\Users\Admin\AppData\Roaming\Ethereum\keystore\utc_wallet.json",
                operation="CREATE",
                value="size=4096,timestamp=1050",
            ),
        ]

    def _plausibility(self, parameters: dict[str, Any]) -> tuple[float, str]:
        ts_score = score_timestamp_consistency(is_post_boot_write=False)
        name_score = score_naming_consistency(matches_locale_convention=True)
        score = combine(ts_score, name_score)
        return score, "Fake cryptocurrency wallet files planted with realistic sizes and timestamps"

    async def revert_async(self, mutation: MutationResult) -> MutationResult:
        for change in reversed(mutation.changes):
            await self._channel.apply_mutation(change.kind.value, change.target, "DELETE", None)
        mutation.status = MutationStatus.REVERTED
        return mutation
