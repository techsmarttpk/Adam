"""
DeceptionPrimitive — base class for every entry in the catalogue
(ARCHITECTURE.md §5.6, §7.8).

Every primitive must implement both apply() and revert(). Snapshot
rollback makes revert technically unnecessary for cleanup, but it's
required for ablation experiments (apply a lure, observe, withdraw it,
observe again) — build it in now, it costs a rewrite to add later.

A primitive NEVER calls VBoxManage or touches the guest directly — all
guest-side work goes through the injected ISandboxController (Pranav's
module). This keeps Deception testable without a VM.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from typing import Any, Protocol

from adam.contracts.enums import MutationStatus
from adam.contracts.interfaces import IDeception
from adam.contracts.mutation import Change, MutationResult


class GuestMutationChannel(Protocol):
    """
    The slice of ISandboxController (Pranav's module) a primitive needs.
    Defined here as a Protocol so Deception can be unit-tested against a
    fake without importing adam.sandbox at all (§11.2 — no sibling imports).
    """

    async def apply_mutation(self, kind: str, target: str, operation: str, value: str | None) -> None:
        ...

    async def apply_mutation_batch(
        self, file_creates: list[tuple[str, str | None]], timeout_s: float = 30.0
    ) -> None:
        """
        Batch FILE CREATE variant: write N files in a single PowerShell invocation.

        Implementors (HTTPGuestChannel) override this for real guest execution.
        Non-HTTP channels (VBoxGuestChannel, mocks) can raise NotImplementedError
        here; primitives that call this must document that they require the HTTP
        backend.
        """
        ...


class DeceptionPrimitive(IDeception, ABC):
    name: str = "UnnamedPrimitive"
    version: str = "1.0"

    def __init__(self, channel: GuestMutationChannel) -> None:
        self._channel = channel

    @abstractmethod
    async def _build_changes(self, parameters: dict[str, Any]) -> list[Change]:
        """Return the list of Change objects this primitive will apply."""

    @abstractmethod
    def _plausibility(self, parameters: dict[str, Any]) -> tuple[float, str]:
        """Return (score 0-1, human-readable notes) — see plausibility.py."""

    async def apply_async(
        self, session_id: str, correlation_id: str, decision_id: str, parameters: dict[str, Any]
    ) -> MutationResult:
        start = time.perf_counter()
        changes = await self._build_changes(parameters)

        try:
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
        latency_ms = (time.perf_counter() - start) * 1000

        return MutationResult(
            mutation_id=f"mut_{uuid.uuid4().hex[:12]}",
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

    def apply(self, parameters: dict[str, Any]) -> MutationResult:  # pragma: no cover
        raise NotImplementedError("Use apply_async — all guest ops are async (C5)")

    def revert(self, mutation: MutationResult) -> MutationResult:  # pragma: no cover
        raise NotImplementedError("Implement revert_async in the concrete primitive")
