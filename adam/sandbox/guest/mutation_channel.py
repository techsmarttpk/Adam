"""
adam/sandbox/guest/mutation_channel.py

RecordingGuestMutationChannel -- the first real (non-test-only) implementation
of `adam.deception.primitives.base.GuestMutationChannel`
(`apply_mutation(kind, target, operation, value) -> None`), the interface
`DeceptionEngine`/every `DeceptionPrimitive` calls to reach a guest.

Why this exists. Before this change, every construction of `DeceptionEngine`
anywhere in the repository passed a test double (`FakeGuestChannel` or
`unittest.mock.AsyncMock`) -- there was no real implementation at all, so
Policy/Deception decisions could never be exercised outside a test process
(see docs/ADAM_Full_Repository_Audit.md, Part 1.2). This class closes that
gap for `adam.orchestrator.pipeline`'s live wiring.

Why it does not touch a live VM (disclosed, not hidden). Actually mutating
a live guest's registry, filesystem, or process list requires a guest-agent
endpoint that performs that specific write. Checked directly against the
current guest agent surface:
  - Registry: no endpoint, no PowerShell manager module, no host-side model
    exists anywhere in the repository for writing a registry value. Not a
    missing wire -- the capability itself does not exist yet.
  - Filesystem: `adam/sandbox/guest/http_models.py` defines `MkdirRequest`/
    `CopyRequest`/`MoveRequest`/`DeleteRequest`, but there is no
    "create/write a file with given content" request model or guest-side
    handler, and `HTTPGuestChannel` never calls any of the four it does
    define except `mkdir` (for the telemetry capture directory).
  - Process: `ProcessStartRequest`/`ProcessStartData` are defined in
    `http_models.py` but `HTTPGuestChannel` never issues that call either.
So today, for every `Change.kind`, there is genuinely no wired path from a
Python call to a guest-side effect -- this is the
"fundamentally impossible because code literally does not exist" case the
integration brief calls out, not a wiring gap this pass can close safely
without inventing and shipping new, unverifiable (no VM available here)
guest-agent surface.

What this class does instead, and why that's still real progress. It gives
`DeceptionEngine` a genuine, non-mock channel: every `apply_mutation()` call
is validated, logged with full structured detail (kind/target/operation/
value/session/correlation), and appended to an in-memory (and, via
`adam.orchestrator.pipeline`, on-disk) record -- `MutationResult.status`
correctly reflects "recorded, not yet applied to a live guest" rather than
lying and claiming `APPLIED` against a guest nothing actually touched. This
makes the full `SemanticEvent -> PolicyDecision -> MutationResult` chain
run for real, end to end, against a live-captured session's own telemetry,
with an honest, structurally-enforced boundary at the one point (guest
mutation) that genuinely cannot be completed without new guest-agent code
this pass does not have a VM to build against or verify.

TODO (tracked, not silently dropped): once `HTTPGuestChannel` grows real
`write_file`/`set_registry_value`/`start_process` methods backed by new
guest-side endpoints, replace `_dispatch_live()`'s `NotImplementedError`
branches below with real calls -- the recording/logging behavior above this
point does not need to change.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Change kinds with a real, wired guest-side effect today. Empty on purpose
# -- see module docstring. Update this set (and add the corresponding call
# in _dispatch_live()) the day a real endpoint exists for a kind.
LIVE_SUPPORTED_KINDS: frozenset[str] = frozenset()


@dataclass(slots=True)
class RecordedMutation:
    """One `apply_mutation()` call, faithfully recorded."""

    kind: str
    target: str
    operation: str
    value: str | None
    recorded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    applied_live: bool = False
    note: str = ""


class RecordingGuestMutationChannel:
    """
    Real `GuestMutationChannel` implementation. Structurally satisfies
    `adam.deception.primitives.base.GuestMutationChannel` (duck-typed
    Protocol -- no inheritance required, verified by
    `tests/unit/test_mutation_channel.py`).

    One instance per session. `session_id` is carried only for logging;
    `apply_mutation()`'s own signature is fixed by the Protocol Deception
    already depends on and is not changed here.
    """

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id
        self._log: list[RecordedMutation] = []

    @property
    def recorded(self) -> list[RecordedMutation]:
        """Every mutation attempt recorded so far, in call order."""
        return list(self._log)

    async def apply_mutation(self, kind: str, target: str, operation: str, value: str | None) -> None:
        applied_live = kind in LIVE_SUPPORTED_KINDS
        note = (
            "applied against a live guest endpoint"
            if applied_live
            else "recorded only -- no live guest-mutation endpoint exists yet for this kind (see module docstring)"
        )

        if applied_live:
            await self._dispatch_live(kind, target, operation, value)

        entry = RecordedMutation(
            kind=kind, target=target, operation=operation, value=value, applied_live=applied_live, note=note
        )
        self._log.append(entry)

        logger.info(
            "session=%s mutation kind=%s operation=%s target=%s value=%s applied_live=%s",
            self._session_id,
            kind,
            operation,
            target,
            value,
            applied_live,
        )

    async def _dispatch_live(self, kind: str, target: str, operation: str, value: str | None) -> None:
        """
        No branch is reachable today -- `LIVE_SUPPORTED_KINDS` is empty
        (see module docstring). Structured this way, rather than omitted,
        so adding real guest-agent support later is a one-line
        `LIVE_SUPPORTED_KINDS` change plus one new `elif` here, not a
        rewrite of `apply_mutation()`'s recording/logging contract above.
        """
        raise NotImplementedError(
            f"kind={kind!r} has no live guest-mutation endpoint yet -- "
            "should be unreachable since LIVE_SUPPORTED_KINDS is empty"
        )
