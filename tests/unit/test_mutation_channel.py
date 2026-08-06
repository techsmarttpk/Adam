"""
tests/unit/test_mutation_channel.py

Covers adam/sandbox/guest/mutation_channel.py -- the first real (non-test-
double) GuestMutationChannel implementation, built as part of the live
Fusion -> Policy -> Deception pipeline integration.
"""

from __future__ import annotations

import pytest

from adam.deception.primitives.base import GuestMutationChannel
from adam.sandbox.guest.mutation_channel import LIVE_SUPPORTED_KINDS, RecordingGuestMutationChannel


class TestRecordingGuestMutationChannel:
    def test_satisfies_guest_mutation_channel_protocol_structurally(self) -> None:
        # GuestMutationChannel (adam/deception/primitives/base.py, Dev C's
        # module) is not @runtime_checkable, so isinstance() against it
        # raises TypeError rather than returning False -- duck-type the
        # same structural check instead of editing a file this project
        # does not own (adam/deception/, per ARCHITECTURE.md section 10.1).
        import inspect

        channel = RecordingGuestMutationChannel(session_id="sess_test")
        assert callable(getattr(channel, "apply_mutation", None))
        protocol_params = list(inspect.signature(GuestMutationChannel.apply_mutation).parameters)
        impl_params = list(inspect.signature(channel.apply_mutation).parameters)
        assert protocol_params == ["self", *impl_params]

    @pytest.mark.asyncio
    async def test_records_every_call_in_order(self) -> None:
        channel = RecordingGuestMutationChannel(session_id="sess_test")

        await channel.apply_mutation("REGISTRY", r"HKLM\SOFTWARE\Run\Decoy", "SET", "C:\\decoy.exe")
        await channel.apply_mutation("FILE", r"C:\Users\analyst\passwords.txt", "CREATE", None)

        assert len(channel.recorded) == 2
        assert channel.recorded[0].kind == "REGISTRY"
        assert channel.recorded[0].target == r"HKLM\SOFTWARE\Run\Decoy"
        assert channel.recorded[0].operation == "SET"
        assert channel.recorded[0].value == "C:\\decoy.exe"
        assert channel.recorded[1].kind == "FILE"

    @pytest.mark.asyncio
    async def test_no_kind_is_live_today_and_that_is_disclosed_in_the_record(self) -> None:
        """
        See mutation_channel.py's module docstring: no guest-agent endpoint
        exists yet for any Change.kind, so LIVE_SUPPORTED_KINDS is
        deliberately empty and every recorded mutation is honestly marked
        applied_live=False, never a fabricated "succeeded against a real
        guest" claim.
        """
        assert LIVE_SUPPORTED_KINDS == frozenset()

        channel = RecordingGuestMutationChannel(session_id="sess_test")
        await channel.apply_mutation("PROCESS", "avp.exe", "CREATE", "pid=1120")

        assert channel.recorded[0].applied_live is False
        assert "no live guest-mutation endpoint exists yet" in channel.recorded[0].note

    @pytest.mark.asyncio
    async def test_recorded_property_returns_a_copy_not_the_live_list(self) -> None:
        channel = RecordingGuestMutationChannel(session_id="sess_test")
        await channel.apply_mutation("NETWORK", "dns:evil.example", "RESPOND", "10.0.0.10")

        snapshot = channel.recorded
        snapshot.clear()

        assert len(channel.recorded) == 1
