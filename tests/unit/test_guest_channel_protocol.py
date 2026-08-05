"""
tests/unit/test_guest_channel_protocol.py

Verifies both GuestChannel backends (VBoxGuestChannel, HTTPGuestChannel)
structurally satisfy the GuestChannel Protocol (adam.sandbox.guest.channel),
and that GuestAgent (the untouched, wrapped class) was never modified to
add explicit inheritance -- the whole point of using a Protocol here (see
channel.py's own docstring) is that VBoxGuestChannel can wrap it via plain
composition without GuestAgent itself changing at all.
"""

from __future__ import annotations

import inspect

from adam.sandbox.guest.agent.agent import GuestAgent
from adam.sandbox.guest.channel import GuestChannel
from adam.sandbox.guest.http_channel import HTTPGuestChannel
from adam.sandbox.guest.vbox_channel import VBoxGuestChannel


def test_vbox_guest_channel_satisfies_protocol() -> None:
    # Constructed with dummy/None-ish args just to get an instance for the
    # isinstance check -- GuestAgent's __init__ does no I/O.
    class _FakeClient:
        pass

    agent = GuestAgent.__new__(GuestAgent)  # bypass __init__, we only need the method surface
    channel = VBoxGuestChannel(agent)
    assert isinstance(channel, GuestChannel)


def test_http_guest_channel_satisfies_protocol() -> None:
    import httpx

    # Explicit MockTransport client -- avoids httpx.AsyncClient's default
    # constructor picking up this sandbox's own proxy environment
    # variables (trust_env=True by default), which is irrelevant to this
    # isinstance-only structural check.
    fake_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    channel = HTTPGuestChannel(
        "http://192.0.2.1:8765", capture_dir="C:\\ADAM\\telemetry",
        procmon_path=None, tshark_path=None, sysmon_log="Microsoft-Windows-Sysmon/Operational",
        client=fake_client,
    )
    assert isinstance(channel, GuestChannel)


def test_guest_agent_itself_was_not_modified_to_inherit_channel() -> None:
    """
    "Do NOT patch the existing GuestControl-based GuestAgent" -- confirms
    GuestAgent's own MRO contains no reference to GuestChannel; it
    satisfies the interface only via VBoxGuestChannel's composition, not
    by GuestAgent itself being changed to subclass or import channel.py.
    """
    assert GuestChannel not in GuestAgent.__mro__


def test_guest_channel_methods_are_async() -> None:
    for name in ("verify_tools", "start_captures", "stop_export_and_fetch"):
        method = getattr(GuestChannel, name)
        assert inspect.iscoroutinefunction(method), f"{name} must be an async method"
