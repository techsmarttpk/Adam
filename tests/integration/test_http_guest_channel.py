"""
tests/integration/test_http_guest_channel.py

Mock HTTP server tests for HTTPGuestChannel -- drives real production code
(HTTPGuestChannel's verify_tools/start_captures/stop_export_and_fetch)
against a fake guest agent HTTP boundary, using httpx.MockTransport (no
real socket, no real Windows guest) as the fake -- the same
fake-the-transport-boundary methodology this project has used throughout
(FakeClient(VirtualBoxClient) for the vbox backend;
scripts/manual_tests/guest_agent_offline_verification.py's
FakeVirtualBoxClient is the closest precedent).

This proves HTTPGuestChannel's own orchestration logic (which endpoints it
calls, in what order, how it maps responses into ToolAvailability/
TelemetryArtifacts, how it handles success=false and transport errors)
end-to-end against the documented API spec (docs/phase5-http-agent-api.md)
-- it does NOT prove the real PowerShell guest agent actually implements
that spec correctly, since nothing here executes PowerShell. See
docs/phase5-migration-guide.md for what still needs a real VM.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import httpx
import pytest

from adam.sandbox.guest.http_channel import HTTPGuestChannel


def _envelope(data: dict | None = None, *, success: bool = True, error_code: str | None = None, error_message: str | None = None) -> httpx.Response:
    body = {"success": success, "error_code": error_code, "error_message": error_message, "data": data}
    status = 200 if success else 500
    return httpx.Response(status, json=body)


class FakeGuestAgentServer:
    """
    A stateful fake implementing just enough of docs/phase5-http-agent-api.md
    to drive HTTPGuestChannel's three GuestChannel methods end-to-end,
    mirroring the offline harness's FakeVirtualBoxClient in spirit: models
    a minimal guest filesystem (`self.files`) so a produced artifact can
    actually be "read back" by /filesystem/read.
    """

    def __init__(self, *, procmon_present: bool = True, tshark_present: bool = True, sysmon_available: bool = True) -> None:
        self.calls: list[tuple[str, str]] = []
        self.procmon_present = procmon_present
        self.tshark_present = tshark_present
        self.sysmon_available = sysmon_available
        self.files: dict[str, bytes] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        method = request.method
        path = request.url.path
        self.calls.append((method, path))
        params = dict(request.url.params)
        body = json.loads(request.content) if request.content else {}

        if method == "GET" and path == "/health":
            return _envelope({"status": "ok", "uptime_s": 1.0})

        if method == "GET" and path == "/filesystem/exists":
            target = params.get("path", "")
            present = (self.procmon_present and "Procmon" in target) or (self.tshark_present and "tshark" in target.lower())
            return _envelope({"exists": present, "is_directory": False, "size_bytes": 100 if present else None})

        if method == "GET" and path == "/sysmon/diagnostics":
            return _envelope({"channel_available": self.sysmon_available, "event_count": 3 if self.sysmon_available else None})

        if method == "POST" and path == "/filesystem/mkdir":
            return _envelope({"created": True, "already_existed": False})

        if method == "POST" and path == "/procmon/start":
            self.files[body["backing_file"]] = b""  # backing file "created"
            return _envelope({"pid": 4242})

        if method == "GET" and path == "/network/interfaces":
            return _envelope({"interfaces": [{"index": "1", "description": "Ethernet"}]})

        if method == "POST" and path == "/network/start":
            return _envelope({"pid": 4243})

        if method == "POST" and path in ("/procmon/stop", "/network/stop"):
            return _envelope({"stopped": True})

        if method == "GET" and path == "/procmon/verify-backing-file":
            exists = params.get("path") in self.files
            return _envelope({"exists": exists, "size_bytes": 0 if exists else None})

        if method == "POST" and path == "/procmon/export":
            self.files[body["csv_path"]] = b"Date & Time,Process Name\n1/1/2026,test.exe\n"
            return _envelope({"csv_path": body["csv_path"]})

        if method == "POST" and path == "/network/convert":
            self.files[body["ek_json_path"]] = b'{"index":{}}\n'
            return _envelope({"ek_json_path": body["ek_json_path"]})

        if method == "POST" and path == "/sysmon/export":
            if not self.sysmon_available:
                return _envelope(success=False, error_code="ACCESS_DENIED", error_message="Access is denied.")
            self.files[body["output_path"]] = b"FAKE-EVTX"
            return _envelope({"output_path": body["output_path"], "mechanism": "wevtutil"})

        if method == "GET" and path == "/filesystem/read":
            guest_path = params.get("path", "")
            if guest_path not in self.files:
                return httpx.Response(404, headers={"X-Error-Code": "NOT_FOUND"}, content=b"")
            return httpx.Response(200, content=self.files[guest_path], headers={"Content-Type": "application/octet-stream"})

        # Any unmodeled route -- fail loudly so a test gap is visible, not silently ok()'d.
        raise AssertionError(f"FakeGuestAgentServer: unhandled {method} {path}")


async def _always_network_reachable() -> tuple[bool, str]:
    """
    Fake `network_prober` for tests that exercise HTTP-layer logic
    (verify_tools/start_captures/stop_export_and_fetch/wait_until_ready's
    HTTP stage) against httpx.MockTransport -- no real socket exists
    behind "fake-guest:8765" or similar test hostnames, so the real
    `_default_network_probe()` (a genuine TCP connect, independent of the
    injected httpx client) would fail/hang against them. Injected exactly
    like `client` already is, to keep the network-readiness stage out of
    these tests' way -- its own behavior is covered separately below by
    TestNetworkReadinessStage.
    """
    return True, "fake: network stage bypassed for this test"


def _make_channel(fake: FakeGuestAgentServer, **overrides) -> HTTPGuestChannel:
    transport = httpx.MockTransport(fake.handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://fake-guest:8765")
    defaults = dict(
        capture_dir="C:\\ADAM\\telemetry",
        procmon_path="C:\\Users\\Admin\\Downloads\\ProcessMonitor\\Procmon64.exe",
        tshark_path="C:\\Program Files\\Wireshark\\tshark.exe",
        sysmon_log="Microsoft-Windows-Sysmon/Operational",
        client=client,
        network_prober=_always_network_reachable,
    )
    defaults.update(overrides)
    return HTTPGuestChannel("http://fake-guest:8765", **defaults)


async def test_verify_tools_all_present() -> None:
    fake = FakeGuestAgentServer()
    channel = _make_channel(fake)
    report = await channel.verify_tools()
    assert report.procmon_available is True
    assert report.tshark_available is True
    assert report.sysmon_log_available is True
    assert report.detail == {}


async def test_verify_tools_missing_reports_specific_detail() -> None:
    fake = FakeGuestAgentServer(procmon_present=False, sysmon_available=False)
    channel = _make_channel(fake)
    report = await channel.verify_tools()
    assert report.procmon_available is False
    assert report.tshark_available is True
    assert "procmon" in report.detail
    assert "sysmon" in report.detail


async def test_full_capture_export_fetch_round_trip() -> None:
    fake = FakeGuestAgentServer()
    channel = _make_channel(fake)
    with tempfile.TemporaryDirectory() as tmp:
        await channel.start_captures("sess_test_001")
        artifacts = await channel.stop_export_and_fetch("sess_test_001", tmp)

        assert artifacts.sysmon_evtx_path is not None
        assert artifacts.procmon_csv_path is not None
        assert artifacts.network_ek_json_path is not None
        assert Path(artifacts.procmon_csv_path).read_bytes() == b"Date & Time,Process Name\n1/1/2026,test.exe\n"
        assert b"index" in Path(artifacts.network_ek_json_path).read_bytes()


async def test_sysmon_access_denied_yields_none_not_raise() -> None:
    """Support-partial-telemetry contract: a sysmon failure must not raise and must not affect the other two sources."""
    fake = FakeGuestAgentServer(sysmon_available=False)
    channel = _make_channel(fake)
    with tempfile.TemporaryDirectory() as tmp:
        await channel.start_captures("sess_test_002")
        artifacts = await channel.stop_export_and_fetch("sess_test_002", tmp)

    assert artifacts.sysmon_evtx_path is None
    assert artifacts.procmon_csv_path is not None
    assert artifacts.network_ek_json_path is not None


async def test_transport_error_never_raises() -> None:
    """A guest that's simply unreachable must degrade to None/empty results, per HTTPGuestChannel's own 'never raise' contract."""

    def _broken_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    transport = httpx.MockTransport(_broken_handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://unreachable:8765")
    channel = HTTPGuestChannel(
        "http://unreachable:8765", capture_dir="C:\\ADAM\\telemetry",
        procmon_path="C:\\procmon.exe", tshark_path="C:\\tshark.exe",
        sysmon_log="Microsoft-Windows-Sysmon/Operational", client=client,
        retry_attempts=1,  # this test asserts never-raises behavior, not retry timing -- keep it instant
        # verify_tools() now calls wait_until_ready() first (see
        # test_http_readiness.py-style tests below) -- against this
        # always-ConnectError handler that would otherwise poll /health
        # for the full default 200s agent_ready_timeout_s. Small values
        # keep this "never raises" assertion fast without changing what
        # it's actually testing. network_prober bypasses the real TCP
        # network-readiness stage (stage 1), which would otherwise try a
        # genuine socket connect to a nonexistent "unreachable" host --
        # independent of `client`/MockTransport entirely -- see
        # _always_network_reachable()'s own docstring.
        guest_ready_timeout_s=0.05,
        readiness_poll_interval_s=0.01,
        network_prober=_always_network_reachable,
    )
    report = await channel.verify_tools()
    assert report.procmon_available is False
    assert report.tshark_available is False
    assert report.sysmon_log_available is False
    assert "agent" in report.detail

    with tempfile.TemporaryDirectory() as tmp:
        artifacts = await channel.stop_export_and_fetch("sess_unreachable", tmp)
    assert artifacts.sysmon_evtx_path is None
    assert artifacts.procmon_csv_path is None
    assert artifacts.network_ek_json_path is None


async def test_transport_error_retries_before_giving_up() -> None:
    """
    Verifies the actual retry mechanism (not just its end state): a
    handler that fails twice then succeeds should still produce a
    successful result, proving _request() really does retry rather than
    giving up on the first transient error.
    """
    call_count = {"n": 0}

    def _flaky_handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        if call_count["n"] < 3:
            raise httpx.ConnectError("connection refused", request=request)
        return httpx.Response(200, json={"success": True, "error_code": None, "error_message": None, "data": {"status": "ok", "uptime_s": 12.5}})

    transport = httpx.MockTransport(_flaky_handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://flaky:8765")
    channel = HTTPGuestChannel(
        "http://flaky:8765", capture_dir="C:\\ADAM\\telemetry",
        procmon_path=None, tshark_path=None,
        sysmon_log="Microsoft-Windows-Sysmon/Operational", client=client,
        retry_attempts=3, retry_backoff_s=0.01,
    )
    health = await channel.get_health()
    assert health.status == "ok"
    assert call_count["n"] == 3


async def test_get_health_raises_on_unreachable_guest() -> None:
    """get_health()/get_version() are the deliberate exception to the 'never raise' rule -- explicit opt-in diagnostics, not part of the automatic session lifecycle."""
    from adam.sandbox.guest.http_models import GuestAgentUnreachableError

    def _broken_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    transport = httpx.MockTransport(_broken_handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://unreachable:8765")
    channel = HTTPGuestChannel(
        "http://unreachable:8765", capture_dir="C:\\ADAM\\telemetry",
        procmon_path=None, tshark_path=None,
        sysmon_log="Microsoft-Windows-Sysmon/Operational", client=client,
    )
    with pytest.raises(GuestAgentUnreachableError):
        await channel.get_health()


async def test_get_health_raises_on_application_error() -> None:
    """A reachable guest that reports success=false on /health raises the base GuestAgentError, carrying the real error_code."""
    from adam.sandbox.guest.http_models import GuestAgentError

    def _unhealthy_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"success": False, "error_code": "INTERNAL_ERROR", "error_message": "listener degraded", "data": None})

    transport = httpx.MockTransport(_unhealthy_handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://degraded:8765")
    channel = HTTPGuestChannel(
        "http://degraded:8765", capture_dir="C:\\ADAM\\telemetry",
        procmon_path=None, tshark_path=None,
        sysmon_log="Microsoft-Windows-Sysmon/Operational", client=client,
    )
    with pytest.raises(GuestAgentError) as excinfo:
        await channel.get_health()
    assert excinfo.value.error_code == "INTERNAL_ERROR"


async def test_get_version_success() -> None:
    def _version_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "error_code": None, "error_message": None, "data": {"agent_version": "1.0.0", "api_version": "1"}})

    transport = httpx.MockTransport(_version_handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://guest:8765")
    channel = HTTPGuestChannel(
        "http://guest:8765", capture_dir="C:\\ADAM\\telemetry",
        procmon_path=None, tshark_path=None,
        sysmon_log="Microsoft-Windows-Sysmon/Operational", client=client,
    )
    version = await channel.get_version()
    assert version.agent_version == "1.0.0"
    assert version.api_version == "1"


# --------------------------------------------------------------------- #
# HTTP guest agent readiness -- HTTPGuestChannel.wait_until_ready()
#
# Real-VM validation found a genuine startup-timing gap: immediately
# after VM boot, GET /health refuses the connection for a short window
# before adam_agent.ps1's HttpListener is actually up, then consistently
# returns 200. These tests drive wait_until_ready() directly (not through
# verify_tools()) against mocked HTTP responses -- no real VM, no fixed
# sleeps: `readiness_poll_interval_s` is set tiny (0.01s) everywhere below
# so a multi-attempt test still runs in milliseconds, while still
# genuinely exercising the same poll-then-sleep-then-poll-again loop
# production code runs with its real 1-second interval.
# --------------------------------------------------------------------- #


def _readiness_channel(handler, **overrides) -> HTTPGuestChannel:
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://fake-guest:8765")
    defaults = dict(
        capture_dir="C:\\ADAM\\telemetry",
        procmon_path=None,
        tshark_path=None,
        sysmon_log="Microsoft-Windows-Sysmon/Operational",
        client=client,
        guest_ready_timeout_s=0.2,
        readiness_poll_interval_s=0.01,
        # These tests exercise stage 2 (GET /health polling) in isolation
        # -- stage 1 (network readiness) is covered on its own by
        # TestNetworkReadinessStage below, so bypass it here exactly like
        # _make_channel() does.
        network_prober=_always_network_reachable,
    )
    defaults.update(overrides)
    return HTTPGuestChannel("http://fake-guest:8765", **defaults)


async def test_wait_until_ready_immediate_success() -> None:
    calls = {"n": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        assert request.url.path == "/health"
        return _envelope({"status": "ok", "uptime_s": 0.5})

    channel = _readiness_channel(_handler)
    await channel.wait_until_ready()
    assert calls["n"] == 1


async def test_wait_until_ready_connection_refused_then_success() -> None:
    calls = {"n": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("connection refused", request=request)
        return _envelope({"status": "ok", "uptime_s": 0.5})

    channel = _readiness_channel(_handler)
    await channel.wait_until_ready()
    assert calls["n"] == 3


async def test_wait_until_ready_malformed_json_then_success() -> None:
    calls = {"n": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(200, content=b"not json{{{", headers={"Content-Type": "application/json"})
        return _envelope({"status": "ok", "uptime_s": 0.5})

    channel = _readiness_channel(_handler)
    await channel.wait_until_ready()
    assert calls["n"] == 3


async def test_wait_until_ready_http_500_then_success() -> None:
    calls = {"n": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(500, json={"success": False, "error_code": "INTERNAL_ERROR", "error_message": "not ready yet", "data": None})
        return _envelope({"status": "ok", "uptime_s": 0.5})

    channel = _readiness_channel(_handler)
    await channel.wait_until_ready()
    assert calls["n"] == 3


async def test_wait_until_ready_timeout_raises_guest_timeout_error() -> None:
    from adam.common.errors import GuestTimeoutError

    def _always_refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    channel = _readiness_channel(_always_refused, guest_ready_timeout_s=0.05, readiness_poll_interval_s=0.01)
    with pytest.raises(GuestTimeoutError) as excinfo:
        await channel.wait_until_ready()
    message = str(excinfo.value)
    assert "did not become healthy" in message
    # Must distinguish "guest HTTP agent never came up" from a VM boot
    # failure -- per the requirement this was built against.
    assert "not a VM boot failure" in message


async def test_wait_until_ready_success_true_required_not_just_http_200() -> None:
    """HTTP 200 alone must not be treated as healthy -- the envelope's success field must also be true."""

    def _handler(request: httpx.Request) -> httpx.Response:
        # Malformed guest: 200 status but success:false in the body.
        return httpx.Response(200, json={"success": False, "error_code": "INTERNAL_ERROR", "error_message": "listener degraded", "data": None})

    channel = _readiness_channel(_handler, guest_ready_timeout_s=0.03, readiness_poll_interval_s=0.01)
    from adam.common.errors import GuestTimeoutError
    with pytest.raises(GuestTimeoutError):
        await channel.wait_until_ready()


async def test_wait_until_ready_caches_success_and_never_polls_again() -> None:
    """Session-lifetime caching: once healthy, a second call must not issue another HTTP request at all."""
    calls = {"n": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _envelope({"status": "ok", "uptime_s": 0.5})

    channel = _readiness_channel(_handler)
    await channel.wait_until_ready()
    assert calls["n"] == 1
    await channel.wait_until_ready()
    await channel.wait_until_ready()
    assert calls["n"] == 1  # still just the one probe -- cached, not re-polled


async def test_verify_tools_waits_for_readiness_first_then_proceeds_normally() -> None:
    """Integration: verify_tools() against a healthy /health plus the normal FakeGuestAgentServer routes behaves exactly as before readiness was added."""
    fake = FakeGuestAgentServer()
    channel = _make_channel(fake)
    report = await channel.verify_tools()
    assert report.procmon_available is True
    assert report.tshark_available is True
    assert report.sysmon_log_available is True
    assert ("GET", "/health") in fake.calls


async def test_verify_tools_folds_readiness_timeout_into_detail_without_raising() -> None:
    """verify_tools()'s own 'never raise' contract must survive a readiness timeout -- it degrades to detail['agent'], per HTTPGuestChannel's resilience contract."""

    def _always_refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    channel = _readiness_channel(_always_refused, guest_ready_timeout_s=0.03, readiness_poll_interval_s=0.01)
    report = await channel.verify_tools()
    assert report.procmon_available is False
    assert report.tshark_available is False
    assert report.sysmon_log_available is False
    assert "agent" in report.detail
    assert "did not become healthy" in report.detail["agent"]


# --------------------------------------------------------------------- #
# Network-readiness stage (startup/readiness hardening pass) --
# HTTPGuestChannel.wait_until_ready() now runs an explicit stage 1
# (_wait_for_network(), raw TCP reachability) before stage 2 (GET /health
# polling, covered above). These tests drive stage 1 via the injectable
# `network_prober` (same reasoning `client` is injectable -- see
# __init__'s docstring and _always_network_reachable()'s own docstring),
# plus one set of tests against the real default TCP-connect prober
# itself, against a real local socket (no mocks) so the actual
# reachable/refused/unreachable classification logic is genuinely
# exercised, not just its plumbing.
# --------------------------------------------------------------------- #


def _network_only_channel(network_prober, **overrides) -> HTTPGuestChannel:
    """
    A channel whose HTTP layer never actually gets exercised -- these
    tests only care about `_wait_for_network()`'s own retry/timeout
    behavior, so the httpx transport is a MockTransport that would raise
    AssertionError if it were ever called (proving stage 2 never starts
    when stage 1 fails).
    """

    def _unexpected_http_call(request: httpx.Request) -> httpx.Response:
        raise AssertionError(
            f"HTTP layer was called ({request.method} {request.url.path}) -- stage 2 (GET /health) "
            "must not run until stage 1 (network readiness) has already succeeded."
        )

    transport = httpx.MockTransport(_unexpected_http_call)
    client = httpx.AsyncClient(transport=transport, base_url="http://fake-guest:8765")
    defaults = dict(
        capture_dir="C:\\ADAM\\telemetry",
        procmon_path=None,
        tshark_path=None,
        sysmon_log="Microsoft-Windows-Sysmon/Operational",
        client=client,
        network_prober=network_prober,
        network_ready_timeout_s=0.2,
        network_poll_interval_s=0.01,
    )
    defaults.update(overrides)
    return HTTPGuestChannel("http://fake-guest:8765", **defaults)


class TestNetworkReadinessStage:
    async def test_network_unreachable_raises_before_ever_touching_http_layer(self) -> None:
        """Proves stage ordering: a network stage that never succeeds must raise its own GuestTimeoutError and never fall through to GET /health at all (the MockTransport handler above would assert-fail if it did)."""
        from adam.common.errors import GuestTimeoutError

        async def _always_unreachable() -> tuple[bool, str]:
            return False, "simulated: no route to host"

        channel = _network_only_channel(_always_unreachable)
        with pytest.raises(GuestTimeoutError) as excinfo:
            await channel.wait_until_ready()
        message = str(excinfo.value)
        assert "network unavailable" in message
        # Must read distinctly from stage 2's own timeout message (see
        # test_wait_until_ready_timeout_raises_guest_timeout_error above).
        assert "did not become healthy" not in message

    async def test_network_prober_retries_then_succeeds_then_health_stage_runs(self) -> None:
        """A prober that fails twice then succeeds should let wait_until_ready() proceed into (and complete) stage 2 -- proves retry really happens, not just the end state."""
        calls = {"n": 0}

        async def _flaky() -> tuple[bool, str]:
            calls["n"] += 1
            if calls["n"] < 3:
                return False, "simulated: not reachable yet"
            return True, "simulated: reachable"

        def _healthy(request: httpx.Request) -> httpx.Response:
            return _envelope({"status": "ok", "uptime_s": 0.1})

        transport = httpx.MockTransport(_healthy)
        client = httpx.AsyncClient(transport=transport, base_url="http://fake-guest:8765")
        channel = HTTPGuestChannel(
            "http://fake-guest:8765", capture_dir="C:\\ADAM\\telemetry",
            procmon_path=None, tshark_path=None, sysmon_log="Microsoft-Windows-Sysmon/Operational",
            client=client, network_prober=_flaky,
            network_ready_timeout_s=0.2, network_poll_interval_s=0.01,
            guest_ready_timeout_s=0.2, readiness_poll_interval_s=0.01,
        )
        await channel.wait_until_ready()
        assert calls["n"] == 3

    async def test_network_reachable_immediately_incurs_no_retry(self) -> None:
        calls = {"n": 0}

        async def _immediate() -> tuple[bool, str]:
            calls["n"] += 1
            return True, "simulated: reachable"

        channel = _network_only_channel(_immediate)
        # Swap the assert-fail transport for a real healthy one now that
        # we actually want stage 2 to run and succeed too.
        channel._client = httpx.AsyncClient(  # noqa: SLF001 -- test-only reach-in, same pattern as _readiness_channel's constructor injection would use if it needed a post-construction swap
            transport=httpx.MockTransport(lambda r: _envelope({"status": "ok", "uptime_s": 0.1})),
            base_url="http://fake-guest:8765",
        )
        await channel.wait_until_ready()
        assert calls["n"] == 1


class TestDefaultNetworkProbe:
    """
    Exercises HTTPGuestChannel._default_network_probe() -- the real,
    production TCP-connect implementation used when no `network_prober`
    is injected -- against real local sockets (no mocks), so the
    reachable/refused/unreachable classification is genuinely proven, not
    just its call-site plumbing (covered above).
    """

    async def test_open_port_is_reachable(self) -> None:
        import asyncio as _asyncio

        server = await _asyncio.start_server(lambda r, w: None, host="127.0.0.1", port=0)
        host, port = server.sockets[0].getsockname()[:2]
        try:
            channel = HTTPGuestChannel(
                f"http://{host}:{port}", capture_dir="C:\\ADAM\\telemetry",
                procmon_path=None, tshark_path=None, sysmon_log="Microsoft-Windows-Sysmon/Operational",
                client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))),
            )
            reachable, detail = await channel._default_network_probe()  # noqa: SLF001 -- deliberately testing the private default implementation directly
            assert reachable is True
            assert "tcp connect succeeded" in detail
        finally:
            server.close()
            await server.wait_closed()

    async def test_closed_port_connection_refused_counts_as_reachable(self) -> None:
        import asyncio as _asyncio

        # Bind and immediately close -- gives us a real, currently-unused
        # local port that will refuse connections deterministically.
        server = await _asyncio.start_server(lambda r, w: None, host="127.0.0.1", port=0)
        host, port = server.sockets[0].getsockname()[:2]
        server.close()
        await server.wait_closed()

        channel = HTTPGuestChannel(
            f"http://{host}:{port}", capture_dir="C:\\ADAM\\telemetry",
            procmon_path=None, tshark_path=None, sysmon_log="Microsoft-Windows-Sysmon/Operational",
            client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))),
        )
        reachable, detail = await channel._default_network_probe()  # noqa: SLF001
        assert reachable is True
        assert "connection refused" in detail
