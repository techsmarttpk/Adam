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

        if method == "POST" and path == "/sample/stage":
            target = body.get("target_path", "")
            b64 = body.get("content_base64")
            if b64:
                import base64
                import hashlib
                raw_bytes = base64.b64decode(b64)
                actual_sha = hashlib.sha256(raw_bytes).hexdigest()
                self.files[target] = raw_bytes
                return _envelope({"target_path": target, "sha256": actual_sha, "size_bytes": len(raw_bytes)})
            return _envelope({"target_path": target, "sha256": "0" * 64, "size_bytes": 0})

        if method == "POST" and path == "/process/start":
            exit_code = body.get("mock_exit_code", 0)
            return _envelope({"pid": 5555, "exit_code": exit_code, "stdout": "test_stdout\n", "stderr": ""})

        if method == "GET" and path == "/filesystem/read":
            guest_path = params.get("path", "")
            if guest_path not in self.files:
                return httpx.Response(404, headers={"X-Error-Code": "NOT_FOUND"}, content=b"")
            return httpx.Response(200, content=self.files[guest_path], headers={"Content-Type": "application/octet-stream"})

        # Any unmodeled route -- fail loudly so a test gap is visible, not silently ok()'d.
        raise AssertionError(f"FakeGuestAgentServer: unhandled {method} {path}")


def _make_channel(fake: FakeGuestAgentServer, **overrides) -> HTTPGuestChannel:
    transport = httpx.MockTransport(fake.handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://fake-guest:8765")
    defaults = dict(
        capture_dir="C:\\ADAM\\telemetry",
        procmon_path="C:\\Users\\Admin\\Downloads\\ProcessMonitor\\Procmon64.exe",
        tshark_path="C:\\Program Files\\Wireshark\\tshark.exe",
        sysmon_log="Microsoft-Windows-Sysmon/Operational",
        client=client,
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
        # for the full default 150s guest_ready_timeout_s. Small values
        # keep this "never raises" assertion fast without changing what
        # it's actually testing.
        guest_ready_timeout_s=0.05,
        readiness_poll_interval_s=0.01,
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


async def test_http_guest_channel_attaches_auth_token() -> None:
    captured_tokens: list[str | None] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        captured_tokens.append(request.headers.get("X-Adam-Token"))
        return _envelope({"status": "ok"})

    transport = httpx.MockTransport(_handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://192.168.19.101:8765")
    channel = HTTPGuestChannel(
        "http://192.168.19.101:8765",
        capture_dir="C:\\ADAM\\telemetry",
        procmon_path="C:\\Procmon.exe",
        tshark_path="C:\\tshark.exe",
        sysmon_log="Microsoft-Windows-Sysmon/Operational",
        auth_token="secops_super_secret_token",
        client=client,
    )

    await channel.wait_until_ready()
    assert len(captured_tokens) == 1
    assert captured_tokens[0] == "secops_super_secret_token"


async def test_http_guest_channel_handles_401_unauthorized() -> None:
    def _auth_reject_handler(request: httpx.Request) -> httpx.Response:
        token = request.headers.get("X-Adam-Token")
        if token != "valid_token":
            return httpx.Response(401, json={"success": False, "error_code": "UNAUTHORIZED", "error_message": "invalid token"})
        return _envelope({"status": "ok"})

    transport = httpx.MockTransport(_auth_reject_handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://192.168.19.101:8765")

    # 1. Direct HTTP request with wrong token asserts status 401 explicitly
    resp_wrong = await client.get("/health", headers={"X-Adam-Token": "wrong_token"})
    assert resp_wrong.status_code == 401
    assert resp_wrong.json()["error_code"] == "UNAUTHORIZED"

    # 2. Direct HTTP request with missing token asserts status 401 explicitly
    resp_missing = await client.get("/health")
    assert resp_missing.status_code == 401
    assert resp_missing.json()["error_code"] == "UNAUTHORIZED"

    # 3. Direct probe inside HTTPGuestChannel detects HTTP 401 explicitly
    channel = HTTPGuestChannel(
        "http://192.168.19.101:8765",
        capture_dir="C:\\ADAM\\telemetry",
        procmon_path="C:\\Procmon.exe",
        tshark_path="C:\\tshark.exe",
        sysmon_log="Microsoft-Windows-Sysmon/Operational",
        auth_token="wrong_token",
        client=client,
    )
    healthy, detail = await channel._probe_health_once()
    assert healthy is False
    assert detail == "HTTP 401"


# --------------------------------------------------------------------- #
# Stage A: stage_sample, run_process, and SandboxController migration
# --------------------------------------------------------------------- #


async def test_stage_sample_success(tmp_path: Path) -> None:
    sample_file = tmp_path / "test_sample.exe"
    sample_file.write_bytes(b"\x90\x90\x90HELLO_TEST_PAYLOAD")
    expected_sha256 = "657158784a0d9e871e84df94dfcb547f382103f6984e7ad18939b4bc063f25c7"
    import hashlib
    actual_expected_sha = hashlib.sha256(sample_file.read_bytes()).hexdigest()

    fake = FakeGuestAgentServer()
    channel = _make_channel(fake)
    result = await channel.stage_sample(sample_file, "C:\\ADAM\\sample.exe")

    assert result.success is True
    assert result.target_path == "C:\\ADAM\\sample.exe"
    assert result.sha256 == actual_expected_sha
    assert result.size_bytes == len(sample_file.read_bytes())
    assert fake.files["C:\\ADAM\\sample.exe"] == sample_file.read_bytes()
    assert ("POST", "/sample/stage") in fake.calls


async def test_stage_sample_hash_mismatch_raises_value_error(tmp_path: Path) -> None:
    sample_file = tmp_path / "test_sample.exe"
    sample_file.write_bytes(b"PAYLOAD")

    def _corrupted_hash_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/sample/stage":
            return _envelope({"target_path": "C:\\ADAM\\sample.exe", "sha256": "corrupted_hash_0000", "size_bytes": 7})
        return _envelope({"status": "ok"})

    transport = httpx.MockTransport(_corrupted_hash_handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://fake-guest:8765")
    channel = HTTPGuestChannel(
        "http://fake-guest:8765",
        capture_dir="C:\\ADAM\\telemetry",
        procmon_path="C:\\Procmon.exe",
        tshark_path="C:\\tshark.exe",
        sysmon_log="Sysmon",
        client=client,
    )

    with pytest.raises(ValueError) as excinfo:
        await channel.stage_sample(sample_file, "C:\\ADAM\\sample.exe")
    assert "Sample SHA256 mismatch during staging" in str(excinfo.value)


async def test_stage_sample_auth_rejection_raises_guest_agent_error(tmp_path: Path) -> None:
    from adam.sandbox.guest.http_models import GuestAgentError

    sample_file = tmp_path / "test_sample.exe"
    sample_file.write_bytes(b"PAYLOAD")

    def _auth_fail_handler(request: httpx.Request) -> httpx.Response:
        return _envelope(success=False, error_code="UNAUTHORIZED", error_message="Invalid token")

    transport = httpx.MockTransport(_auth_fail_handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://fake-guest:8765")
    channel = HTTPGuestChannel(
        "http://fake-guest:8765",
        capture_dir="C:\\ADAM\\telemetry",
        procmon_path="C:\\Procmon.exe",
        tshark_path="C:\\tshark.exe",
        sysmon_log="Sysmon",
        client=client,
    )

    with pytest.raises(GuestAgentError) as excinfo:
        await channel.stage_sample(sample_file, "C:\\ADAM\\sample.exe")
    assert excinfo.value.error_code == "UNAUTHORIZED"


async def test_stage_sample_missing_file_raises_filenotfound() -> None:
    fake = FakeGuestAgentServer()
    channel = _make_channel(fake)
    with pytest.raises(FileNotFoundError):
        await channel.stage_sample("C:\\nonexistent_host_path\\missing.exe", "C:\\ADAM\\sample.exe")


async def test_run_process_success() -> None:
    fake = FakeGuestAgentServer()
    channel = _make_channel(fake)
    result = await channel.run_process("C:\\ADAM\\sample.exe", arguments=["/arg1", "val1"])

    assert result.success is True
    assert result.return_code == 0
    assert result.stdout == "test_stdout\n"
    assert result.stderr == ""
    assert result.termination_reason is None
    assert ("POST", "/process/start") in fake.calls


async def test_run_process_crash_exit_code() -> None:
    def _crash_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/process/start":
            return _envelope({"pid": 5555, "exit_code": 3221226356, "stdout": "", "stderr": ""})
        return _envelope({"status": "ok"})

    transport = httpx.MockTransport(_crash_handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://fake-guest:8765")
    channel = HTTPGuestChannel(
        "http://fake-guest:8765",
        capture_dir="C:\\ADAM\\telemetry",
        procmon_path="C:\\Procmon.exe",
        tshark_path="C:\\tshark.exe",
        sysmon_log="Sysmon",
        client=client,
    )

    result = await channel.run_process("C:\\ADAM\\sample.exe")
    assert result.success is False
    assert result.return_code == 3221226356
    assert result.termination_reason == "STATUS_HEAP_CORRUPTION"


async def test_sandbox_controller_arm_and_detonate_uses_http_channel(tmp_path: Path) -> None:
    from unittest.mock import AsyncMock, MagicMock
    from adam.contracts.session import SampleRef
    from adam.sandbox.controller import SandboxController
    from adam.sandbox.state import SandboxState
    from adam.sandbox.vbox.client import VirtualBoxClient
    from adam.sandbox.vbox.models import VMOperationResult

    sample_file = tmp_path / "smoke.exe"
    sample_file.write_bytes(b"SMOKE_EXE_BYTES")

    fake = FakeGuestAgentServer()
    channel = _make_channel(fake)

    mock_client = MagicMock(spec=VirtualBoxClient)
    mock_client.get_state = AsyncMock(return_value="poweroff")
    mock_client.restore_snapshot = AsyncMock(return_value=VMOperationResult(True, ("restore",), 10.0, 0, "", ""))
    mock_client.start = AsyncMock(return_value=VMOperationResult(True, ("start",), 10.0, 0, "", ""))
    mock_client.wait_for_state = AsyncMock(return_value=VMOperationResult(True, ("wait",), 10.0, 0, "", ""))
    mock_client.wait_for_guest_ready = AsyncMock(return_value=VMOperationResult(True, ("ready",), 10.0, 0, "", ""))
    mock_client.stop = AsyncMock(return_value=VMOperationResult(True, ("stop",), 10.0, 0, "", ""))
    mock_client.copy_to_guest = AsyncMock()
    mock_client.run_in_guest = AsyncMock()

    ctrl = SandboxController(
        mock_client,
        "TestVM",
        guest_username="Adam",
        guest_password="Password",
        guest_channel=channel,
    )

    await ctrl.prepare()
    assert ctrl.state == SandboxState.READY

    await ctrl.arm(str(sample_file), "C:\\ADAM\\smoke.exe")
    assert ctrl.state == SandboxState.ARMED
    # Assert HTTP staging was used, NOT client.copy_to_guest
    assert ("POST", "/sample/stage") in fake.calls
    mock_client.copy_to_guest.assert_not_called()

    sample_ref = SampleRef(
        sha256="0" * 64,
        md5="0" * 32,
        filename="smoke.exe",
        size_bytes=100,
        file_type="PE32",
    )
    await ctrl.detonate(sample_ref)
    assert ctrl.state == SandboxState.COMPLETED
    # Assert HTTP process start was used, NOT client.run_in_guest
    assert ("POST", "/process/start") in fake.calls
    mock_client.run_in_guest.assert_not_called()
    assert ctrl.last_detonation_result.return_code == 0


async def test_sandbox_controller_arm_and_detonate_fallback_on_unreachable(tmp_path: Path) -> None:
    from unittest.mock import AsyncMock, MagicMock
    from adam.contracts.session import SampleRef
    from adam.sandbox.controller import SandboxController
    from adam.sandbox.state import SandboxState
    from adam.sandbox.vbox.client import VirtualBoxClient
    from adam.sandbox.vbox.models import VMOperationResult

    sample_file = tmp_path / "smoke.exe"
    sample_file.write_bytes(b"SMOKE_EXE_BYTES")

    def _unreachable_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/sample/stage", "/process/start"):
            raise httpx.ConnectError("connection refused", request=request)
        return _envelope({"status": "ok"})

    transport = httpx.MockTransport(_unreachable_handler)
    client = httpx.AsyncClient(transport=transport, base_url="http://fake-guest:8765")
    channel = HTTPGuestChannel(
        "http://fake-guest:8765",
        capture_dir="C:\\ADAM\\telemetry",
        procmon_path="C:\\Procmon.exe",
        tshark_path="C:\\tshark.exe",
        sysmon_log="Sysmon",
        client=client,
    )

    mock_client = MagicMock(spec=VirtualBoxClient)
    mock_client.get_state = AsyncMock(return_value="poweroff")
    mock_client.restore_snapshot = AsyncMock(return_value=VMOperationResult(True, ("restore",), 10.0, 0, "", ""))
    mock_client.start = AsyncMock(return_value=VMOperationResult(True, ("start",), 10.0, 0, "", ""))
    mock_client.wait_for_state = AsyncMock(return_value=VMOperationResult(True, ("wait",), 10.0, 0, "", ""))
    mock_client.wait_for_guest_ready = AsyncMock(return_value=VMOperationResult(True, ("ready",), 10.0, 0, "", ""))
    mock_client.stop = AsyncMock(return_value=VMOperationResult(True, ("stop",), 10.0, 0, "", ""))
    mock_client.copy_to_guest = AsyncMock(return_value=VMOperationResult(True, ("copyto",), 10.0, 0, "", ""))
    mock_client.run_in_guest = AsyncMock(return_value=VMOperationResult(True, ("run",), 10.0, 0, "fallback_out", ""))

    ctrl = SandboxController(
        mock_client,
        "TestVM",
        guest_username="Adam",
        guest_password="Password",
        guest_channel=channel,
    )

    await ctrl.prepare()
    await ctrl.arm(str(sample_file), "C:\\ADAM\\smoke.exe")
    assert ctrl.state == SandboxState.ARMED
    # Fallback to copy_to_guest was invoked
    mock_client.copy_to_guest.assert_called_once()

    sample_ref = SampleRef(
        sha256="0" * 64,
        md5="0" * 32,
        filename="smoke.exe",
        size_bytes=100,
        file_type="PE32",
    )
    await ctrl.detonate(sample_ref)
    assert ctrl.state == SandboxState.COMPLETED
    # Fallback to run_in_guest was invoked
    mock_client.run_in_guest.assert_called_once()
    assert ctrl.last_detonation_result.stdout == "fallback_out"


