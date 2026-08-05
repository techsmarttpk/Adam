"""
adam/sandbox/guest/http_channel.py

HTTPGuestChannel -- the target Phase 5 architecture's GuestChannel
implementation, talking to a persistent, guest-resident PowerShell 5.1
HTTP service (adam/sandbox/guest/agent/adam_agent.ps1) instead of driving
VBoxManage GuestControl. See adam/sandbox/guest/channel.py for why this
exists alongside, not instead of, VBoxGuestChannel, and
docs/phase5-http-agent-api.md for the full wire-format spec this class is
written against.

Design notes:

  Resilience contract matches GuestAgent's own (adam/sandbox/guest/agent/
  agent.py's module docstring Guarantees): verify_tools() never raises;
  start_captures() is best-effort per source; stop_export_and_fetch()
  yields None for any source that fails, independently of the other two.
  Every fine-grained HTTP call funnels through `_request()`, which never
  raises -- a transport failure (guest unreachable, timeout) or an
  application-level failure (`success: false` in the envelope) both
  become a logged warning and a `None` return, exactly mirroring
  GuestAgent's `_run_quiet()` -> None-on-failure pattern, so callers at
  every level of this class read the same way.

  No shell, no stdout parsing on the HOST side of this transport either --
  `_request()` speaks JSON over HTTP via httpx; the guest-side elimination
  of shell/stdout parsing is the PowerShell implementation's own job (see
  the API spec's section 5-8 notes on ProcessStartInfo/ArgumentList).

  File transfer: `GET /filesystem/read` (API spec section 12.1) returns
  raw bytes outside the JSON envelope -- `_fetch_file()` is the one method
  in this class that does not go through `_request()`.

  Readiness: real-VM validation found a real startup-timing gap this
  class's other methods don't handle on their own -- immediately after VM
  boot, GET /health can refuse the connection for a short window before
  the guest-resident PowerShell HTTP agent (adam_agent.ps1) is actually
  listening, even though the VM/guest OS itself is already up (i.e. this
  is strictly AFTER SandboxController.prepare()'s own VirtualBox-level
  wait_for_guest_ready() has already succeeded -- it is not a VM boot
  problem, it's this specific HTTP service coming up slightly later).
  `wait_until_ready()` polls GET /health once a second until it returns
  HTTP 200 with a `success: true` envelope, or `guest_ready_timeout_s`
  (the SAME setting SandboxController already uses for VM-level readiness
  -- no second timeout config) expires, in which case it raises
  `adam.common.errors.GuestTimeoutError`. A successful check is cached for
  the lifetime of this instance (`self._ready`) -- once ready, this method
  is a no-op; nothing in this class proactively re-polls /health before
  later calls, so a guest that goes unhealthy mid-session is caught by
  those calls' own normal transport-error handling instead, exactly as
  requested. `verify_tools()` is the one caller (see its own docstring) --
  every other method assumes verify_tools() already ran, matching how
  SessionOrchestrator actually calls this class (adam/orchestrator/
  session.py: controller.prepare() -> controller.arm() -> guest_agent.
  verify_tools() -> start_captures() -> ... -> stop_export_and_fetch()).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import time
from pathlib import Path
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel

from adam.common.errors import GuestTimeoutError
from adam.sandbox.guest.agent.agent import TelemetryArtifacts, ToolAvailability
from adam.sandbox.guest.http_models import (
    BackingFileData,
    ErrorCode,
    ExistsData,
    GuestAgentError,
    GuestAgentUnreachableError,
    HealthData,
    MkdirRequest,
    NetworkConvertRequest,
    NetworkInterfacesData,
    NetworkStartRequest,
    NetworkStopRequest,
    ProcmonExportRequest,
    ProcmonStartRequest,
    ProcmonStopRequest,
    ResponseEnvelope,
    SysmonDiagnosticsData,
    SysmonExportData,
    SysmonExportRequest,
    TokenData,
    VersionData,
)

logger = logging.getLogger(__name__)

_ModelT = TypeVar("_ModelT", bound=BaseModel)

# Transport-level errors worth a short retry -- the guest agent momentarily
# unreachable (a Scheduled Task restart per install.ps1's RestartCount, a
# brief host-only-adapter network hiccup) is a real, expected class of
# failure this project's own real-VM history has already seen for the
# GuestControl backend (agent.py's "session leak"/timeout investigations).
# Deliberately narrow -- excludes generic httpx.HTTPError subclasses that
# don't indicate "try again might help" (e.g. httpx.InvalidURL).
_RETRYABLE_TRANSPORT_ERRORS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)


class HTTPGuestChannel:
    """GuestChannel backend driving the guest-resident PowerShell HTTP agent. See module docstring for the resilience contract every method follows."""

    def __init__(
        self,
        base_url: str,
        *,
        capture_dir: str,
        procmon_path: str | None,
        tshark_path: str | None,
        sysmon_log: str,
        tshark_interface: str = "1",
        request_timeout_s: float = 15.0,
        retry_attempts: int = 3,
        retry_backoff_s: float = 0.2,
        guest_ready_timeout_s: float = 150.0,
        readiness_poll_interval_s: float = 1.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """
        base_url: e.g. "http://192.168.56.101:8765" -- the guest's
        HttpListener endpoint (see install.ps1 for the default port).

        `retry_attempts`/`retry_backoff_s`: every call through `_request()`
        retries up to `retry_attempts` times (exponential backoff starting
        at `retry_backoff_s`) on a transient transport-level error (see
        `_RETRYABLE_TRANSPORT_ERRORS`) before giving up and returning None
        -- this does not change the "never raise" contract, only how much
        effort is spent before settling into the same None/logged-warning
        outcome a single failed attempt already produced. Set
        `retry_attempts=1` to disable retrying (e.g. in tests that want a
        transport failure to resolve immediately).

        `guest_ready_timeout_s`: default matches
        Settings.sandbox.guest_ready_timeout_s's own default (adam/common/
        config.py) -- callers built via adam/orchestrator/runner.py's
        Runner._build_guest_channel() pass that same setting explicitly, so
        this default only matters for a directly-constructed channel (e.g.
        a script or test) that doesn't. See `wait_until_ready()`.

        `readiness_poll_interval_s`: the 1-second poll cadence
        `wait_until_ready()` uses between GET /health attempts. Overridable
        (not just so tests can run fast without a real sleep -- see
        tests/integration/test_http_guest_channel.py -- but because it's
        the one number in this constructor that isn't itself sourced from
        Settings, per the "do not introduce another timeout configuration
        unless absolutely necessary" instruction this was built against;
        1.0 is the literal, explicitly requested default).

        `client` is injectable for tests (see
        tests/integration/test_http_guest_channel.py) -- defaults to a
        real httpx.AsyncClient against base_url.
        """
        self._base_url = base_url.rstrip("/")
        self._capture_dir = capture_dir
        self._procmon_path = procmon_path
        self._tshark_path = tshark_path
        self._sysmon_log = sysmon_log
        self._tshark_interface = tshark_interface
        self._default_timeout = request_timeout_s
        self._retry_attempts = max(1, retry_attempts)
        self._retry_backoff_s = retry_backoff_s
        self._guest_ready_timeout_s = guest_ready_timeout_s
        self._readiness_poll_interval_s = readiness_poll_interval_s
        self._ready = False
        self._client = client or httpx.AsyncClient(base_url=self._base_url, timeout=request_timeout_s)

    async def aclose(self) -> None:
        """Closes the underlying httpx client. Callers that inject their own `client` own its lifecycle instead."""
        await self._client.aclose()

    # ------------------------------------------------------------------ #
    # transport
    # ------------------------------------------------------------------ #

    async def _send_with_retry(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
        label: str = "",
    ) -> httpx.Response:
        """
        Low-level transport call, shared by `_request()` (never-raise
        callers) and `_get_raising()` (raising callers) -- retries a
        transient transport error (`_RETRYABLE_TRANSPORT_ERRORS`) up to
        `self._retry_attempts` times with exponential backoff, then
        re-raises the last exception so each of the two callers can
        translate it into its own contract (None+log for `_request()`,
        `GuestAgentUnreachableError` for `_get_raising()`). A non-retryable
        `httpx.HTTPError` (e.g. a malformed URL) is raised immediately, no
        retry budget spent on an error retrying can't fix.
        """
        last_exc: httpx.HTTPError | None = None
        for attempt in range(1, self._retry_attempts + 1):
            try:
                return await self._client.request(
                    method, path, json=json_body, params=params, timeout=timeout or self._default_timeout
                )
            except _RETRYABLE_TRANSPORT_ERRORS as exc:
                last_exc = exc
                if attempt < self._retry_attempts:
                    backoff = self._retry_backoff_s * (2 ** (attempt - 1))
                    logger.warning(
                        "guest_http: %s transient transport error on attempt %d/%d, retrying in %.2fs: %s",
                        label or path, attempt, self._retry_attempts, backoff, exc,
                    )
                    await asyncio.sleep(backoff)
                    continue
                logger.warning(
                    "guest_http: %s failed after %d attempt(s) (transport error): %s",
                    label or path, self._retry_attempts, exc,
                )
                raise

        assert last_exc is not None  # loop only exits via `return` (success) or `raise` above
        raise last_exc

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
        label: str = "",
    ) -> dict[str, Any] | None:
        """
        Issues one HTTP call, parses the response envelope, and returns
        `data` on success -- or logs a warning and returns None on ANY
        failure (transport error, timeout, or `success: false`), per this
        class's "never raise" resilience contract. `label` is a short,
        human-readable operation name for the warning log, matching
        GuestAgent's own `_run_quiet(..., label=...)` convention.

        Transient transport errors are retried via `_send_with_retry()`
        before this method settles into its normal None-returning failure
        path -- still never raises, just tries harder first.
        """
        try:
            response = await self._send_with_retry(
                method, path, json_body=json_body, params=params, timeout=timeout, label=label
            )
        except httpx.HTTPError:
            # _send_with_retry() already logged the specific reason
            # (retried-and-exhausted vs. non-retryable) -- nothing more to
            # log here, just settle into this method's None contract.
            return None

        try:
            envelope = ResponseEnvelope.model_validate(response.json())
        except Exception as exc:  # noqa: BLE001 -- guest returned unparseable JSON; treat as a failure, not a crash
            logger.warning(
                "guest_http: %s returned an unparseable response (status=%s): %s",
                label or path, response.status_code, exc,
            )
            return None

        if not envelope.success:
            logger.warning(
                "guest_http: %s failed -- error_code=%s error_message=%s",
                label or path, envelope.error_code, envelope.error_message,
            )
            return None

        return envelope.data or {}

    async def _fetch_file(self, guest_path: str, host_path: Path, *, label: str) -> str | None:
        """`GET /filesystem/read` -- raw bytes, outside the JSON envelope (API spec 12.1)."""
        try:
            response = await self._client.get(
                "/filesystem/read", params={"path": guest_path}, timeout=self._default_timeout
            )
        except httpx.HTTPError as exc:
            logger.warning("guest_http: %s failed to fetch %s (transport error): %s", label, guest_path, exc)
            return None

        if response.status_code != 200:
            error_code = response.headers.get("X-Error-Code", "UNKNOWN")
            logger.warning(
                "guest_http: %s failed to fetch %s -- status=%s error_code=%s",
                label, guest_path, response.status_code, error_code,
            )
            return None

        host_path.parent.mkdir(parents=True, exist_ok=True)
        host_path.write_bytes(response.content)
        logger.info("[HTTPGuestChannel] fetched %s -> %s (%d bytes)", guest_path, host_path, len(response.content))
        return str(host_path)

    # ------------------------------------------------------------------ #
    # Readiness -- HTTP backend only (VBoxGuestChannel is unaffected: it
    # has no analogous "the transport itself needs a moment to come up"
    # problem, since GuestControl calls go through VBoxManage/the
    # hypervisor's own guest-addition channel, not a guest-resident HTTP
    # listener started via a Scheduled Task). See module docstring's
    # "Readiness" paragraph for the full design rationale.
    # ------------------------------------------------------------------ #

    async def _probe_health_once(self) -> tuple[bool, str]:
        """
        One single, non-retried GET /health attempt. Returns
        (healthy, detail) -- never raises; every failure mode
        (unreachable, non-200, unparseable body, success=false) is folded
        into `healthy=False` so `wait_until_ready()`'s polling loop can
        treat all of them identically ("not ready yet, try again"),
        exactly as the requirement specifies ("malformed JSON... treat it
        as not ready", not as a hard error).

        Deliberately bypasses `_send_with_retry()`/`_request()`: those
        implement their OWN short exponential-backoff retry loop for a
        transient error, which would make each of `wait_until_ready()`'s
        1-second-spaced "Attempt N" log lines secretly take longer than
        1 second and retry more than once per attempt -- confusing given
        the explicit "1 second interval" requirement. The outer
        `wait_until_ready()` loop IS this method's retry strategy.
        """
        try:
            response = await self._client.get("/health", timeout=self._default_timeout)
        except httpx.HTTPError as exc:
            return False, f"transport error: {exc}"

        if response.status_code != 200:
            return False, f"HTTP {response.status_code}"

        try:
            envelope = ResponseEnvelope.model_validate(response.json())
        except Exception as exc:  # noqa: BLE001 -- malformed/non-JSON body -- "not ready", not a crash
            return False, f"malformed response: {exc}"

        if not envelope.success:
            return False, f"success=false (error_code={envelope.error_code})"

        return True, "ok"

    async def wait_until_ready(self, timeout_s: float | None = None) -> None:
        """
        Polls GET /health at `self._readiness_poll_interval_s` (default
        1s) intervals until it reports healthy or `timeout_s` (default
        `self._guest_ready_timeout_s`, i.e. the SAME
        Settings.sandbox.guest_ready_timeout_s VM-level readiness already
        uses -- no second timeout config introduced) elapses.

        No sleep before the FIRST attempt -- it fires immediately on
        entry, so a guest that's already up returns right away with zero
        added latency; the 1-second wait only happens BETWEEN a failed
        attempt and the next one. This deliberately does not duplicate
        VM-level boot detection: by the time anything calls this method
        (verify_tools(), in the real session flow -- see module
        docstring), SandboxController.prepare() has already run its own
        wait_for_guest_ready() check and confirmed the VM/guest OS itself
        is reachable. A timeout here means specifically that the VM booted
        but the guest-resident HTTP agent (adam_agent.ps1) never came up
        on top of that -- distinct from a VM boot failure, which would
        have already raised (a VMOperationError) inside prepare(), earlier
        in the call chain, before this method could ever run.

        Caches success on `self._ready` -- a second call after a
        successful first one returns immediately without issuing another
        HTTP request, so a long-running session's later guest-channel
        calls never proactively re-check /health; per the explicit
        instruction this was built against, a later request that actually
        fails is left to its own normal error handling instead.

        Raises `adam.common.errors.GuestTimeoutError` if the timeout
        expires without a healthy response.
        """
        if self._ready:
            return

        effective_timeout = timeout_s if timeout_s is not None else self._guest_ready_timeout_s
        started = time.monotonic()
        deadline = started + effective_timeout
        attempt = 0

        logger.info(
            "guest_http: Waiting for HTTP guest agent... (base_url=%s, timeout=%.1fs, poll_interval=%.1fs)",
            self._base_url, effective_timeout, self._readiness_poll_interval_s,
        )

        while True:
            attempt += 1
            logger.info("guest_http: Attempt %d", attempt)

            healthy, detail = await self._probe_health_once()
            if healthy:
                elapsed = time.monotonic() - started
                logger.info("guest_http: HTTP guest agent is healthy after %.1f seconds.", elapsed)
                self._ready = True
                return

            logger.debug("guest_http: Attempt %d not healthy yet -- %s", attempt, detail)

            if time.monotonic() >= deadline:
                elapsed = time.monotonic() - started
                logger.warning("guest_http: HTTP guest agent failed to become healthy before timeout.")
                raise GuestTimeoutError(
                    f"HTTP guest agent at {self._base_url} did not become healthy within "
                    f"{effective_timeout:.1f}s ({attempt} attempt(s), polling GET /health every "
                    f"{self._readiness_poll_interval_s:.1f}s; last elapsed={elapsed:.1f}s). The VM/guest "
                    "OS itself was already confirmed reachable by SandboxController.prepare()'s existing "
                    "wait_for_guest_ready() check before this method ever ran -- this is specifically the "
                    "guest-resident HTTP agent (adam_agent.ps1) never responding healthy on top of an "
                    f"already-booted VM, not a VM boot failure. Last observed state: {detail}"
                )

            await asyncio.sleep(self._readiness_poll_interval_s)

    # ------------------------------------------------------------------ #
    # GuestChannel: verify_tools
    # ------------------------------------------------------------------ #

    async def verify_tools(self) -> ToolAvailability:
        """
        Never raises (see module docstring's resilience contract). First
        action: wait for the HTTP guest agent to actually be reachable
        (`wait_until_ready()`) -- this is the one call site that method has
        in the whole class (see its own docstring and the module
        docstring's "Readiness" paragraph). A readiness timeout is caught
        here and folded into a normal, non-raising ToolAvailability(detail=
        {"agent": ...}) result instead of propagating -- `wait_until_ready()`
        itself stays independently raising (and directly unit-testable via
        pytest.raises) without breaking this method's own contract, which
        SessionOrchestrator (adam/orchestrator/session.py) and this
        codebase's tests already depend on.
        """
        detail: dict[str, str] = {}

        try:
            await self.wait_until_ready()
        except GuestTimeoutError as exc:
            detail["agent"] = str(exc)
            logger.warning("guest_http: tool unavailable -- agent: %s", detail["agent"])
            return ToolAvailability(
                procmon_available=False, tshark_available=False, sysmon_log_available=False, detail=detail
            )

        procmon_available = False
        if self._procmon_path is None:
            detail["procmon"] = "guest_tools.procmon_path is not configured"
        else:
            exists_data = await self._request(
                "GET", "/filesystem/exists", params={"path": self._procmon_path}, label="verify_tools: procmon path"
            )
            procmon_available = bool(exists_data and ExistsData.model_validate(exists_data).exists)
            if not procmon_available:
                detail["procmon"] = f"not found in guest at configured path {self._procmon_path!r}"

        tshark_available = False
        if self._tshark_path is None:
            detail["tshark"] = "guest_tools.tshark_path is not configured"
        else:
            exists_data = await self._request(
                "GET", "/filesystem/exists", params={"path": self._tshark_path}, label="verify_tools: tshark path"
            )
            tshark_available = bool(exists_data and ExistsData.model_validate(exists_data).exists)
            if not tshark_available:
                detail["tshark"] = f"not found in guest at configured path {self._tshark_path!r}"

        sysmon_data = await self._request(
            "GET", "/sysmon/diagnostics", params={"channel": self._sysmon_log}, label="verify_tools: sysmon channel"
        )
        sysmon_log_available = bool(sysmon_data and SysmonDiagnosticsData.model_validate(sysmon_data).channel_available)
        if not sysmon_log_available:
            detail["sysmon"] = f"event log channel {self._sysmon_log!r} not available"

        for tool, reason in detail.items():
            logger.warning("guest_http: tool unavailable -- %s: %s", tool, reason)

        return ToolAvailability(
            procmon_available=procmon_available,
            tshark_available=tshark_available,
            sysmon_log_available=sysmon_log_available,
            detail=detail,
        )

    # ------------------------------------------------------------------ #
    # GuestChannel: start_captures
    # ------------------------------------------------------------------ #

    def _guest_path(self, filename: str) -> str:
        return f"{self._capture_dir}\\{filename}"

    async def start_captures(
        self,
        session_id: str,
        *,
        capture_procmon: bool = True,
        capture_network: bool = True,
    ) -> None:
        await self._request(
            "POST", "/filesystem/mkdir", json_body=MkdirRequest(path=self._capture_dir).model_dump(),
            label="start_captures: mkdir capture_dir",
        )

        if capture_procmon and self._procmon_path is not None:
            pml_path = self._guest_path(f"{session_id}_procmon.pml")
            result = await self._request(
                "POST", "/procmon/start",
                json_body=ProcmonStartRequest(session_id=session_id, backing_file=pml_path).model_dump(),
                label="start_captures: procmon",
            )
            logger.info("[HTTPGuestChannel] session=%s procmon start result=%s", session_id, result)

        if capture_network and self._tshark_path is not None:
            interfaces = await self._request("GET", "/network/interfaces", label="start_captures: list interfaces")
            if interfaces is not None:
                logger.info(
                    "[HTTPGuestChannel] session=%s available interfaces: %s",
                    session_id, NetworkInterfacesData.model_validate(interfaces).interfaces,
                )
            pcap_path = self._guest_path(f"{session_id}_network.pcapng")
            result = await self._request(
                "POST", "/network/start",
                json_body=NetworkStartRequest(
                    session_id=session_id, interface=self._tshark_interface, pcap_path=pcap_path
                ).model_dump(),
                label="start_captures: tshark",
            )
            logger.info("[HTTPGuestChannel] session=%s tshark start result=%s", session_id, result)

    # ------------------------------------------------------------------ #
    # GuestChannel: stop_export_and_fetch
    # ------------------------------------------------------------------ #

    async def stop_export_and_fetch(
        self,
        session_id: str,
        host_artifact_dir: str | Path,
        *,
        export_sysmon: bool = True,
        export_procmon: bool = True,
        export_network: bool = True,
    ) -> TelemetryArtifacts:
        host_dir = Path(host_artifact_dir)
        host_dir.mkdir(parents=True, exist_ok=True)

        sysmon_path = await self._export_sysmon(session_id, host_dir) if export_sysmon else None
        procmon_path = await self._export_procmon(session_id, host_dir) if export_procmon else None
        network_path = await self._export_network(session_id, host_dir) if export_network else None

        return TelemetryArtifacts(
            sysmon_evtx_path=sysmon_path,
            procmon_csv_path=procmon_path,
            network_ek_json_path=network_path,
        )

    async def _export_sysmon(self, session_id: str, host_dir: Path) -> str | None:
        guest_evtx = self._guest_path(f"{session_id}_sysmon.evtx")
        result = await self._request(
            "POST", "/sysmon/export",
            json_body=SysmonExportRequest(channel=self._sysmon_log, output_path=guest_evtx).model_dump(),
            label="stop_export_and_fetch: sysmon export",
        )
        if result is None:
            return None
        mechanism = SysmonExportData.model_validate(result).mechanism if "mechanism" in result else "unknown"
        logger.info("[HTTPGuestChannel] session=%s sysmon exported via %s", session_id, mechanism)
        return await self._fetch_file(guest_evtx, host_dir / "sysmon.evtx", label=f"session={session_id} sysmon")

    async def _export_procmon(self, session_id: str, host_dir: Path) -> str | None:
        if self._procmon_path is None:
            return None
        pml_path = self._guest_path(f"{session_id}_procmon.pml")
        csv_path = self._guest_path(f"{session_id}_procmon.csv")

        await self._request(
            "POST", "/procmon/stop",
            json_body=ProcmonStopRequest(session_id=session_id).model_dump(),
            label="stop_export_and_fetch: procmon stop",
        )

        backing = await self._request(
            "GET", "/procmon/verify-backing-file", params={"path": pml_path}, label="stop_export_and_fetch: verify pml"
        )
        if backing is None or not BackingFileData.model_validate(backing).exists:
            logger.warning(
                "guest_http: session=%s no Procmon backing file at %s -- procmon telemetry unavailable this session",
                session_id, pml_path,
            )
            return None

        result = await self._request(
            "POST", "/procmon/export",
            json_body=ProcmonExportRequest(pml_path=pml_path, csv_path=csv_path).model_dump(),
            label="stop_export_and_fetch: procmon export",
        )
        if result is None:
            return None
        return await self._fetch_file(csv_path, host_dir / "procmon.csv", label=f"session={session_id} procmon")

    async def _export_network(self, session_id: str, host_dir: Path) -> str | None:
        if self._tshark_path is None:
            return None
        pcap_path = self._guest_path(f"{session_id}_network.pcapng")
        ek_path = self._guest_path(f"{session_id}_network.ek.json")

        await self._request(
            "POST", "/network/stop",
            json_body=NetworkStopRequest(session_id=session_id).model_dump(),
            label="stop_export_and_fetch: tshark stop",
        )

        result = await self._request(
            "POST", "/network/convert",
            json_body=NetworkConvertRequest(pcap_path=pcap_path, ek_json_path=ek_path).model_dump(),
            label="stop_export_and_fetch: tshark convert",
        )
        if result is None:
            return None
        return await self._fetch_file(ek_path, host_dir / "network.ek.json", label=f"session={session_id} network")

    # ------------------------------------------------------------------ #
    # Diagnostics -- structured token/privilege data, not whoami text
    # ------------------------------------------------------------------ #

    async def get_token_diagnostics(self) -> TokenData | None:
        """
        Structured replacement for VBoxGuestChannel's whoami-text-parsing
        diagnostics (agent.py's `_whoami_diagnostics()`). Exposed as a
        method on this class rather than GuestChannel itself -- it isn't
        part of the shared session lifecycle, just a diagnostic exposed by
        this specific backend.
        """
        result = await self._request("GET", "/diagnostics/token", label="get_token_diagnostics")
        return TokenData.model_validate(result) if result is not None else None

    # ------------------------------------------------------------------ #
    # Explicit, RAISING diagnostics -- deliberately NOT used by
    # verify_tools/start_captures/stop_export_and_fetch above (those keep
    # the "never raise" contract this whole class exists to provide, per
    # ARCHITECTURE.md section 14.4's "partial results are still evidence"
    # philosophy: SessionOrchestrator.run_session() treats a down guest
    # agent as a reason to degrade to PARTIAL telemetry, not to abort
    # sample detonation). get_health()/get_version() are for a caller that
    # explicitly wants a fail-fast, exception-raising check instead -- a
    # manual troubleshooting step, or a future `adam guest-check` CLI
    # command -- the host-side mirror of install.ps1's own Test-Deployment
    # /health check (docs/phase5-migration-guide.md step 3, "Verify
    # manually").
    # ------------------------------------------------------------------ #

    async def _get_raising(self, path: str, model: type[_ModelT]) -> _ModelT:
        try:
            response = await self._send_with_retry("GET", path, timeout=self._default_timeout, label=path)
        except httpx.HTTPError as exc:
            raise GuestAgentUnreachableError(
                f"could not reach guest agent at {self._base_url}{path} (after retrying): {exc}. "
                "Confirm install.ps1 completed successfully on the guest (see "
                "docs/phase5-migration-guide.md) and that this base_url is the guest's "
                "correct host-only-adapter IP/port."
            ) from exc

        try:
            envelope = ResponseEnvelope.model_validate(response.json())
        except Exception as exc:  # noqa: BLE001 -- guest returned unparseable JSON
            raise GuestAgentUnreachableError(
                f"guest agent at {self._base_url}{path} returned an unparseable response "
                f"(status={response.status_code}): {exc}"
            ) from exc

        if not envelope.success:
            raise GuestAgentError(envelope.error_code, envelope.error_message)

        return model.model_validate(envelope.data or {})

    async def get_health(self) -> HealthData:
        """Raises GuestAgentUnreachableError (transport/parse failure) or GuestAgentError (guest reached but reported success=false) instead of returning None -- see the section docstring above for why this is separate from verify_tools()."""
        return await self._get_raising("/health", HealthData)

    async def get_version(self) -> VersionData:
        """Same raising contract as get_health() -- see the section docstring above."""
        return await self._get_raising("/version", VersionData)


def verify_sample_hash(content: bytes, expected_sha256: str) -> bool:
    """Host-side helper mirroring the guest's own upload-time verification -- used by callers before calling /sample/upload, per defense in depth (spec section 10)."""
    return hashlib.sha256(content).hexdigest().lower() == expected_sha256.lower()


def encode_sample_for_upload(content: bytes) -> str:
    """base64-encodes sample bytes for the /sample/upload JSON body (spec section 10)."""
    return base64.b64encode(content).decode("ascii")


__all__ = [
    "HTTPGuestChannel",
    "ErrorCode",
    "GuestAgentError",
    "GuestAgentUnreachableError",
    "verify_sample_hash",
    "encode_sample_for_upload",
]
