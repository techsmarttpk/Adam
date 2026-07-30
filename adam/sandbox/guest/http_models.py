"""
adam/sandbox/guest/http_models.py

Host-side Pydantic models for the Phase 5 guest agent HTTP API -- see
docs/phase5-http-agent-api.md for the full, authoritative spec both this
file and the guest-side PowerShell implementation
(adam/sandbox/guest/agent/adam_agent.ps1 + modules/*.psm1) are written
against. There is no shared runtime between Python and PowerShell, so
these models are this side's own typed view of the wire format, not
generated from or shared with the guest implementation -- keeping the two
in sync is the API spec doc's job, verified by
tests/integration/test_http_guest_channel.py's mock-server tests.

Only the request/response shapes HTTPGuestChannel actually calls are
modelled as full Pydantic classes; the response envelope
(`ResponseEnvelope`) is generic over `data`'s shape via a plain dict,
parsed into the specific `*Data` model by whichever method received it --
this avoids fighting Pydantic's generics for a one-off internal client
where each call site already knows exactly which shape to expect.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# --------------------------------------------------------------------- #
# Envelope + error codes (spec section 2)
# --------------------------------------------------------------------- #


class ErrorCode:
    """String constants matching docs/phase5-http-agent-api.md section 2.1 -- not a Python Enum so a JSON string compares equal without a cast."""

    NOT_FOUND = "NOT_FOUND"
    ALREADY_EXISTS = "ALREADY_EXISTS"
    ACCESS_DENIED = "ACCESS_DENIED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    TIMEOUT = "TIMEOUT"
    TOOL_NOT_CONFIGURED = "TOOL_NOT_CONFIGURED"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class GuestAgentError(Exception):
    """Raised by HTTPGuestChannel's explicit, opt-in diagnostic methods (get_health()/get_version()) when a guest agent call returns success=false. Carries the structured error_code, never a parsed text message alone. NOT raised by any GuestChannel Protocol method (verify_tools/start_captures/stop_export_and_fetch) -- those follow this class's documented "never raise" resilience contract instead; see http_channel.py's module docstring."""

    def __init__(self, error_code: str | None, error_message: str | None) -> None:
        self.error_code = error_code
        self.error_message = error_message
        super().__init__(f"{error_code}: {error_message}")


class GuestAgentUnreachableError(GuestAgentError):
    """
    Raised by get_health()/get_version() when the guest agent's HTTP
    endpoint could not be reached or returned an unparseable response at
    all -- distinct from the base GuestAgentError case (endpoint reached,
    but the envelope itself reported success=false with a real guest-side
    error_code). error_code is fixed to "TRANSPORT_ERROR", a host-side-only
    synthetic value -- not one of docs/phase5-http-agent-api.md section
    2.1's guest-reported codes, since the guest never got a chance to
    report anything.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(error_code="TRANSPORT_ERROR", error_message=detail)


class ResponseEnvelope(BaseModel):
    """Every JSON endpoint's top-level shape (spec section 2) except `GET /filesystem/read`, which returns raw bytes."""

    success: bool
    error_code: str | None = None
    error_message: str | None = None
    data: dict[str, Any] | None = None


# --------------------------------------------------------------------- #
# Health / Version (spec section 3)
# --------------------------------------------------------------------- #


class HealthData(BaseModel):
    status: str
    uptime_s: float


class VersionData(BaseModel):
    agent_version: str
    api_version: str


# --------------------------------------------------------------------- #
# Filesystem (spec section 4)
# --------------------------------------------------------------------- #


class MkdirRequest(BaseModel):
    path: str


class MkdirData(BaseModel):
    created: bool
    already_existed: bool


class ExistsData(BaseModel):
    exists: bool
    is_directory: bool
    size_bytes: int | None = None


class CopyRequest(BaseModel):
    source: str
    destination: str
    overwrite: bool = False


class CopyData(BaseModel):
    copied: bool


class MoveRequest(BaseModel):
    source: str
    destination: str
    overwrite: bool = False


class MoveData(BaseModel):
    moved: bool


class DeleteRequest(BaseModel):
    path: str
    recursive: bool = False


class DeleteData(BaseModel):
    deleted: bool


class FileEntry(BaseModel):
    name: str
    is_directory: bool
    size_bytes: int
    modified_utc: str


class ListData(BaseModel):
    entries: list[FileEntry]


# --------------------------------------------------------------------- #
# Process (spec section 5)
# --------------------------------------------------------------------- #


class ProcessStartRequest(BaseModel):
    executable: str
    arguments: list[str] = Field(default_factory=list)
    working_directory: str | None = None
    wait: bool = False
    timeout_s: float | None = None


class ProcessStartData(BaseModel):
    pid: int
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None


class ProcessTerminateRequest(BaseModel):
    pid: int | None = None
    name: str | None = None


class ProcessTerminateData(BaseModel):
    terminated_count: int


class ProcessWaitRequest(BaseModel):
    pid: int
    timeout_s: float


class ProcessWaitData(BaseModel):
    exited: bool
    exit_code: int | None = None


class ProcessInfo(BaseModel):
    pid: int
    name: str
    command_line: str
    session_id: int


class ProcessQueryData(BaseModel):
    processes: list[ProcessInfo]


# --------------------------------------------------------------------- #
# Procmon (spec section 6)
# --------------------------------------------------------------------- #


class ProcmonStartRequest(BaseModel):
    session_id: str
    backing_file: str


class ProcmonStartData(BaseModel):
    pid: int


class ProcmonStopRequest(BaseModel):
    session_id: str


class ProcmonStopData(BaseModel):
    stopped: bool


class ProcmonExportRequest(BaseModel):
    pml_path: str
    csv_path: str


class ProcmonExportData(BaseModel):
    csv_path: str


class BackingFileData(BaseModel):
    exists: bool
    size_bytes: int | None = None


# --------------------------------------------------------------------- #
# Network / tshark (spec section 7)
# --------------------------------------------------------------------- #


class NetworkInterface(BaseModel):
    index: str
    description: str


class NetworkInterfacesData(BaseModel):
    interfaces: list[NetworkInterface]


class NetworkStartRequest(BaseModel):
    session_id: str
    interface: str
    pcap_path: str


class NetworkStartData(BaseModel):
    pid: int


class NetworkStopRequest(BaseModel):
    session_id: str


class NetworkStopData(BaseModel):
    stopped: bool


class NetworkConvertRequest(BaseModel):
    pcap_path: str
    ek_json_path: str


class NetworkConvertData(BaseModel):
    ek_json_path: str


# --------------------------------------------------------------------- #
# Sysmon (spec section 8)
# --------------------------------------------------------------------- #


class SysmonExportRequest(BaseModel):
    channel: str
    output_path: str


class SysmonExportData(BaseModel):
    output_path: str
    mechanism: str  # "wevtutil" | "raw_copy"


class SysmonDiagnosticsData(BaseModel):
    channel_available: bool
    event_count: int | None = None


# --------------------------------------------------------------------- #
# Diagnostics (spec section 9)
# --------------------------------------------------------------------- #


class TokenGroup(BaseModel):
    name: str
    attributes: list[str]


class TokenPrivilege(BaseModel):
    name: str
    state: str


class TokenData(BaseModel):
    groups: list[TokenGroup]
    privileges: list[TokenPrivilege]
    integrity_level: str
    is_elevated: bool


class ServiceInfo(BaseModel):
    name: str
    status: str
    start_type: str


class ServicesData(BaseModel):
    services: list[ServiceInfo]


class DriverInfo(BaseModel):
    name: str
    state: str


class DriversData(BaseModel):
    drivers: list[DriverInfo]


# --------------------------------------------------------------------- #
# Sample (spec section 10)
# --------------------------------------------------------------------- #


class SampleUploadRequest(BaseModel):
    filename: str
    sha256: str
    content_base64: str


class SampleUploadData(BaseModel):
    staged_path: str
    sha256_verified: bool


class SampleStageRequest(BaseModel):
    staged_path: str
    target_path: str


class SampleStageData(BaseModel):
    target_path: str


# --------------------------------------------------------------------- #
# Artifact (spec section 11)
# --------------------------------------------------------------------- #


class ArtifactInfo(BaseModel):
    name: str
    path: str
    size_bytes: int
    kind: str


class ArtifactListData(BaseModel):
    artifacts: list[ArtifactInfo]


class ArtifactPackageRequest(BaseModel):
    session_id: str
    paths: list[str]
    output_zip: str


class ArtifactPackageData(BaseModel):
    zip_path: str
    entry_count: int


class ArtifactMetadataData(BaseModel):
    size_bytes: int
    sha256: str
    modified_utc: str
