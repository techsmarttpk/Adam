"""
tests/unit/test_http_models.py

Serialization tests for adam.sandbox.guest.http_models -- verifies each
model round-trips against a JSON shape matching
docs/phase5-http-agent-api.md exactly, i.e. that the Python side actually
agrees with the spec the PowerShell guest side is independently written
against. This is the closest thing to a cross-language contract test
achievable without a real guest to talk to: it can't prove the PowerShell
side produces this shape, but it does prove the Python side's
expectations are internally consistent and match the documented spec.
"""

from __future__ import annotations

from adam.sandbox.guest.http_models import (
    ArtifactMetadataData,
    BackingFileData,
    ErrorCode,
    ExistsData,
    FileEntry,
    ListData,
    MkdirRequest,
    NetworkInterface,
    NetworkInterfacesData,
    ProcessInfo,
    ProcessQueryData,
    ProcessStartRequest,
    ResponseEnvelope,
    SysmonExportData,
    TokenData,
    TokenGroup,
    TokenPrivilege,
)


def test_success_envelope_round_trip() -> None:
    raw = {"success": True, "error_code": None, "error_message": None, "data": {"status": "ok", "uptime_s": 12.5}}
    envelope = ResponseEnvelope.model_validate(raw)
    assert envelope.success is True
    assert envelope.data == {"status": "ok", "uptime_s": 12.5}
    assert envelope.model_dump() == raw


def test_error_envelope_round_trip() -> None:
    raw = {"success": False, "error_code": "ACCESS_DENIED", "error_message": "wevtutil epl: Access is denied.", "data": None}
    envelope = ResponseEnvelope.model_validate(raw)
    assert envelope.success is False
    assert envelope.error_code == ErrorCode.ACCESS_DENIED
    assert envelope.data is None


def test_mkdir_request_serializes_exact_spec_shape() -> None:
    request = MkdirRequest(path="C:\\ADAM\\telemetry")
    assert request.model_dump() == {"path": "C:\\ADAM\\telemetry"}


def test_process_start_request_defaults_match_spec() -> None:
    request = ProcessStartRequest(executable="C:\\Windows\\System32\\whoami.exe")
    dumped = request.model_dump()
    assert dumped["arguments"] == []
    assert dumped["working_directory"] is None
    assert dumped["wait"] is False
    assert dumped["timeout_s"] is None


def test_process_query_data_parses_cim_shaped_response() -> None:
    raw = {
        "processes": [
            {"pid": 4321, "name": "Procmon64.exe", "command_line": "Procmon64.exe /AcceptEula /Quiet", "session_id": 1},
        ]
    }
    data = ProcessQueryData.model_validate(raw)
    assert data.processes == [ProcessInfo(pid=4321, name="Procmon64.exe", command_line="Procmon64.exe /AcceptEula /Quiet", session_id=1)]


def test_token_data_parses_groups_privileges_integrity() -> None:
    raw = {
        "groups": [{"name": "BUILTIN\\Administrators", "attributes": ["deny_only"]}],
        "privileges": [{"name": "SeBackupPrivilege", "state": "Disabled"}],
        "integrity_level": "Medium",
        "is_elevated": False,
    }
    data = TokenData.model_validate(raw)
    assert data.groups == [TokenGroup(name="BUILTIN\\Administrators", attributes=["deny_only"])]
    assert data.privileges == [TokenPrivilege(name="SeBackupPrivilege", state="Disabled")]
    assert data.integrity_level == "Medium"
    assert data.is_elevated is False


def test_sysmon_export_data_mechanism_field() -> None:
    data = SysmonExportData.model_validate({"output_path": "C:\\ADAM\\telemetry\\x.evtx", "mechanism": "raw_copy"})
    assert data.mechanism == "raw_copy"


def test_network_interfaces_data() -> None:
    data = NetworkInterfacesData.model_validate(
        {"interfaces": [{"index": "1", "description": "Ethernet"}]}
    )
    assert data.interfaces == [NetworkInterface(index="1", description="Ethernet")]


def test_filesystem_list_data() -> None:
    data = ListData.model_validate(
        {"entries": [{"name": "a.txt", "is_directory": False, "size_bytes": 10, "modified_utc": "2026-07-28T00:00:00Z"}]}
    )
    assert data.entries == [FileEntry(name="a.txt", is_directory=False, size_bytes=10, modified_utc="2026-07-28T00:00:00Z")]


def test_backing_file_data_missing() -> None:
    data = BackingFileData.model_validate({"exists": False, "size_bytes": None})
    assert data.exists is False
    assert data.size_bytes is None


def test_artifact_metadata_data() -> None:
    data = ArtifactMetadataData.model_validate(
        {"size_bytes": 100, "sha256": "a" * 64, "modified_utc": "2026-07-28T00:00:00Z"}
    )
    assert data.sha256 == "a" * 64


def test_exists_data_directory_has_no_size() -> None:
    data = ExistsData.model_validate({"exists": True, "is_directory": True, "size_bytes": None})
    assert data.is_directory is True
    assert data.size_bytes is None
