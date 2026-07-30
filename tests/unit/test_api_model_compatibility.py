"""
tests/unit/test_api_model_compatibility.py

Cross-checks every documented endpoint in docs/phase5-http-agent-api.md
against the host-side Pydantic models in adam/sandbox/guest/http_models.py
-- field-for-field, not just "the route exists" (that's already covered
by tests/unit/test_guest_service_static_structure.py's
test_route_table_covers_every_get_and_post_in_api_spec, which only checks
adam_agent.ps1's router against the spec, not the Python model layer at
all).

This test parses each spec table row's "Request body" and "data on
success" columns (a pseudo-JSON-schema string like `{"path": str}`) into a
set of top-level field names, and asserts that set matches the
corresponding Pydantic model's `model_fields.keys()` exactly. The mapping
from (method, path) to (RequestModel, DataModel) is explicit, not
inferred, so this test is itself an auditable cross-reference in addition
to a regression check.

Building this test surfaced six endpoints the spec documents and the
guest-side PowerShell fully implements, but that had NO corresponding
host-side Pydantic model at all: /filesystem/move, /process/wait,
/procmon/stop, /network/stop, /sample/stage, /artifact/package. All six
were added to http_models.py as part of this same change (see git history
/ delivery report) -- this test is what would have caught that gap
immediately, and is what keeps it from silently recurring.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from adam.sandbox.guest import http_models as hm

API_SPEC_PATH = Path(__file__).resolve().parents[2] / "docs" / "phase5-http-agent-api.md"


def _extract_top_level_field_names(cell: str) -> set[str] | None:
    """
    Parses a markdown table cell like `{"path": str}` or
    `{"exists": bool, "is_directory": bool, "size_bytes": int\\|null}` into
    {"path"} / {"exists", "is_directory", "size_bytes"} -- only fields at
    brace-depth 1 (immediately inside the outermost `{}`), so a nested
    object/array (e.g. `{"entries": [{"name": str, ...}]}`) contributes
    only "entries" at this level, not the nested item's own fields (those
    belong to a different, nested model -- e.g. FileEntry -- not the
    top-level ListData this cell is being checked against).

    Returns None for an empty cell / em-dash (no request body / no data).
    """
    cell = cell.strip().strip("`").strip()
    if cell in ("", "—", "-", "—"):
        return None
    if not cell.startswith("{"):
        return None

    depth = 0
    fields: set[str] = set()
    key_pattern = re.compile(r'"?([A-Za-z_][A-Za-z0-9_]*)"?\s*:')
    i = 0
    n = len(cell)
    while i < n:
        ch = cell[i]
        if ch == "{":
            depth += 1
            i += 1
            continue
        if ch == "}":
            depth -= 1
            i += 1
            continue
        if ch == "[":
            depth += 1
            i += 1
            continue
        if ch == "]":
            depth -= 1
            i += 1
            continue
        if depth == 1:
            match = key_pattern.match(cell, i)
            if match:
                fields.add(match.group(1))
                i = match.end()
                continue
        i += 1
    return fields


_PIPE_PLACEHOLDER = "\x00ESCAPED_PIPE\x00"


def _split_table_row(line: str) -> list[str] | None:
    """
    Splits one `| a | b | c | d |` markdown table row into
    ["a", "b", "c", "d"], correctly ignoring markdown's own escaped `\\|`
    (used throughout this spec for union types like `int\\|null`) as a
    column delimiter -- a naive `line.split("|")` or a single non-greedy
    regex across the whole line both mis-split on those escaped pipes,
    since they're visually indistinguishable from a real delimiter to
    anything that doesn't first protect them. Returns None for a line
    that isn't a table row at all.
    """
    line = line.strip()
    if not (line.startswith("|") and line.endswith("|")):
        return None
    protected = line.replace("\\|", _PIPE_PLACEHOLDER)
    parts = protected.split("|")
    # A well-formed `| a | b |` row split on "|" yields ["", " a ", " b ", ""] -- drop the outer empties.
    if len(parts) < 2 or parts[0].strip() or parts[-1].strip():
        return None
    cells = [p.replace(_PIPE_PLACEHOLDER, "\\|").strip() for p in parts[1:-1]]
    return cells


def _parse_spec_rows() -> dict[tuple[str, str], tuple[set[str] | None, set[str] | None]]:
    """
    Parses every `| GET|POST | `/path` | request_cell | data_cell |` row
    in the API spec into {(method, path): (request_fields, data_fields)}.
    Skips section 2's example envelope blocks (fenced ```json, not table
    rows) and health/version (handled separately below, since they're
    prose-formatted, not a markdown table).
    """
    text = API_SPEC_PATH.read_text(encoding="utf-8")
    rows: dict[tuple[str, str], tuple[set[str] | None, set[str] | None]] = {}

    for line in text.splitlines():
        cells = _split_table_row(line)
        if cells is None or len(cells) != 4:
            continue
        method_cell, path_cell, request_cell, data_cell = cells
        if method_cell not in ("GET", "POST"):
            continue
        path_match = re.match(r"^`([^`]+)`$", path_cell)
        if not path_match:
            continue
        path = path_match.group(1).split("?")[0]
        # Table cells escape markdown's own column separator as `\|` --
        # unescape before parsing so `int\|null` reads as `int|null`.
        request_cell = request_cell.replace("\\|", "|")
        data_cell = data_cell.replace("\\|", "|")
        rows[(method_cell, path)] = (
            _extract_top_level_field_names(request_cell),
            _extract_top_level_field_names(data_cell),
        )
    return rows


# (method, path) -> (RequestModel or None, DataModel or None). Explicit,
# not inferred -- doubles as the human-readable cross-reference between
# the spec and http_models.py.
_ENDPOINT_MODELS: dict[tuple[str, str], tuple[type[hm.BaseModel] | None, type[hm.BaseModel] | None]] = {
    ("GET", "/health"): (None, hm.HealthData),
    ("GET", "/version"): (None, hm.VersionData),
    ("POST", "/filesystem/mkdir"): (hm.MkdirRequest, hm.MkdirData),
    ("GET", "/filesystem/exists"): (None, hm.ExistsData),
    ("POST", "/filesystem/copy"): (hm.CopyRequest, hm.CopyData),
    ("POST", "/filesystem/move"): (hm.MoveRequest, hm.MoveData),
    ("POST", "/filesystem/delete"): (hm.DeleteRequest, hm.DeleteData),
    ("GET", "/filesystem/list"): (None, hm.ListData),
    ("POST", "/process/start"): (hm.ProcessStartRequest, hm.ProcessStartData),
    ("POST", "/process/terminate"): (hm.ProcessTerminateRequest, hm.ProcessTerminateData),
    ("POST", "/process/wait"): (hm.ProcessWaitRequest, hm.ProcessWaitData),
    ("GET", "/process/query"): (None, hm.ProcessQueryData),
    ("POST", "/procmon/start"): (hm.ProcmonStartRequest, hm.ProcmonStartData),
    ("POST", "/procmon/stop"): (hm.ProcmonStopRequest, hm.ProcmonStopData),
    ("POST", "/procmon/export"): (hm.ProcmonExportRequest, hm.ProcmonExportData),
    ("GET", "/procmon/verify-backing-file"): (None, hm.BackingFileData),
    ("GET", "/network/interfaces"): (None, hm.NetworkInterfacesData),
    ("POST", "/network/start"): (hm.NetworkStartRequest, hm.NetworkStartData),
    ("POST", "/network/stop"): (hm.NetworkStopRequest, hm.NetworkStopData),
    ("POST", "/network/convert"): (hm.NetworkConvertRequest, hm.NetworkConvertData),
    ("POST", "/sysmon/export"): (hm.SysmonExportRequest, hm.SysmonExportData),
    ("GET", "/sysmon/diagnostics"): (None, hm.SysmonDiagnosticsData),
    ("GET", "/diagnostics/token"): (None, hm.TokenData),
    ("GET", "/diagnostics/services"): (None, hm.ServicesData),
    ("GET", "/diagnostics/drivers"): (None, hm.DriversData),
    ("POST", "/sample/upload"): (hm.SampleUploadRequest, hm.SampleUploadData),
    ("POST", "/sample/stage"): (hm.SampleStageRequest, hm.SampleStageData),
    ("GET", "/artifact/list"): (None, hm.ArtifactListData),
    ("POST", "/artifact/package"): (hm.ArtifactPackageRequest, hm.ArtifactPackageData),
    ("GET", "/artifact/metadata"): (None, hm.ArtifactMetadataData),
}


def test_spec_parser_finds_every_mapped_endpoint() -> None:
    """Sanity check on the parser itself -- every (method, path) this test knows how to check must actually appear as a table row in the spec (catches a doc rewrite that silently drops/renames a row before the real per-field checks below would produce a confusing failure)."""
    parsed = _parse_spec_rows()
    for method, path in _ENDPOINT_MODELS:
        if (method, path) in (("GET", "/health"), ("GET", "/version")):
            continue  # prose-formatted, not table rows -- see _parse_spec_rows()'s docstring
        assert (method, path) in parsed, f"{method} {path} is mapped in this test but not found as a spec table row"


@pytest.mark.parametrize(
    "method,path",
    [(m, p) for (m, p) in _ENDPOINT_MODELS if (m, p) not in (("GET", "/health"), ("GET", "/version"))],
)
def test_endpoint_models_match_spec_fields(method: str, path: str) -> None:
    parsed = _parse_spec_rows()
    request_fields_doc, data_fields_doc = parsed[(method, path)]
    request_model, data_model = _ENDPOINT_MODELS[(method, path)]

    if request_fields_doc is None:
        assert request_model is None, f"{method} {path}: spec documents no request body, but {request_model} exists"
    else:
        assert request_model is not None, f"{method} {path}: spec documents a request body {request_fields_doc}, but no Request model is mapped"
        assert set(request_model.model_fields.keys()) == request_fields_doc, (
            f"{method} {path}: {request_model.__name__} fields {set(request_model.model_fields.keys())} "
            f"!= spec's documented request fields {request_fields_doc}"
        )

    assert data_fields_doc is not None, f"{method} {path}: spec row has no parseable 'data on success' cell"
    assert data_model is not None, f"{method} {path}: spec documents data fields {data_fields_doc}, but no Data model is mapped"
    assert set(data_model.model_fields.keys()) == data_fields_doc, (
        f"{method} {path}: {data_model.__name__} fields {set(data_model.model_fields.keys())} "
        f"!= spec's documented data fields {data_fields_doc}"
    )


def test_health_and_version_models_match_spec() -> None:
    """/health and /version are documented as prose ```json examples, not table rows -- checked directly against the spec's example blocks instead of the table parser above."""
    text = API_SPEC_PATH.read_text(encoding="utf-8")

    health_example = re.search(r'"status":\s*"ok",\s*"uptime_s":\s*[\d.]+', text)
    assert health_example is not None, "docs/phase5-http-agent-api.md's /health example block not found or changed shape"
    assert set(hm.HealthData.model_fields.keys()) == {"status", "uptime_s"}

    version_example = re.search(r'"agent_version":\s*"[^"]+",\s*"api_version":\s*"[^"]+"', text)
    assert version_example is not None, "docs/phase5-http-agent-api.md's /version example block not found or changed shape"
    assert set(hm.VersionData.model_fields.keys()) == {"agent_version", "api_version"}


def test_no_endpoint_models_are_unmapped_or_orphaned() -> None:
    """
    Every *Request/*Data class defined in http_models.py should be
    reachable from _ENDPOINT_MODELS above (an unreferenced model is either
    dead code or a model this test forgot to wire in) -- except the
    envelope/nested-item helper types, which aren't top-level
    endpoint models.
    """
    not_endpoint_models = {
        "ResponseEnvelope", "GuestAgentError", "GuestAgentUnreachableError",
        "FileEntry", "ProcessInfo", "NetworkInterface", "TokenGroup",
        "TokenPrivilege", "ServiceInfo", "DriverInfo", "ArtifactInfo",
    }
    mapped_models = {m.__name__ for pair in _ENDPOINT_MODELS.values() for m in pair if m is not None}

    for name in dir(hm):
        obj = getattr(hm, name)
        if not isinstance(obj, type) or not issubclass(obj, hm.BaseModel):
            continue
        if obj is hm.BaseModel or name in not_endpoint_models:
            continue
        assert name in mapped_models, f"{name} is defined in http_models.py but not referenced by any endpoint in this test's _ENDPOINT_MODELS mapping"
