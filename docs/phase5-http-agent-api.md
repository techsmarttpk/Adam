# Phase 5 Guest Agent HTTP API Specification

Status: implemented against this spec on the host side (`adam/sandbox/guest/http_channel.py`)
and the guest side (`adam/sandbox/guest/agent/adam_agent.ps1` + `modules/*.psm1`). This document
is the single source of truth both implementations are written against — there is no shared
runtime between Python (host) and PowerShell (guest), so this spec, not shared code, is what
keeps the two sides in sync.

## 1. Transport

- Protocol: plain HTTP/1.1 (not HTTPS — ARCHITECTURE.md section 4's "one-way-authenticated,
  host-only" isolated/host-only guest network already provides the trust boundary; this matches
  ARCHITECTURE.md's own diagram annotation `HTTPS ... host-only` loosely — TLS termination inside
  a throwaway malware-analysis guest adds operational complexity, mainly self-signed-cert
  distribution, for no real gain over the existing host-only network isolation. Flagged as a
  documented, deliberate simplification, not an oversight).
- Listener: guest-resident PowerShell 5.1 `System.Net.HttpListener`, bound to
  `http://0.0.0.0:8765/` inside the guest by default (configurable — see `install.ps1`).
- Host reaches it via the VirtualBox host-only adapter's guest IP (already resolvable the same
  way `wait_for_guest_ready` reaches the guest today).
- Every request and response body is JSON, `Content-Type: application/json`, UTF-8.
- No shell parsing, no stdout parsing anywhere in this transport — every field below is a real
  JSON value produced/consumed directly by PowerShell's `ConvertTo-Json`/`ConvertFrom-Json` and
  Python's `httpx`/`pydantic`, never scraped from a subprocess's text output.

## 2. Response envelope

Every endpoint returns this envelope, HTTP status `200` for `success: true`, and one of the HTTP
statuses in the error-code table below for `success: false` (the JSON body's `error_code` is the
authoritative signal; the HTTP status is a secondary, REST-conventional hint, not itself parsed
for control flow on the host side):

```json
{
  "success": true,
  "error_code": null,
  "error_message": null,
  "data": { }
}
```

```json
{
  "success": false,
  "error_code": "ACCESS_DENIED",
  "error_message": "wevtutil epl: Access is denied.",
  "data": null
}
```

### 2.1 Structured error codes

| error_code | HTTP status | Meaning |
|---|---|---|
| `NOT_FOUND` | 404 | Path, process, or resource does not exist |
| `ALREADY_EXISTS` | 409 | Target already exists and overwrite was not requested |
| `ACCESS_DENIED` | 403 | Underlying Windows API denied the operation (see `adam/sandbox/guest/agent/agent.py`'s "Known Issues" — the same filtered-token class of failure this endpoint now reports structurally instead of via `whoami` text-parsing) |
| `INVALID_ARGUMENT` | 400 | Request body failed validation |
| `TIMEOUT` | 504 | The underlying operation did not complete within its allotted time |
| `TOOL_NOT_CONFIGURED` | 412 | Procmon/tshark path not configured on the guest side |
| `TOOL_UNAVAILABLE` | 503 | Configured tool path does not exist in the guest |
| `INTERNAL_ERROR` | 500 | Unhandled guest-side exception; `error_message` carries the .NET exception message |

## 3. Health / Version

### `GET /health`
```json
{"success": true, "data": {"status": "ok", "uptime_s": 431.2}}
```

### `GET /version`
```json
{"success": true, "data": {"agent_version": "1.0.0", "api_version": "1"}}
```

## 4. Filesystem Manager — `/filesystem/*`

| Method | Path | Request body | `data` on success |
|---|---|---|---|
| POST | `/filesystem/mkdir` | `{"path": str}` | `{"created": bool, "already_existed": bool}` |
| GET | `/filesystem/exists?path=` | — | `{"exists": bool, "is_directory": bool, "size_bytes": int\|null}` |
| POST | `/filesystem/copy` | `{"source": str, "destination": str, "overwrite": bool}` | `{"copied": bool}` |
| POST | `/filesystem/move` | `{"source": str, "destination": str, "overwrite": bool}` | `{"moved": bool}` |
| POST | `/filesystem/delete` | `{"path": str, "recursive": bool}` | `{"deleted": bool}` |
| GET | `/filesystem/list?path=` | — | `{"entries": [{"name": str, "is_directory": bool, "size_bytes": int, "modified_utc": str}]}` |

## 5. Process Manager — `/process/*`

| Method | Path | Request body | `data` on success |
|---|---|---|---|
| POST | `/process/start` | `{"executable": str, "arguments": [str], "working_directory": str\|null, "wait": bool, "timeout_s": float\|null}` | `{"pid": int, "exit_code": int\|null, "stdout": str\|null, "stderr": str\|null}` |
| POST | `/process/terminate` | `{"pid": int\|null, "name": str\|null}` | `{"terminated_count": int}` |
| POST | `/process/wait` | `{"pid": int, "timeout_s": float}` | `{"exited": bool, "exit_code": int\|null}` |
| GET | `/process/query?name=&pid=` | — | `{"processes": [{"pid": int, "name": str, "command_line": str, "session_id": int}]}` |

`arguments` is a real JSON array of strings — the guest passes it straight to
`System.Diagnostics.ProcessStartInfo.ArgumentList` (per-element, no shell join, no manual
quoting), which is the .NET-native equivalent of `subprocess.run([...], shell=False)` on the host
side. This is what structurally eliminates the entire class of cmd.exe quote-nesting bugs
(Bug #1 / Issue #1 in `agent.py`'s history) — there is no shell in this path at all to
mis-parse a reconstructed command line.

`command_line` and `session_id` in `/process/query` come from `Get-CimInstance Win32_Process`
(the same real API the diagnostics added to the compatibility backend for Issue #2 use), not
from parsing `tasklist` text.

## 6. Procmon Manager — `/procmon/*`

| Method | Path | Request body | `data` on success |
|---|---|---|---|
| POST | `/procmon/start` | `{"session_id": str, "backing_file": str}` | `{"pid": int}` |
| POST | `/procmon/stop` | `{"session_id": str}` | `{"stopped": bool}` |
| POST | `/procmon/export` | `{"pml_path": str, "csv_path": str}` | `{"csv_path": str}` |
| GET | `/procmon/verify-backing-file?path=` | — | `{"exists": bool, "size_bytes": int\|null}` |

Every Procmon64.exe invocation the guest agent makes includes `/AcceptEula` unconditionally
(the guest-side equivalent of `agent.py`'s `_procmon_args()` helper — same fix, same reasoning,
reimplemented natively since the compatibility backend is not shared code with the guest side).

## 7. Network (tshark) Manager — `/network/*`

| Method | Path | Request body | `data` on success |
|---|---|---|---|
| GET | `/network/interfaces` | — | `{"interfaces": [{"index": str, "description": str}]}` |
| POST | `/network/start` | `{"session_id": str, "interface": str, "pcap_path": str}` | `{"pid": int}` |
| POST | `/network/stop` | `{"session_id": str}` | `{"stopped": bool}` |
| POST | `/network/convert` | `{"pcap_path": str, "ek_json_path": str}` | `{"ek_json_path": str}` |

`/network/convert` launches `tshark.exe` directly with `ArgumentList = @("-r", $pcapPath, "-T",
"ek")` and redirects the **.NET process's own StandardOutput stream** to `$ekJsonPath` — this is
the guest-side elimination of Issue #1 (the `cmd.exe /c ... > ...` redirection bug): there is no
`cmd.exe`, no `>`, and no argument that ever needs manual quoting, because .NET's
`ProcessStartInfo` takes the space-containing tshark path as `FileName` directly (like
`CreateProcessW`'s `lpApplicationName`, not part of a command-line string) and captures stdout
via a real stream redirect, not shell syntax.

## 8. Sysmon Manager — `/sysmon/*`

| Method | Path | Request body | `data` on success |
|---|---|---|---|
| POST | `/sysmon/export` | `{"channel": str, "output_path": str}` | `{"output_path": str, "mechanism": "wevtutil" \| "raw_copy"}` |
| GET | `/sysmon/diagnostics?channel=` | — | `{"channel_available": bool, "event_count": int\|null}` |

`/sysmon/export` tries `wevtutil.exe epl` first; on `ACCESS_DENIED` it automatically falls back
to a raw copy of the channel's backing `.evtx` file (the same two-mechanism strategy
`agent.py`'s `_export_sysmon_raw_copy_fallback()` uses for the compatibility backend) and reports
which one actually produced the file via `mechanism`.

## 9. Diagnostics Manager — `/diagnostics/*`

| Method | Path | Request body | `data` on success |
|---|---|---|---|
| GET | `/diagnostics/token` | — | `{"groups": [{"name": str, "attributes": [str]}], "privileges": [{"name": str, "state": str}], "integrity_level": str, "is_elevated": bool}` |
| GET | `/diagnostics/services?name=` | — | `{"services": [{"name": str, "status": str, "start_type": str}]}` |
| GET | `/diagnostics/drivers?name=` | — | `{"drivers": [{"name": str, "state": str}]}` |

`/diagnostics/token` is the single most direct upgrade this architecture provides over the
compatibility backend: instead of running `whoami /groups` + `whoami /priv` and treating their
text output as evidence (as `agent.py`'s `_whoami_diagnostics()` does today), the guest agent
calls `OpenProcessToken` / `GetTokenInformation` (`TokenGroups`, `TokenPrivileges`,
`TokenIntegrityLevel`) directly via .NET's `System.Security.Principal.WindowsIdentity` and P/Invoke,
returning structured, unambiguous data — no more inferring "Group used for deny only" from a
text string.

## 10. Sample Manager — `/sample/*`

| Method | Path | Request body | `data` on success |
|---|---|---|---|
| POST | `/sample/upload` | `{"filename": str, "sha256": str, "content_base64": str}` | `{"staged_path": str, "sha256_verified": bool}` |
| POST | `/sample/stage` | `{"staged_path": str, "target_path": str}` | `{"target_path": str}` |

Samples are transferred as base64-encoded JSON, not multipart, to keep every endpoint in this API
symmetric (single JSON body in, single JSON envelope out) — acceptable for this project's sample
size envelope (ARCHITECTURE.md's own scope: single-sample detonation, not bulk corpus ingestion);
flagged in the migration guide as a scaling limitation if that scope ever changes. `sha256` is
verified guest-side against the decoded bytes before the file is written, so a corrupted transfer
is caught immediately rather than surfacing later as a detonation failure.

## 11. Artifact Manager — `/artifact/*`

| Method | Path | Request body | `data` on success |
|---|---|---|---|
| GET | `/artifact/list?session_id=` | — | `{"artifacts": [{"name": str, "path": str, "size_bytes": int, "kind": str}]}` |
| POST | `/artifact/package` | `{"session_id": str, "paths": [str], "output_zip": str}` | `{"zip_path": str, "entry_count": int}` |
| GET | `/artifact/metadata?path=` | — | `{"size_bytes": int, "sha256": str, "modified_utc": str}` |

`/artifact/package` uses .NET's `System.IO.Compression.ZipFile`, not an external `zip.exe` /
`Compress-Archive` subprocess — no shell, no shelling out for something the guest's own runtime
already does natively.

## 12. Mapping to `GuestChannel`

`HTTPGuestChannel` (host-side, `adam/sandbox/guest/http_channel.py`) implements
`GuestChannel`'s three coarse session-lifecycle methods by composing calls to the fine-grained
endpoints above — the same internal shape `GuestAgent`'s own private `_export_sysmon()` /
`_export_procmon()` / `_export_network()` methods already have, just via HTTP+JSON instead of
GuestControl+shell:

- `verify_tools()` → `GET /diagnostics/token`, `GET /filesystem/exists` (per configured tool
  path), `GET /sysmon/diagnostics`.
- `start_captures()` → `POST /filesystem/mkdir` (capture dir), `POST /procmon/start`,
  `GET /network/interfaces` + `POST /network/start`.
- `stop_export_and_fetch()` → `POST /procmon/stop` + `POST /procmon/export`,
  `POST /network/stop` + `POST /network/convert`, `POST /sysmon/export`, then
  `GET /artifact/metadata` + a raw `GET` byte-fetch of each produced file (see
  `http_channel.py`'s own docstring for the file-transfer endpoint, `GET /filesystem/read`, added
  for this purpose — not listed above as an FS/artifact endpoint originally, split out during
  implementation because "package as zip" and "return one file's raw bytes" are genuinely
  different operations).

### 12.1 `GET /filesystem/read?path=`

Returns the raw file bytes directly as the HTTP response body (`Content-Type:
application/octet-stream`), **not** wrapped in the JSON envelope — the one deliberate exception
to section 2, since base64-wrapping a multi-megabyte EVTX/CSV/pcap export inside JSON on every
telemetry fetch would be a real, avoidable overhead. Errors on this one endpoint are reported via
HTTP status codes and an `X-Error-Code` response header instead of a JSON body.
