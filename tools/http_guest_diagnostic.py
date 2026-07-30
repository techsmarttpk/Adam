#!/usr/bin/env python3
"""
tools/http_guest_diagnostic.py

Standalone diagnostic utility for the ADAM Phase 5 HTTP guest agent
(adam/sandbox/guest/agent/adam_agent.ps1), talked to exactly as a remote
HTTP client would -- the wire contract this script drives is
docs/phase5-http-agent-api.md, nothing else.

WHAT THIS IS NOT
-----------------
This script is NOT part of the orchestrator, is NOT used by production,
and is deliberately isolated from the rest of this codebase: it imports
nothing from `adam.*` (no GuestChannel, no HTTPGuestChannel, no Settings,
no error hierarchy). It does not touch VirtualBox, does not start/stop
the VM, and does not use GuestControl -- it assumes a VM is already
booted and the guest agent is already listening (default assumption:
http://192.168.56.103:8765), and treats it purely as a black-box HTTP
appliance. If the assumption is wrong, every stage below will fail
loudly and individually -- that's the point: this tool exists to isolate
"is the HTTP guest agent itself healthy" from "is the orchestrator wired
up correctly," which is exactly the question that mattered when the
production HTTP backend was returning 500s on every process-launching
endpoint (the ProcessStartInfo.ArgumentList bug fixed in Common.psm1).

WHAT IT DOES
------------
Runs each of the following checks independently, in order, printing
extremely verbose per-request diagnostics (method, URL, JSON payload,
response code, elapsed time, response body -- for every single HTTP
call) and never aborting early: a failure in one stage is recorded and
the script moves on to the next stage regardless (see `guarded()` and
each `stage_*` function below).

  1. GET  /health                                  -- reachability + liveness
  2. Tool verification (best-effort, printed report, not a summary row):
       - Procmon path            via GET /filesystem/exists
       - tshark path              via GET /filesystem/exists
       - Sysmon channel            via GET /sysmon/diagnostics
       - dump capability           via a harmless route-existence probe
         (see `probe_dump_supported` -- no endpoint for this is
         documented in docs/phase5-http-agent-api.md; detected, not
         assumed)
  3. POST /filesystem/mkdir  <capture-dir>          -- + GET /filesystem/exists to confirm
  4. Procmon: POST /procmon/start -> sleep -> POST /procmon/stop ->
     GET /filesystem/exists (PML) -> GET /filesystem/read (download) ->
     best-effort POST /procmon/export + download of the CSV ("if
     possible", per the requirements this tool was built against -- not
     a summary-table row, since none of docs/phase5-http-agent-api.md's
     endpoints guarantee it and the checklist below doesn't name one).
  5. Sysmon: POST /sysmon/export -> GET /filesystem/exists ->
     GET /filesystem/read (download), size verified.
  6. Dump: GET /process/query (enumerate a real process) -> route-
     existence probe -> if supported, request + download a dump; if not
     supported, this is DETECTED and reported as SKIPPED, never treated
     as a crash.
  7. Every produced file is verified twice: remotely via
     GET /filesystem/exists (spec section 4), then locally via a plain
     Path.exists()/stat() check after download -- both PASS/FAIL are
     printed, per the checklist this tool was built against.
  8. Every HTTP call goes through the single `http_request()` helper,
     which prints method/URL/params/JSON body/status/elapsed time/
     response body for every call and NEVER swallows a transport
     exception -- it prints the full traceback, then re-raises, letting
     the calling stage's own `guarded()` wrapper decide how to classify
     the failure (never a silent pass, never an uncaught crash that
     kills the whole run).
  9. Stage independence: Procmon failing does not prevent Sysmon or the
     dump test from running, and one row failing inside a stage (e.g.
     Procmon Start) does not prevent that same stage's other,
     independently-callable rows (e.g. Procmon Stop) from still being
     attempted -- see `guarded()`.
 10. A final summary table (`print_summary`) with exactly these rows,
     each PASS/FAIL/ERROR/SKIPPED with a short reason:
       Health, Procmon Start, Procmon Stop, PML Created, PML Download,
       Sysmon Export, EVTX Download, Dump Created, Dump Download.

USAGE
-----
    python3 tools/http_guest_diagnostic.py
    python3 tools/http_guest_diagnostic.py --base-url http://192.168.56.103:8765 \\
        --dump-target explorer.exe --sleep-seconds 15

Run `python3 tools/http_guest_diagnostic.py --help` for every override
(tool paths, capture directory, artifacts directory, timeouts, etc.) --
none of them are read from config/default.toml or any other project
file; this tool is fully self-contained and every default below is a
literal, hardcoded value chosen to match that file's own documented
defaults, not an import of it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from collections import Counter
from pathlib import Path
from typing import Any

import httpx

# --------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------- #

# The exact checklist rows this tool's final summary table reports,
# in this exact order -- initialized to SKIPPED/"not attempted" up
# front so the table is always complete even if a stage never runs
# at all (e.g. the script is killed mid-run).
ROW_ORDER: list[str] = [
    "Health",
    "Procmon Start",
    "Procmon Stop",
    "PML Created",
    "PML Download",
    "Sysmon Export",
    "EVTX Download",
    "Dump Created",
    "Dump Download",
]

# No process-dump endpoint is documented anywhere in
# docs/phase5-http-agent-api.md (sections 1-11 cover health/version,
# filesystem, process, procmon, network, sysmon, diagnostics, sample,
# artifact -- no /dump/* or /process/dump). This is this tool's own
# best guess at a plausible name, consistent with the API's existing
# /process/* prefix convention (section 5) -- `probe_dump_supported()`
# below detects, rather than assumes, whether it's real.
DUMP_ENDPOINT = "/process/dump"

VALID_STATUSES = {"PASS", "FAIL", "ERROR", "SKIPPED"}


# --------------------------------------------------------------------- #
# HTTP transport -- the ONE function in this script that talks to the
# network, so the "extremely verbose logging" contract only has to be
# implemented once and every stage below inherits it automatically.
# --------------------------------------------------------------------- #


def http_request(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    expect_binary: bool = False,
) -> httpx.Response:
    """
    Issues one HTTP request against the guest agent, printing method,
    full URL, query params, JSON payload, response status, elapsed
    time, and response body -- every single field the "extremely
    verbose logging" requirement this tool was built against calls
    out, for every single call, unconditionally.

    Never swallows a transport-level exception (connection refused,
    timeout, DNS failure, etc.): it's printed here in full (a real
    traceback, not a summary) and then RE-RAISED, so the caller (one of
    the `guarded()`-wrapped stage closures below) decides how to
    classify it -- this function's only job is transport + logging, not
    deciding what a failure means for the checklist.

    `expect_binary=True` is for GET /filesystem/read (spec section
    12.1), the one documented endpoint that returns raw bytes outside
    the JSON envelope -- printing an attempted JSON parse of a
    multi-megabyte EVTX/PML file would be both useless and slow, so the
    body line instead shows byte count + Content-Type + (on failure)
    the X-Error-Code header that endpoint uses instead of a JSON error
    body.
    """
    full_url = client.base_url.join(path)
    print()
    print("=" * 78)
    print(f"HTTP {method} {path}")
    print("=" * 78)
    print(f"URL     : {full_url}")
    print(f"PARAMS  : {params if params else '(none)'}")
    if json_body is not None:
        print(f"JSON    :\n{json.dumps(json_body, indent=2)}")
    else:
        print("JSON    : (none)")

    start = time.monotonic()
    try:
        response = client.request(method, path, json=json_body, params=params)
    except Exception:
        elapsed = time.monotonic() - start
        print(f"ELAPSED : {elapsed:.3f}s")
        print("RESULT  : TRANSPORT EXCEPTION -- full traceback follows (never swallowed):")
        traceback.print_exc()
        print("=" * 78)
        raise
    elapsed = time.monotonic() - start

    print(f"STATUS  : {response.status_code}")
    print(f"ELAPSED : {elapsed:.3f}s")
    if expect_binary:
        content_type = response.headers.get("Content-Type")
        print(f"BODY    : <binary payload, {len(response.content)} byte(s)>  Content-Type={content_type!r}")
        if response.status_code != 200:
            print(f"X-Error-Code header: {response.headers.get('X-Error-Code')!r}")
    else:
        try:
            pretty = json.dumps(response.json(), indent=2)
        except Exception:
            # Not JSON at all -- show the raw text rather than hiding it;
            # a caller further up (parse_envelope) will raise on this if
            # it actually needed a JSON envelope.
            pretty = response.text
        print(f"BODY    :\n{pretty}")
    print("=" * 78)
    return response


def parse_envelope(response: httpx.Response) -> dict[str, Any]:
    """
    Parses a JSON response envelope (docs/phase5-http-agent-api.md
    section 2) -- NOT used for GET /filesystem/read, which returns raw
    bytes outside the envelope (section 12.1) and is handled directly
    via response.content in `download_file()` below.

    Deliberately raises, rather than returning some empty/default dict,
    if the body isn't valid JSON at all -- that's a genuine protocol
    violation worth surfacing loudly (per "no silent failures"), not a
    normal success/failure outcome this function should paper over.
    """
    try:
        parsed: dict[str, Any] = response.json()
        return parsed
    except Exception as exc:
        raise RuntimeError(
            f"response body is not valid JSON (status={response.status_code}): {exc}. "
            f"Raw body: {response.text!r}"
        ) from exc


def is_route_missing(envelope: dict[str, Any]) -> bool:
    """
    True only for the guest router's own, exact "no matching route"
    signature (adam_agent.ps1's Invoke-Route `default` case:
    `New-ErrorEnvelope ... -ErrorMessage "no route for $Method $Path"`)
    -- distinct from a real endpoint legitimately reporting its OWN
    NOT_FOUND (e.g. a missing file), which would never contain this
    exact phrase. This is what makes `probe_dump_supported()` below a
    genuine detection rather than a guess.
    """
    message = envelope.get("error_message") or ""
    return envelope.get("success") is False and "no route for" in message


# --------------------------------------------------------------------- #
# File verification (requirement: every produced file is checked BOTH
# remotely, via GET /filesystem/exists, and locally after download).
# --------------------------------------------------------------------- #


def remote_file_exists(client: httpx.Client, guest_path: str) -> tuple[bool, dict[str, Any]]:
    response = http_request(client, "GET", "/filesystem/exists", params={"path": guest_path})
    envelope = parse_envelope(response)
    if not envelope.get("success"):
        return False, envelope
    return bool(envelope["data"]["exists"]), envelope


def download_file(client: httpx.Client, guest_path: str, local_path: Path) -> tuple[bool, int]:
    """
    GET /filesystem/read -- raw bytes outside the envelope (spec
    12.1). Writes the response body directly to `local_path` and
    returns (ok, byte_count). Raises (never silently returns a fake
    success) on a non-200 status -- the X-Error-Code response header is
    already printed by http_request() above.
    """
    response = http_request(client, "GET", "/filesystem/read", params={"path": guest_path}, expect_binary=True)
    if response.status_code != 200:
        raise RuntimeError(
            f"download of {guest_path!r} failed: HTTP {response.status_code}, "
            f"X-Error-Code={response.headers.get('X-Error-Code')!r}"
        )
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(response.content)
    return True, len(response.content)


def verify_downloaded_file(local_path: Path, expected_size: int) -> tuple[bool, str]:
    """Local-side half of requirement 7's double verification -- a plain filesystem check, no HTTP involved."""
    if not local_path.exists():
        return False, f"local file {local_path} does not exist after download"
    actual_size = local_path.stat().st_size
    if actual_size != expected_size:
        return False, f"local file {local_path} is {actual_size} bytes, expected {expected_size}"
    return True, f"local file {local_path} exists, {actual_size} bytes"


# --------------------------------------------------------------------- #
# Row bookkeeping -- "never abort the script because one test failed":
# every checklist row is executed through `guarded()`, which catches
# ANYTHING the row's own closure doesn't handle itself, prints a full
# traceback, and records ERROR instead of letting the exception
# propagate and kill the rest of the script.
# --------------------------------------------------------------------- #


def record(results: dict[str, tuple[str, str]], row: str, status: str, reason: str) -> None:
    assert status in VALID_STATUSES, f"invalid status {status!r} for row {row!r}"
    results[row] = (status, reason)
    print(f"\n>>> [{row}] {status} -- {reason}\n")


def guarded(results: dict[str, tuple[str, str]], row: str, fn: Any) -> None:
    """
    Runs `fn()` -- a zero-argument callable that performs one checklist
    row's real work and returns (status, reason) on any CONTROLLED
    outcome (success, or a cleanly-detected failure it chose to report
    as FAIL/SKIPPED itself). Anything `fn()` doesn't handle (a raised
    exception -- network error, malformed response, assertion, etc.) is
    caught here, its full traceback is printed (never swallowed), and
    the row is recorded as ERROR -- this is what lets the rest of the
    script keep running instead of crashing out entirely.
    """
    try:
        status, reason = fn()
        record(results, row, status, reason)
    except Exception as exc:
        print(f"\n***** UNHANDLED EXCEPTION while running check {row!r} -- full traceback follows *****")
        traceback.print_exc()
        record(results, row, "ERROR", f"{type(exc).__name__}: {exc}")


# --------------------------------------------------------------------- #
# Stage 1 -- Health
# --------------------------------------------------------------------- #


def stage_health(client: httpx.Client, results: dict[str, tuple[str, str]]) -> None:
    print("\n########## STEP 1: Health Check ##########")

    def _run() -> tuple[str, str]:
        response = http_request(client, "GET", "/health")
        envelope = parse_envelope(response)
        healthy = bool(envelope.get("success")) and envelope.get("data", {}).get("status") == "ok"
        print("PASS" if healthy else "FAIL")
        if healthy:
            return "PASS", f"uptime_s={envelope['data'].get('uptime_s')}"
        return "FAIL", f"unexpected envelope: {envelope}"

    guarded(results, "Health", _run)


# --------------------------------------------------------------------- #
# Stage 2 -- Verify tools (printed report; not a summary-table row --
# see module docstring for why).
# --------------------------------------------------------------------- #


def probe_dump_supported(client: httpx.Client) -> tuple[bool, str]:
    """
    Detects whether this guest agent build exposes ANY process-dump
    endpoint, WITHOUT triggering a real dump: sends a request against
    DUMP_ENDPOINT with a deliberately invalid pid (-1) and a throwaway
    output path -- a real implementation would reject this as
    INVALID_ARGUMENT or a process-not-found NOT_FOUND, which is a
    normal, expected response from a route that EXISTS. The one signal
    that means "this route does not exist at all" is the guest router's
    own exact, unambiguous default-case message (see
    `is_route_missing()`); anything else -- including a genuine error --
    means the endpoint is real.
    """
    try:
        response = http_request(
            client,
            "POST",
            DUMP_ENDPOINT,
            json_body={"pid": -1, "output_path": "C:\\ADAM\\diagnostic\\__dump_probe__.dmp"},
        )
    except Exception as exc:
        # A transport failure here doesn't tell us anything about dump
        # support specifically (the whole agent might be down) -- report
        # it plainly rather than guessing either way.
        return False, f"could not probe {DUMP_ENDPOINT} -- transport error: {exc}"

    envelope = parse_envelope(response)
    if is_route_missing(envelope):
        return False, f"no route for POST {DUMP_ENDPOINT} -- this guest agent build does not expose process-dump functionality"
    return True, f"POST {DUMP_ENDPOINT} exists (probe response: {envelope})"


def verify_tools(client: httpx.Client, args: argparse.Namespace) -> dict[str, bool]:
    print("\n########## STEP 2: Verify Tools ##########")
    findings: dict[str, bool] = {}

    def _check_path(label: str, path: str) -> None:
        try:
            exists, envelope = remote_file_exists(client, path)
            findings[label] = exists
        except Exception:
            traceback.print_exc()
            findings[label] = False

    _check_path("procmon_executable", args.procmon_path)
    _check_path("tshark_executable", args.tshark_path)

    try:
        response = http_request(client, "GET", "/sysmon/diagnostics", params={"channel": args.sysmon_channel})
        envelope = parse_envelope(response)
        findings["sysmon_channel"] = bool(envelope.get("success")) and bool(envelope["data"]["channel_available"])
    except Exception:
        traceback.print_exc()
        findings["sysmon_channel"] = False

    try:
        supported, detail = probe_dump_supported(client)
        findings["dump_capability"] = supported
        print(f"dump_capability detail: {detail}")
    except Exception:
        traceback.print_exc()
        findings["dump_capability"] = False

    print("\n--- Tool availability ---")
    for label, available in findings.items():
        print(f"  {label:20s}: {'AVAILABLE' if available else 'NOT AVAILABLE'}")
    return findings


# --------------------------------------------------------------------- #
# Stage 3 -- Create capture directory (printed report; not a
# summary-table row).
# --------------------------------------------------------------------- #


def create_capture_dir(client: httpx.Client, args: argparse.Namespace) -> bool:
    print("\n########## STEP 3: Create Capture Directory ##########")
    try:
        response = http_request(client, "POST", "/filesystem/mkdir", json_body={"path": args.capture_dir})
        envelope = parse_envelope(response)
        if not envelope.get("success"):
            print(f"FAIL -- mkdir reported failure: {envelope}")
            return False
    except Exception:
        traceback.print_exc()
        print("ERROR -- mkdir raised (see traceback above)")
        return False

    try:
        exists, envelope = remote_file_exists(client, args.capture_dir)
    except Exception:
        traceback.print_exc()
        print("ERROR -- post-mkdir existence check raised (see traceback above)")
        return False

    if exists:
        print(f"PASS -- {args.capture_dir} confirmed present via GET /filesystem/exists")
        return True
    print(f"FAIL -- {args.capture_dir} does not exist after mkdir: {envelope}")
    return False


# --------------------------------------------------------------------- #
# Stage 4 -- Procmon test
# --------------------------------------------------------------------- #


def stage_procmon(client: httpx.Client, args: argparse.Namespace, results: dict[str, tuple[str, str]]) -> None:
    print("\n########## STEP 4: Procmon Test ##########")
    session_id = f"diagnostic_{int(time.time())}"
    pml_path = f"{args.capture_dir}\\diagnostic_procmon.pml"
    csv_path = f"{args.capture_dir}\\diagnostic_procmon.csv"

    def _start() -> tuple[str, str]:
        response = http_request(
            client, "POST", "/procmon/start", json_body={"session_id": session_id, "backing_file": pml_path}
        )
        envelope = parse_envelope(response)
        if envelope.get("success"):
            return "PASS", f"pid={envelope['data'].get('pid')}"
        return "FAIL", f"error_code={envelope.get('error_code')} error_message={envelope.get('error_message')}"

    guarded(results, "Procmon Start", _start)

    print(f"\nSleeping {args.sleep_seconds}s to let Procmon capture activity...")
    time.sleep(args.sleep_seconds)

    def _stop() -> tuple[str, str]:
        response = http_request(client, "POST", "/procmon/stop", json_body={"session_id": session_id})
        envelope = parse_envelope(response)
        if envelope.get("success"):
            return "PASS", f"stopped={envelope['data'].get('stopped')}"
        return "FAIL", f"error_code={envelope.get('error_code')} error_message={envelope.get('error_message')}"

    guarded(results, "Procmon Stop", _stop)

    def _pml_created() -> tuple[str, str]:
        # Bonus, Procmon-specific detail (not the row's own PASS/FAIL
        # signal -- that's GET /filesystem/exists, per the general file
        # verification requirement this tool was built against).
        try:
            vb_response = http_request(client, "GET", "/procmon/verify-backing-file", params={"path": pml_path})
            print(f"(bonus detail) /procmon/verify-backing-file -> {parse_envelope(vb_response)}")
        except Exception:
            traceback.print_exc()

        exists, envelope = remote_file_exists(client, pml_path)
        if exists:
            size = envelope["data"].get("size_bytes")
            return "PASS", f"GET /filesystem/exists confirms {pml_path} is present (size_bytes={size})"
        return "FAIL", f"GET /filesystem/exists reports missing: {envelope}"

    guarded(results, "PML Created", _pml_created)

    def _pml_download() -> tuple[str, str]:
        local_path = args.artifacts_dir / "diagnostic_procmon.pml"
        ok, size = download_file(client, pml_path, local_path)
        local_ok, local_detail = verify_downloaded_file(local_path, size)
        print(f"remote download ok={ok}  {local_detail}")
        if ok and local_ok:
            return "PASS", f"downloaded {size} byte(s) to {local_path}"
        return "FAIL", f"remote_ok={ok} {local_detail}"

    guarded(results, "PML Download", _pml_download)

    # Bonus, best-effort, "if possible" per this tool's own requirements
    # -- NOT a summary-table row (none of the 9 required rows names it).
    print("\n--- Bonus (best-effort): Procmon CSV export + download ---")
    try:
        response = http_request(client, "POST", "/procmon/export", json_body={"pml_path": pml_path, "csv_path": csv_path})
        envelope = parse_envelope(response)
        if envelope.get("success"):
            print(f"CSV export PASS -- csv_path={envelope['data'].get('csv_path')}")
            try:
                local_csv = args.artifacts_dir / "diagnostic_procmon.csv"
                ok, size = download_file(client, csv_path, local_csv)
                local_ok, local_detail = verify_downloaded_file(local_csv, size)
                print(f"CSV download {'PASS' if ok and local_ok else 'FAIL'} -- {local_detail}")
            except Exception:
                traceback.print_exc()
                print("CSV download ERROR (see traceback above)")
        else:
            print(f"CSV export FAIL -- {envelope}")
    except Exception:
        traceback.print_exc()
        print("CSV export ERROR (see traceback above)")


# --------------------------------------------------------------------- #
# Stage 5 -- Sysmon test
# --------------------------------------------------------------------- #


def stage_sysmon(client: httpx.Client, args: argparse.Namespace, results: dict[str, tuple[str, str]]) -> None:
    print("\n########## STEP 5: Sysmon Test ##########")
    evtx_path = f"{args.capture_dir}\\diagnostic_sysmon.evtx"

    def _export() -> tuple[str, str]:
        response = http_request(
            client, "POST", "/sysmon/export", json_body={"channel": args.sysmon_channel, "output_path": evtx_path}
        )
        envelope = parse_envelope(response)
        if envelope.get("success"):
            return "PASS", f"mechanism={envelope['data'].get('mechanism')}"
        return "FAIL", f"error_code={envelope.get('error_code')} error_message={envelope.get('error_message')}"

    guarded(results, "Sysmon Export", _export)

    def _download() -> tuple[str, str]:
        exists, envelope = remote_file_exists(client, evtx_path)
        if not exists:
            return "FAIL", f"GET /filesystem/exists reports missing before download: {envelope}"
        local_path = args.artifacts_dir / "diagnostic_sysmon.evtx"
        ok, size = download_file(client, evtx_path, local_path)
        local_ok, local_detail = verify_downloaded_file(local_path, size)
        print(f"remote download ok={ok}  {local_detail}  file_size_bytes={size}")
        if ok and local_ok and size > 0:
            return "PASS", f"downloaded {size} byte(s) to {local_path}"
        return "FAIL", f"remote_ok={ok} size={size} {local_detail}"

    guarded(results, "EVTX Download", _download)


# --------------------------------------------------------------------- #
# Stage 6 -- Dump test (auto-detects whether the feature exists at all)
# --------------------------------------------------------------------- #


def stage_dump(client: httpx.Client, args: argparse.Namespace, results: dict[str, tuple[str, str]]) -> None:
    print("\n########## STEP 6: Dump Test ##########")
    dump_path = f"{args.capture_dir}\\diagnostic.dmp"

    try:
        response = http_request(client, "GET", "/process/query", params={"name": args.dump_target})
        envelope = parse_envelope(response)
        if not envelope.get("success"):
            raise RuntimeError(f"/process/query reported failure: {envelope}")
        processes = envelope["data"]["processes"]
        print(f"Found {len(processes)} running process(es) named {args.dump_target!r}: {processes}")
    except Exception:
        traceback.print_exc()
        record(results, "Dump Created", "ERROR", "process enumeration (/process/query) failed -- see traceback above")
        record(results, "Dump Download", "ERROR", "process enumeration (/process/query) failed -- see traceback above")
        return

    if not processes:
        reason = f"no running process named {args.dump_target!r} found via GET /process/query"
        record(results, "Dump Created", "SKIPPED", reason)
        record(results, "Dump Download", "SKIPPED", reason)
        return

    try:
        supported, detail = probe_dump_supported(client)
    except Exception:
        traceback.print_exc()
        record(results, "Dump Created", "ERROR", "dump-support probe raised -- see traceback above")
        record(results, "Dump Download", "ERROR", "dump-support probe raised -- see traceback above")
        return

    print(f"\nDump endpoint probe result: {'SUPPORTED' if supported else 'NOT SUPPORTED'} -- {detail}")
    if not supported:
        # Exactly requirement: "If dump functionality does not exist,
        # detect that automatically and report it instead of crashing."
        record(results, "Dump Created", "SKIPPED", detail)
        record(results, "Dump Download", "SKIPPED", detail)
        return

    target_pid = processes[0]["pid"]

    def _create() -> tuple[str, str]:
        response = http_request(client, "POST", DUMP_ENDPOINT, json_body={"pid": target_pid, "output_path": dump_path})
        envelope = parse_envelope(response)
        if envelope.get("success"):
            return "PASS", f"dump requested for pid={target_pid} ({args.dump_target}) -> {dump_path}"
        return "FAIL", f"error_code={envelope.get('error_code')} error_message={envelope.get('error_message')}"

    guarded(results, "Dump Created", _create)

    def _download() -> tuple[str, str]:
        exists, envelope = remote_file_exists(client, dump_path)
        if not exists:
            return "FAIL", f"GET /filesystem/exists reports missing before download: {envelope}"
        local_path = args.artifacts_dir / "diagnostic.dmp"
        ok, size = download_file(client, dump_path, local_path)
        local_ok, local_detail = verify_downloaded_file(local_path, size)
        status_line = f"status={ok and local_ok} size={size} path={local_path}"
        print(status_line)
        if ok and local_ok and size > 0:
            return "PASS", status_line
        return "FAIL", status_line

    guarded(results, "Dump Download", _download)


# --------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------- #


def print_summary(results: dict[str, tuple[str, str]]) -> None:
    print("\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    name_width = max(len(name) for name in ROW_ORDER) + 2
    status_width = 8
    print(f"{'Check'.ljust(name_width)} {'Status'.ljust(status_width)} Reason")
    print("-" * 100)
    for name in ROW_ORDER:
        status, reason = results.get(name, ("SKIPPED", "not attempted"))
        print(f"{name.ljust(name_width)} {status.ljust(status_width)} {reason}")
    print("=" * 100)

    counts = Counter(status for status, _ in results.values())
    print(
        f"\nTotals: PASS={counts.get('PASS', 0)}  FAIL={counts.get('FAIL', 0)}  "
        f"ERROR={counts.get('ERROR', 0)}  SKIPPED={counts.get('SKIPPED', 0)}"
    )


# --------------------------------------------------------------------- #
# CLI / entry point
# --------------------------------------------------------------------- #


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Standalone HTTP-only diagnostic for the ADAM guest agent. Talks directly to an "
            "already-booted VM's already-running HTTP agent -- does not touch VirtualBox, "
            "GuestControl, or any adam.* code."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--base-url", default="http://192.168.56.103:8765", help="Guest agent base URL")
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-request HTTP timeout (seconds)")
    parser.add_argument("--capture-dir", default="C:\\ADAM\\diagnostic", help="Guest-side capture directory")
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path("artifacts/diagnostic"),
        help="Host-side directory downloaded files are saved into",
    )
    parser.add_argument("--sleep-seconds", type=float, default=10.0, help="Seconds to let Procmon capture before stopping it")
    parser.add_argument(
        "--procmon-path",
        default="C:\\Users\\Admin\\Downloads\\ProcessMonitor\\Procmon64.exe",
        help="Guest-side Procmon64.exe path to verify in step 2 (matches config/default.toml's documented default)",
    )
    parser.add_argument(
        "--tshark-path",
        default="C:\\Program Files\\Wireshark\\tshark.exe",
        help="Guest-side tshark.exe path to verify in step 2 (matches config/default.toml's documented default)",
    )
    parser.add_argument(
        "--sysmon-channel",
        default="Microsoft-Windows-Sysmon/Operational",
        help="Sysmon Windows Event Log channel name",
    )
    parser.add_argument(
        "--dump-target",
        choices=["notepad.exe", "explorer.exe"],
        default="notepad.exe",
        help="Process name to target for the dump test (step 6)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)

    print("#" * 100)
    print("ADAM HTTP Guest Agent Diagnostic Utility")
    print(f"Target base URL : {args.base_url}")
    print(f"Capture dir     : {args.capture_dir}")
    print(f"Artifacts dir   : {args.artifacts_dir.resolve()}")
    print("#" * 100)

    results: dict[str, tuple[str, str]] = {name: ("SKIPPED", "not attempted") for name in ROW_ORDER}

    try:
        with httpx.Client(base_url=args.base_url, timeout=args.timeout) as client:
            # Each stage call below is individually guarded at the top
            # level too, on top of guarded()'s own per-row protection --
            # belt and suspenders, so literally nothing can produce an
            # uncaught crash that skips the final summary table. Small
            # void-returning wrappers (rather than the stage functions'
            # own return values, which differ in type -- verify_tools
            # returns a dict, create_capture_dir returns a bool) keep
            # this list's element type uniform for strict type-checking.
            def _run_health() -> None:
                stage_health(client, results)

            def _run_verify_tools() -> None:
                verify_tools(client, args)

            def _run_create_capture_dir() -> None:
                create_capture_dir(client, args)

            def _run_procmon() -> None:
                stage_procmon(client, args, results)

            def _run_sysmon() -> None:
                stage_sysmon(client, args, results)

            def _run_dump() -> None:
                stage_dump(client, args, results)

            stages: list[tuple[str, Any]] = [
                ("health", _run_health),
                ("verify_tools", _run_verify_tools),
                ("create_capture_dir", _run_create_capture_dir),
                ("procmon", _run_procmon),
                ("sysmon", _run_sysmon),
                ("dump", _run_dump),
            ]
            for stage_name, stage_fn in stages:
                try:
                    stage_fn()
                except Exception:
                    print(f"\n***** UNHANDLED EXCEPTION in stage {stage_name!r} -- full traceback follows *****")
                    traceback.print_exc()
                    print(f"Continuing to the next stage regardless (stage {stage_name!r} did not update its own rows).")
    finally:
        # Always print the summary, even if something above escaped
        # every other guard -- the whole point of this table.
        print_summary(results)

    failures = sum(1 for status, _ in results.values() if status in ("FAIL", "ERROR"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
