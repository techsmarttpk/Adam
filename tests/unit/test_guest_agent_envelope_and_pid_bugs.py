"""
tests/unit/test_guest_agent_envelope_and_pid_bugs.py

Regression tests for two more real, shipped guest-agent bugs, found via
real-VM validation after the ProcessStartInfo.ArgumentList fix was
deployed (see test_native_process_argument_quoting.py):

1. Write-AgentLog pipeline pollution (Common.psm1). Write-AgentLog used
   `Write-Output $line` instead of `Write-Host $line` -- the exact same
   bug class as install.ps1's Write-Step/Write-Ok/Write-Bad/Write-Info
   helpers (test_installer_logic.py's own regression test), just never
   applied to this function. Write-Output puts its argument on the
   success/pipeline stream, so calling Write-AgentLog from INSIDE a
   function whose own return value matters -- e.g. Invoke-ProcmonStart
   logging "Procmon started" immediately before its own `return
   New-SuccessEnvelope -Data @{ pid = ... }` -- leaked that log line
   into the CALLER's aggregate return value alongside the real envelope
   hashtable, turning a single Hashtable into a 2-element `Object[]`.
   adam_agent.ps1's Write-JsonResponse/Write-EnvelopeResponse both
   declare a `[hashtable]$Envelope` parameter, so PowerShell's own
   parameter binder rejected that array with "Cannot process argument
   transformation on parameter 'Envelope'. Cannot convert the
   "System.Object[]" value of type "System.Object[]" to type
   "System.Collections.Hashtable"." -- AFTER the real operation
   (Procmon/Sysmon/etc.) had already completed successfully, since the
   log call happens right before the return, not before the actual
   work. Affected every route whose handler function calls
   Write-AgentLog before its own success/error return: /procmon/start,
   /procmon/stop, /sysmon/export (both its wevtutil and raw-copy-
   fallback paths), and /sample/upload.

2. `$pid` read-only variable collisions (adam_agent.ps1 +
   Common.psm1). `$PID` is PowerShell's own automatic variable (the
   CURRENT process's id) and is read-only -- an unqualified `$pid =
   ...` assignment resolves to that same variable rather than creating
   a new local one and throws "Cannot overwrite variable PID because it
   is read-only or constant." adam_agent.ps1's GET /process/query and
   POST /process/terminate route handlers both did this; every GET
   /process/query request failed with exactly that message. Fixed by
   renaming the local variable to $requestedPid in both handlers, and
   defensively in Common.psm1's Invoke-NativeProcess (same anti-pattern,
   not observed to fail there but the identical footgun) to $processId
   -- the returned Hashtable's `Pid` KEY (capital P, a string, unrelated
   to the variable name) is unchanged, so this is purely an internal
   rename with no effect on any endpoint's behavior.

Same disclosed limitation as every other guest-agent test in this suite
(see test_guest_service_static_structure.py's own module docstring):
this sandbox has no PowerShell runtime, so these are static, regex-based
checks against the real .ps1/.psm1 source on disk, not execution.
"""

from __future__ import annotations

import re
from pathlib import Path

GUEST_AGENT_DIR = Path(__file__).resolve().parents[2] / "adam" / "sandbox" / "guest" / "agent"
COMMON_PSM1 = GUEST_AGENT_DIR / "modules" / "Common.psm1"
PROCMON_MANAGER_PSM1 = GUEST_AGENT_DIR / "modules" / "ProcmonManager.psm1"
SYSMON_MANAGER_PSM1 = GUEST_AGENT_DIR / "modules" / "SysmonManager.psm1"
ADAM_AGENT_PS1 = GUEST_AGENT_DIR / "adam_agent.ps1"


def _function_body(text: str, function_name: str) -> str:
    """Same brace-counting extraction as test_native_process_argument_quoting.py's own helper -- see that module's docstring for why this, not a real parse."""
    start = text.index(f"function {function_name}")
    brace_start = text.index("{", start)
    depth = 0
    i = brace_start
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace_start : i + 1]
        i += 1
    raise AssertionError(f"never found a matching closing brace for function {function_name}")


def _strip_line_comments(text: str) -> str:
    """
    Strips everything from the first `#` to end-of-line, for every line
    -- a deliberately simple, disclosed approximation (doesn't account
    for a `#` inside a string literal) matching this test suite's
    existing convention (see test_guest_service_static_structure.py's
    own `_balanced()`). Needed here specifically because this fix's own
    explanatory comments legitimately contain illustrative snippets like
    "`$pid = ...`" in prose -- without stripping comments first, a naive
    scan for the live-code pattern would false-positive on the very
    comment explaining why that pattern is wrong (the same mistake this
    session's install.ps1 self-test regex made against its own
    docstring before being corrected).
    """
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


# --------------------------------------------------------------------- #
# Bug 1: Write-AgentLog pipeline pollution
# --------------------------------------------------------------------- #


class TestWriteAgentLogNoLongerPollutesThePipeline:
    def test_common_psm1_exists(self) -> None:
        assert COMMON_PSM1.exists()

    def test_write_agent_log_uses_write_host_not_write_output(self) -> None:
        text = COMMON_PSM1.read_text(encoding="utf-8")
        body = _function_body(text, "Write-AgentLog")
        assert "Write-Host $line" in body, (
            "Write-AgentLog must emit its log line via Write-Host, not Write-Output -- Write-Output "
            "puts its argument on the success/pipeline stream, which leaks into the return value of "
            "any function that calls Write-AgentLog before its own `return New-SuccessEnvelope/"
            "New-ErrorEnvelope` statement (a real, shipped bug: /procmon/start, /procmon/stop, and "
            "/sysmon/export all returned a 2-element Object[] instead of a single Hashtable for their "
            "response envelope, failing adam_agent.ps1's [hashtable]$Envelope-typed parameter binding "
            "with 'Cannot convert the System.Object[] value ... to type System.Collections.Hashtable')."
        )
        # NOT a blanket "Write-Output" not in body: this fix's own docstring
        # legitimately mentions "Write-Output" in prose while explaining the
        # bug it replaces -- the live-code check that actually matters is
        # the specific statement that used to leak the log line:
        assert "Write-Output $line" not in body, "Write-AgentLog must not also (still) call Write-Output $line"

    def test_previously_broken_endpoints_still_call_write_agent_log_before_returning(self) -> None:
        """
        Confirms the fix above actually addresses a real trigger case,
        not just that Write-AgentLog looks fine in isolation: these
        specific manager functions (the ones the real-VM bug report
        named -- /procmon/start, /procmon/stop, /sysmon/export) must
        still call Write-AgentLog on their success path, immediately
        before their own `return New-SuccessEnvelope`. If a future edit
        removed those Write-AgentLog calls entirely, this fix's own
        regression coverage above would stop meaning anything for this
        specific scenario.
        """
        procmon_text = PROCMON_MANAGER_PSM1.read_text(encoding="utf-8")
        start_body = _function_body(procmon_text, "Invoke-ProcmonStart")
        assert re.search(r"Write-AgentLog[^\n]*\n\s*return New-SuccessEnvelope", start_body), (
            "Invoke-ProcmonStart should still call Write-AgentLog immediately before its success "
            "return -- this is the exact real-VM scenario the Write-Host fix above addresses."
        )
        stop_body = _function_body(procmon_text, "Invoke-ProcmonStop")
        assert re.search(r"Write-AgentLog[^\n]*\n\s*return New-SuccessEnvelope", stop_body)

        sysmon_text = SYSMON_MANAGER_PSM1.read_text(encoding="utf-8")
        export_body = _function_body(sysmon_text, "Invoke-SysmonExport")
        # Both success paths (wevtutil, raw-copy fallback) log immediately before returning.
        assert export_body.count("Write-AgentLog") >= 2
        assert re.search(r"Write-AgentLog[^\n]*\n\s*return New-SuccessEnvelope", export_body)


# --------------------------------------------------------------------- #
# Bug 2: $pid read-only automatic variable collision
# --------------------------------------------------------------------- #


class TestNoReadOnlyPidVariableCollision:
    def test_adam_agent_ps1_exists(self) -> None:
        assert ADAM_AGENT_PS1.exists()

    def test_no_bare_pid_assignment_in_adam_agent_ps1(self) -> None:
        """
        `$pid = <expr>` (any casing -- PowerShell variable names are
        case-insensitive) must not appear anywhere in adam_agent.ps1:
        $PID is PowerShell's own read-only automatic variable (the
        CURRENT process's id), and an unqualified assignment to it
        throws "Cannot overwrite variable PID because it is read-only
        or constant" -- a real, shipped bug that broke every GET
        /process/query request (and, identically, would have broken
        POST /process/terminate the first time it was called with a
        pid). Comments that merely MENTION the pattern in prose while
        explaining this fix are stripped first (see
        _strip_line_comments's own docstring) so they can't
        false-positive this check.
        """
        text = ADAM_AGENT_PS1.read_text(encoding="utf-8")
        code_only = _strip_line_comments(text)
        assert not re.search(r"\$pid\s*=[^=]", code_only, re.IGNORECASE), (
            "adam_agent.ps1 contains a live `$pid = ...` assignment -- $PID is PowerShell's own "
            "read-only automatic variable; use a differently-named local variable (e.g. "
            "$requestedPid) instead."
        )

    def test_process_query_and_terminate_use_requested_pid(self) -> None:
        text = ADAM_AGENT_PS1.read_text(encoding="utf-8")
        assert "$requestedPid" in text
        # Both fixed route handlers actually use the renamed variable
        # when calling their manager function, not just declare it.
        assert re.search(r"Invoke-ProcessQuery\s+-Name\s+\$name\s+-ProcessId\s+\$requestedPid", text)
        assert re.search(r"Invoke-ProcessTerminate\s+-ProcessId\s+\$requestedPid\s+-Name\s+\$name", text)

    def test_no_bare_pid_assignment_in_common_psm1_invoke_native_process(self) -> None:
        """Defensive: the identical anti-pattern in Invoke-NativeProcess (Common.psm1) was renamed to $processId even though it wasn't observed to fail -- same footgun, no reason to leave it in place."""
        text = COMMON_PSM1.read_text(encoding="utf-8")
        body = _function_body(text, "Invoke-NativeProcess")
        code_only = _strip_line_comments(body)
        assert not re.search(r"\$pid\s*=[^=]", code_only, re.IGNORECASE)
        assert "$processId" in body

    def test_invoke_native_process_output_contract_unchanged(self) -> None:
        """
        The rename above must not change Invoke-NativeProcess's
        documented output shape -- the Hashtable's `Pid` KEY (capital P,
        a string, entirely unrelated to the local variable's name) must
        still be present exactly as before.
        """
        text = COMMON_PSM1.read_text(encoding="utf-8")
        body = _function_body(text, "Invoke-NativeProcess")
        assert body.count("Pid = $processId") >= 3, "expected every returned Hashtable literal to still use the `Pid` key, now sourced from $processId"
