"""
tests/unit/test_native_process_argument_quoting.py

Regression tests for a real, shipped guest-agent bug: Common.psm1's
Invoke-NativeProcess (the one shared helper every manager module's
process-launching endpoint funnels through -- /procmon/start,
/procmon/stop, /network/interfaces, /network/start, /sysmon/export, and
every other Invoke-NativeProcess caller) used to build its
System.Diagnostics.ProcessStartInfo argument list via
`$psi.ArgumentList.Add($arg)`. ProcessStartInfo.ArgumentList was only
added in .NET Framework 4.7.2 / .NET Core 2.1 -- PowerShell 5.1 runs on
whatever .NET Framework the guest OS actually has installed (unlike
PowerShell 7, which bundles its own runtime and always has the property),
and ADAM_WIN10_OFFICE's installed .NET Framework predates 4.7.2. Every
endpoint that launched a process therefore failed at runtime with "The
property 'ArgumentList' cannot be found on this object" -- a
PropertyNotFoundException Set-StrictMode can only catch by actually
touching the (absent) property, so nothing caught this ahead of time.

The fix replaces that dependency with ProcessStartInfo.Arguments (a plain
string property present on ProcessStartInfo since .NET Framework 1.1),
built via a new ConvertTo-Win32ArgumentString helper that implements the
same argument quoting/escaping algorithm the Win32 C runtime's argv
parser (and .NET's own internal ArgumentList-to-command-line conversion)
uses.

Like every other guest-agent test in this suite (see
test_guest_service_static_structure.py's own module docstring), this
sandbox has no PowerShell runtime -- pwsh isn't installed here and the
guest script targets Windows PowerShell 5.1 specifically, so nothing here
executes a single line of the real .ps1/.psm1 file. Two complementary,
non-execution techniques are used instead:

  1. Static structural checks (regex over Common.psm1's own source) that
     the incompatible ArgumentList API is gone and the compatible
     Arguments-string approach is in place.
  2. An algorithm-equivalence check: a line-for-line Python transcription
     of ConvertTo-Win32ArgumentString's quoting algorithm, verified
     against a battery of known-correct Win32 argv-quoting vectors. This
     proves the ALGORITHM this fix implements is correct; it does not
     prove the actual PowerShell text has zero syntax errors beyond what
     test_guest_service_static_structure.py's brace/paren balance check
     already covers. See docs/phase5-migration-guide.md's "Remaining
     Phase 5 gaps" for what still needs a real VM/real PowerShell 5.1
     host to fully verify.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

GUEST_AGENT_DIR = Path(__file__).resolve().parents[2] / "adam" / "sandbox" / "guest" / "agent"
COMMON_PSM1 = GUEST_AGENT_DIR / "modules" / "Common.psm1"


def _function_body(text: str, function_name: str) -> str:
    """
    Extracts one `function <Name> { ... }` block's body via brace
    counting (quote/comment-aware isn't needed here -- Common.psm1's
    functions don't contain unbalanced braces inside string literals),
    starting from the function's own opening `{` through its matching
    closing `}`. Same "no real PowerShell parser available" constraint as
    test_guest_service_static_structure.py -- this is a pragmatic,
    disclosed approximation, not a real parse.
    """
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


class TestArgumentListRegressionStatic:
    """Static regex checks against the real Common.psm1 on disk -- no mocks, no reimplementation of the file's content."""

    def test_common_psm1_exists(self) -> None:
        assert COMMON_PSM1.exists()

    def test_invoke_native_process_no_longer_uses_processstartinfo_argumentlist(self) -> None:
        """
        The specific incompatible LIVE CODE statement,
        `$psi.ArgumentList.Add($arg)` (a real variable interpolation, not
        the literal "..." placeholder this fix's own explanatory comments
        use when referring to the old, removed line in prose), must be
        gone from Invoke-NativeProcess's body -- this is the exact
        statement that threw "The property 'ArgumentList' cannot be
        found on this object" on the real guest. Deliberately does NOT
        forbid the substring "$psi.ArgumentList" outright: this fix's own
        comments legitimately mention it while explaining what NOT to do
        and why -- see Common.psm1's ConvertTo-Win32ArgumentString
        docstring and the comment directly above the new $psi.Arguments
        assignment.
        """
        text = COMMON_PSM1.read_text(encoding="utf-8")
        body = _function_body(text, "Invoke-NativeProcess")
        assert not re.search(r"\$psi\.ArgumentList\.Add\(\$\w+\)", body), (
            "Invoke-NativeProcess still contains a live $psi.ArgumentList.Add(<var>) call -- this "
            "property was only added to ProcessStartInfo in .NET Framework 4.7.2 / .NET Core 2.1 and "
            "threw 'The property ArgumentList cannot be found on this object' under this guest's actual "
            "PowerShell 5.1 / older .NET Framework combination. Use $psi.Arguments (a plain string, "
            "present since .NET Framework 1.1) built via ConvertTo-Win32ArgumentString instead."
        )
        # The loop that used to call it (`foreach ($arg in $ArgumentList)
        # { $psi.ArgumentList.Add($arg) }`) must be gone too, not just
        # the one line -- confirms this wasn't left dangling/unreachable.
        assert not re.search(r"foreach\s*\(\s*\$arg\s+in\s+\$ArgumentList\s*\)\s*\{\s*\$psi\.ArgumentList", body)

    def test_invoke_native_process_sets_arguments_via_the_quoting_helper(self) -> None:
        text = COMMON_PSM1.read_text(encoding="utf-8")
        body = _function_body(text, "Invoke-NativeProcess")
        assert re.search(r"\$psi\.Arguments\s*=\s*ConvertTo-Win32ArgumentString", body), (
            "Invoke-NativeProcess must build $psi.Arguments via ConvertTo-Win32ArgumentString -- "
            "the PowerShell 5.1 / .NET Framework 1.1-compatible replacement for ProcessStartInfo."
            "ArgumentList."
        )

    def test_argument_list_parameter_still_accepts_an_array_unchanged(self) -> None:
        """
        Endpoint behavior must not change (explicit instruction this fix
        was built against) -- every existing call site passes
        `-ArgumentList @(...)` (a literal array of separate argument
        values); Invoke-NativeProcess's own public parameter shape must
        stay exactly that, only its INTERNAL handling of that array
        changed.
        """
        text = COMMON_PSM1.read_text(encoding="utf-8")
        body = _function_body(text, "Invoke-NativeProcess")
        assert re.search(r"\[Parameter\(Mandatory = \$false\)\]\[string\[\]\]\$ArgumentList = @\(\)", body)

    def test_convert_to_win32_argument_string_helper_exists(self) -> None:
        text = COMMON_PSM1.read_text(encoding="utf-8")
        assert "function ConvertTo-Win32ArgumentString" in text
        # Defined before its one caller, Invoke-NativeProcess, so
        # PowerShell's own load-time function resolution (top-to-bottom
        # within a module, same as Get-Sha256Hex/Invoke-SampleUpload's
        # ordering in SampleManager.psm1) sees it already defined.
        assert text.index("function ConvertTo-Win32ArgumentString") < text.index("function Invoke-NativeProcess")

    def test_every_manager_module_still_calls_invoke_native_process_unchanged(self) -> None:
        """
        Confirms this fix stayed inside Common.psm1 -- none of the
        manager modules' own -ArgumentList call sites (ProcmonManager,
        NetworkManager, SysmonManager, ProcessManager,
        DiagnosticsManager) needed to change, since
        ConvertTo-Win32ArgumentString's calling convention matches
        ArgumentList's exactly (a literal array of unescaped values).
        """
        for module_name, expected_snippet in [
            ("ProcmonManager.psm1", "Invoke-NativeProcess -FilePath $ProcmonPath -ArgumentList $args"),
            ("NetworkManager.psm1", "Invoke-NativeProcess -FilePath $TsharkPath -ArgumentList"),
            ("SysmonManager.psm1", "Invoke-NativeProcess -FilePath $wevtutil -ArgumentList"),
            ("ProcessManager.psm1", "Invoke-NativeProcess -FilePath $Executable -ArgumentList $Arguments"),
            ("DiagnosticsManager.psm1", "Invoke-NativeProcess -FilePath $whoami -ArgumentList"),
        ]:
            text = (GUEST_AGENT_DIR / "modules" / module_name).read_text(encoding="utf-8")
            assert expected_snippet in text, f"{module_name}: expected call-site shape not found -- {expected_snippet!r}"


# --------------------------------------------------------------------- #
# Algorithm-equivalence test -- Python transcription of
# ConvertTo-Win32ArgumentString's quoting/escaping logic, verified
# against known-correct Win32 argv-quoting vectors. See module docstring
# for why this, and not real execution, is what's available here.
# --------------------------------------------------------------------- #


def _quote_one_argument(arg: str) -> str:
    """
    Line-for-line transcription of ConvertTo-Win32ArgumentString's
    per-argument quoting logic (Common.psm1) into Python, for
    verification against known-correct vectors without a PowerShell
    runtime. Keep in sync with the .psm1 by hand -- there is no shared
    source between the two languages (same disclosed limitation as
    adam/sandbox/guest/http_models.py's own module docstring: "no shared
    runtime between Python and PowerShell").
    """
    if len(arg) > 0 and not re.search(r'[\s"]', arg):
        return arg

    out: list[str] = ['"']
    backslash_count = 0
    for ch in arg:
        if ch == "\\":
            backslash_count += 1
            continue
        if ch == '"':
            out.append("\\" * (backslash_count * 2 + 1))
            out.append('"')
        else:
            out.append("\\" * backslash_count)
            out.append(ch)
        backslash_count = 0
    out.append("\\" * (backslash_count * 2))
    out.append('"')
    return "".join(out)


def _quote_argument_list(args: list[str]) -> str:
    return " ".join(_quote_one_argument(a) for a in args)


@pytest.mark.parametrize(
    "args,expected",
    [
        # Empty argument -- must become an explicit empty pair of quotes,
        # not simply vanish (a bare "" would collapse to nothing if
        # space-joined naively).
        ([""], '""'),
        # No special characters -- left bare, exactly as ArgumentList
        # would pass it through unquoted.
        (["abc"], "abc"),
        # A space forces quoting.
        (["a b"], '"a b"'),
        # A lone embedded quote must be escaped, and its argument quoted.
        (['"'], '"\\""'),
        (['a"b'], '"a\\"b"'),
        # A backslash NOT adjacent to a quote or the argument's end
        # passes through completely literally, undoubled, and does not
        # by itself force quoting.
        (["a\\b"], "a\\b"),
        # A backslash before a space (which DOES force quoting) still
        # passes through literally -- only backslashes immediately before
        # a quote character (embedded or closing) get doubled.
        (["a\\ b"], '"a\\ b"'),
        # A trailing backslash on an argument that's quoted for another
        # reason (the embedded space) must be doubled, or the closing
        # quote would be read as escaping it instead of closing the
        # argument -- the single most common real-world case this
        # guards, since every guest tool path in config/default.toml ends
        # in a directory-like prefix.
        (["C:\\Program Files\\"], '"C:\\Program Files\\\\"'),
        # Multiple arguments -- each quoted independently, then
        # space-joined -- matching real Invoke-NativeProcess call sites
        # (NetworkManager.psm1's tshark invocation, SysmonManager.psm1's
        # wevtutil invocation).
        (
            ["-r", "C:\\ADAM\\telemetry\\sess_001_network.pcapng", "-T", "ek"],
            "-r C:\\ADAM\\telemetry\\sess_001_network.pcapng -T ek",
        ),
        (
            ["epl", "Microsoft-Windows-Sysmon/Operational", "C:\\ADAM\\telemetry\\sess_001_sysmon.evtx"],
            "epl Microsoft-Windows-Sysmon/Operational C:\\ADAM\\telemetry\\sess_001_sysmon.evtx",
        ),
        # No arguments at all -- empty command line, not an error.
        ([], ""),
    ],
)
def test_win32_argument_quoting_algorithm_matches_known_vectors(args: list[str], expected: str) -> None:
    assert _quote_argument_list(args) == expected
