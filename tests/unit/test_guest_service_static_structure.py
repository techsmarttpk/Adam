"""
tests/unit/test_guest_service_static_structure.py

"Guest service startup tests", best-effort substitute. This sandbox has no
Windows/PowerShell runtime, so none of these tests actually START
adam_agent.ps1 or execute a single line of PowerShell -- they are static
structural checks only: balanced braces/parens, every route referenced in
adam_agent.ps1 has a corresponding Export-ModuleMember'd function in the
module it calls, and every route in adam_agent.ps1 is present in
docs/phase5-http-agent-api.md. This catches obvious drift (a renamed
function, a route removed from one side but not the other) but proves
NOTHING about runtime correctness -- see docs/phase5-migration-guide.md's
"Remaining Phase 5 gaps" for the real verification this still needs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

GUEST_AGENT_DIR = Path(__file__).resolve().parents[2] / "adam" / "sandbox" / "guest" / "agent"
API_SPEC_PATH = Path(__file__).resolve().parents[2] / "docs" / "phase5-http-agent-api.md"

PS1_FILES = [GUEST_AGENT_DIR / "adam_agent.ps1", GUEST_AGENT_DIR / "install.ps1"]
PSM1_FILES = sorted((GUEST_AGENT_DIR / "modules").glob("*.psm1"))


def _strip_block_comments(text: str) -> str:
    """Removes every `<# ... #>` PowerShell block comment (non-greedy, DOTALL) before brace/paren counting -- these routinely contain example code snippets with their own braces that must not be counted."""
    return re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)


def _balanced(text: str, open_ch: str, close_ch: str) -> bool:
    text = _strip_block_comments(text)
    depth = 0
    in_single = False
    in_double = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
        elif in_double:
            if ch == '"':
                in_double = False
        elif ch == "'":
            in_single = True
        elif ch == '"':
            in_double = True
        elif ch == "#":
            newline = text.find("\n", i)
            i = newline if newline != -1 else len(text)
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
        i += 1
    return depth == 0


@pytest.mark.parametrize("path", PS1_FILES + PSM1_FILES, ids=lambda p: p.name)
def test_file_exists_and_nonempty(path: Path) -> None:
    assert path.exists(), f"missing guest agent file: {path}"
    assert path.stat().st_size > 0


@pytest.mark.parametrize("path", PS1_FILES + PSM1_FILES, ids=lambda p: p.name)
def test_braces_and_parens_are_balanced(path: Path) -> None:
    """
    A crude but real syntax smell test -- catches an unclosed `{`/`(` (a
    very easy mistake to make writing PowerShell without a runtime to
    check it against). Comment-aware (strips `# ...` to end of line) and
    quote-aware (ignores braces inside '...'/"..." strings) so it doesn't
    false-positive on a brace mentioned in a comment or string literal.
    Does NOT parse PowerShell -- a genuinely malformed script could still
    pass this check.
    """
    text = path.read_text(encoding="utf-8")
    assert _balanced(text, "{", "}"), f"{path.name}: unbalanced {{ }}"
    assert _balanced(text, "(", ")"), f"{path.name}: unbalanced ( )"


@pytest.mark.parametrize("path", PSM1_FILES, ids=lambda p: p.name)
def test_every_module_has_export_modulemember(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if path.name == "AgentConfig.psm1":
        pytest.skip("config loader -- exports Get-AgentConfig only, checked separately")
    assert "Export-ModuleMember" in text, f"{path.name}: no Export-ModuleMember -- its functions would be unreachable from adam_agent.ps1"


def test_every_exported_function_is_referenced_in_adam_agent() -> None:
    """
    Every function a module exports should be called from SOMEWHERE in
    adam_agent.ps1's route table -- an exported-but-unused function is
    either dead code or a route the router forgot to wire up.
    """
    agent_text = (GUEST_AGENT_DIR / "adam_agent.ps1").read_text(encoding="utf-8")

    for psm1 in PSM1_FILES:
        text = psm1.read_text(encoding="utf-8")
        export_match = re.search(r"Export-ModuleMember\s+-Function\s+([^\n]+)", text)
        if not export_match:
            continue
        exported_names = [n.strip() for n in export_match.group(1).split(",") if n.strip() and "-Variable" not in n]
        for name in exported_names:
            # Get-Sha256Hex is an internal helper re-used by ArtifactManager,
            # not a route handler -- expected to not appear in adam_agent.ps1.
            if name in ("Get-Sha256Hex",):
                continue
            assert name in agent_text, f"{psm1.name} exports {name}, but adam_agent.ps1 never calls it"


@pytest.mark.parametrize("path", PSM1_FILES, ids=lambda p: p.name)
def test_no_nested_force_reimport_of_a_sibling_module(path: Path) -> None:
    """
    Regression test for a real, shipped startup crash: every manager
    module used to do `Import-Module (Join-Path $PSScriptRoot
    'Common.psm1') -Force` internally, and ArtifactManager.psm1 did the
    same for SampleManager.psm1. Since adam_agent.ps1 (the top-level
    entrypoint) already imports every one of these modules directly and
    exactly once, a NESTED `-Force` reimport of one of them from inside
    another module removes its exports from wherever they were
    originally loaded -- adam_agent.ps1's own top-level scope -- and
    re-adds them only into the nested importer's private scope,
    invisible to the top-level script (a documented PowerShell behavior:
    github.com/PowerShell/PowerShell issue 7367). The observed symptom
    was `Write-AgentLog : The term 'Write-AgentLog' is not recognized`
    the first time Start-AdamAgent called it, well after every
    Import-Module line had already reported success.

    A plain `Import-Module Foo.psm1` (no -Force) is idempotent -- if
    Foo.psm1 is already loaded, it's a no-op, so the original,
    correctly-scoped instance survives. This test asserts every
    `Import-Module (Join-Path $PSScriptRoot '<AnotherModule>.psm1')`
    line inside any modules/*.psm1 file omits `-Force`.
    """
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r"Import-Module\s+\(Join-Path\s+\$PSScriptRoot\s+'([^']+\.psm1)'\)(\s*-Force)?", text):
        imported_module, force_flag = match.group(1), match.group(2)
        assert not force_flag, (
            f"{path.name} imports {imported_module} with -Force from a nested module scope -- this reintroduces "
            f"the PowerShell/PowerShell#7367 class of bug that caused a real 'Write-AgentLog is not recognized' "
            f"startup crash. Drop -Force; a plain Import-Module is idempotent and won't strip {imported_module}'s "
            f"exports out of adam_agent.ps1's top-level scope."
        )


def test_adam_agent_has_a_startup_self_test() -> None:
    """
    Regression test for the same shipped bug (see
    test_no_nested_force_reimport_of_a_sibling_module's docstring):
    adam_agent.ps1 must verify every function it depends on is actually
    callable immediately after importing its modules, and before
    Start-AdamAgent (which binds the HttpListener and starts serving
    requests) ever runs -- so a startup-time import/export problem is
    reported clearly and immediately, not the first time some specific
    route handler happens to be hit.
    """
    text = (GUEST_AGENT_DIR / "adam_agent.ps1").read_text(encoding="utf-8")
    assert "function Test-RequiredCommandsAvailable" in text
    assert "Get-Command -Name" in text

    self_test_call_idx = text.index("\nTest-RequiredCommandsAvailable\n")
    listener_start_idx = text.index("function Start-AdamAgent")
    invocation_idx = text.rindex("Start-AdamAgent")  # the bottom-of-file call, not the function definition
    assert self_test_call_idx < listener_start_idx, "the startup self-test must run before Start-AdamAgent is even defined in reading order"
    assert self_test_call_idx < invocation_idx, "the startup self-test must run before Start-AdamAgent is actually invoked"


def test_startup_self_test_command_list_matches_real_module_exports() -> None:
    """
    Cross-checks $Script:RequiredCommandsByModule's per-module function
    list (adam_agent.ps1) against that module's own real
    Export-ModuleMember list -- every command the self-test expects from
    a module must actually be exported by that module's .psm1 file, or
    the self-test itself would either always fail (checking for a
    function that was never really exported) or -- worse -- silently
    stop protecting against a real drift if someone edits one list and
    not the other.
    """
    agent_text = (GUEST_AGENT_DIR / "adam_agent.ps1").read_text(encoding="utf-8")

    dict_match = re.search(r"\$Script:RequiredCommandsByModule\s*=\s*\[ordered\]@\{(.*?)\n\}", agent_text, re.DOTALL)
    assert dict_match is not None, "expected a $Script:RequiredCommandsByModule = [ordered]@{ ... } block in adam_agent.ps1"

    required_by_module: dict[str, list[str]] = {}
    for line_match in re.finditer(r"'([^']+\.psm1)'\s*=\s*@\(([^)]*)\)", dict_match.group(1)):
        module_name = line_match.group(1)
        commands = [c.strip().strip("'") for c in line_match.group(2).split(",") if c.strip()]
        required_by_module[module_name] = commands

    assert required_by_module, "failed to parse any entries out of $Script:RequiredCommandsByModule -- check the regex above against adam_agent.ps1's current formatting"

    for module_name, required_commands in required_by_module.items():
        if module_name == "AgentConfig.psm1":
            exported_names = ["Get-AgentConfig"]  # see test_every_module_has_export_modulemember's own skip for this module
        else:
            module_path = GUEST_AGENT_DIR / "modules" / module_name
            assert module_path.exists(), f"$Script:RequiredCommandsByModule references {module_name}, which doesn't exist under modules/"
            module_text = module_path.read_text(encoding="utf-8")
            export_match = re.search(r"Export-ModuleMember\s+-Function\s+([^\n]+)", module_text)
            assert export_match is not None, f"{module_name} has no Export-ModuleMember line to check {module_name}'s required commands against"
            # The -Function argument list ends at the next `-Something`
            # switch/parameter (e.g. Common.psm1's trailing `-Variable
            # ErrorCodes`) -- split that off BEFORE comma-splitting, so a
            # trailing "-Variable ErrorCodes" clause doesn't swallow the
            # last real function name along with it (a plain "does this
            # element contain '-Variable'" substring filter would drop
            # "Invoke-NativeProcess -Variable ErrorCodes" as one unsplit
            # chunk, silently losing "Invoke-NativeProcess" too).
            function_list_text = re.split(r"\s+-\w+\s", export_match.group(1))[0]
            exported_names = [n.strip() for n in function_list_text.split(",") if n.strip()]

        for command_name in required_commands:
            assert command_name in exported_names, (
                f"adam_agent.ps1's startup self-test expects {command_name!r} from {module_name}, "
                f"but {module_name} does not export it (exports: {exported_names})"
            )


def test_route_table_covers_every_get_and_post_in_api_spec() -> None:
    """
    Cross-checks adam_agent.ps1's route table against every `| Method |
    Path |` table row in docs/phase5-http-agent-api.md -- the API spec is
    this project's single source of truth for the contract; a route
    documented there but missing from the router (or vice versa) is a
    real drift bug this test exists to catch.
    """
    spec_text = API_SPEC_PATH.read_text(encoding="utf-8")
    documented_routes = set(re.findall(r"\|\s*(GET|POST)\s*\|\s*(`[^`]+`|/\S+)\s*\|", spec_text))
    documented_routes = {
        (method, path.strip("`").split("?")[0]) for method, path in documented_routes
    }
    # health/version aren't in a markdown table (they're their own headed
    # sections) -- included explicitly.
    documented_routes |= {("GET", "/health"), ("GET", "/version")}

    agent_text = (GUEST_AGENT_DIR / "adam_agent.ps1").read_text(encoding="utf-8")
    router_routes = set(re.findall(r"'(GET|POST)\s+(/[^']*)'\s*\{", agent_text))

    missing_from_router = documented_routes - router_routes
    assert not missing_from_router, f"routes documented in the API spec but missing from adam_agent.ps1's router: {missing_from_router}"
