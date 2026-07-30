"""
tests/unit/test_installer_logic.py

Static logic checks on adam/sandbox/guest/agent/install.ps1 -- same
disclosed limitation as test_guest_service_static_structure.py: this
sandbox has no Windows/PowerShell runtime, so nothing here actually RUNS
install.ps1. These are regex/text-presence checks against the script's
source, verifying the specific idempotency/prerequisite/verification
behaviors Task G's INSTALLER section required are actually present in the
code, in roughly the right order -- catching an accidental deletion or a
refactor that silently drops one of these behaviors, not proving runtime
correctness (see docs/phase5-migration-guide.md's "Remaining Phase 5
gaps" -- a real Windows guest run of install.ps1 is still required before
this script should be trusted).
"""

from __future__ import annotations

import re
from pathlib import Path

INSTALL_PS1_PATH = (
    Path(__file__).resolve().parents[2] / "adam" / "sandbox" / "guest" / "agent" / "install.ps1"
)


def _read() -> str:
    return INSTALL_PS1_PATH.read_text(encoding="utf-8")


def _index_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    assert idx != -1, f"expected to find {needle!r} in install.ps1"
    return idx


def test_file_exists() -> None:
    assert INSTALL_PS1_PATH.exists()


# --------------------------------------------------------------------- #
# Prerequisite validation
# --------------------------------------------------------------------- #


def test_has_prerequisite_check_function() -> None:
    text = _read()
    assert "function Test-Prerequisites" in text


def test_prerequisites_check_powershell_version() -> None:
    text = _read()
    assert "$PSVersionTable.PSVersion" in text
    assert "5.1" in text


def test_prerequisites_check_administrator() -> None:
    text = _read()
    assert "WindowsBuiltInRole]::Administrator" in text


def test_prerequisites_check_windows_version() -> None:
    text = _read()
    assert "Win32_OperatingSystem" in text


def test_prerequisites_check_httplistener_availability() -> None:
    text = _read()
    assert "New-Object System.Net.HttpListener" in text


def test_console_helpers_never_write_to_the_pipeline() -> None:
    """
    Regression test for a real, shipped bug: Write-Step/Write-Ok/Write-Bad/
    Write-Info were originally defined with Write-Output, which places its
    argument on PowerShell's success/pipeline stream -- not just the
    console. A function that calls one of these internally (Test-
    Prerequisites calls Write-Ok once per PASSING check) has that string
    silently appended to its own return value, because PowerShell
    aggregates every bit of uncaptured pipeline output emitted inside a
    function as part of its result, not just whatever follows an explicit
    `return`. The observed symptom on a real VM: every prerequisite check
    printed [OK], and the script still took the failure branch, printing
    those same [OK] lines a second time as if they were the failure list
    -- because $prereqFailures ended up containing one stray "[OK] ..."
    string per PASSING check, so $prereqFailures.Count was never 0 even
    when $failures itself legitimately was.

    Write-Host is the fix: it writes straight to the console host and
    never touches the pipeline, so these purely-informational status
    lines can never again contaminate a function's real return value --
    this test locks that in for all four helpers, not just the one that
    happened to trigger the bug, since any of them could be called from
    inside a value-returning function in the future (e.g. if
    Test-Deployment ever grows an inline Write-Ok call).
    """
    text = _read()
    for name in ("Write-Step", "Write-Ok", "Write-Bad", "Write-Info"):
        match = re.search(rf"function {name}\s*\{{[^}}]*\}}", text)
        assert match is not None, f"expected a one-line 'function {name} {{ ... }}' definition"
        body = match.group(0)
        assert "Write-Host" in body, f"{name} must use Write-Host, not Write-Output -- see this test's docstring for why"
        assert "Write-Output" not in body, f"{name} must not use Write-Output -- it would leak into the return value of any function that calls it"


def test_prerequisites_has_no_unsuppressed_cmdlet_calls() -> None:
    """
    Narrower check on the exact function that shipped the bug: every
    PowerShell cmdlet/function invocation (a `Verb-Noun` token at the
    start of a statement) inside Test-Prerequisites must either be one of
    the Write-* console helpers (safe now that those use Write-Host -- see
    test_console_helpers_never_write_to_the_pipeline), or be captured via
    assignment (`$x = Cmdlet-Name ...`) or explicitly suppressed
    (`Cmdlet-Name ... | Out-Null`) -- never a bare, un-suppressed call,
    which would land on the pipeline and get silently bundled into the
    function's return value alongside `return $failures`, the exact shape
    of the original bug.
    """
    text = _read()
    fn_start = _index_of(text, "function Test-Prerequisites")
    fn_end = text.index("\n}\n", fn_start) + 3
    fn_text = re.sub(r"<#.*?#>", "", text[fn_start:fn_end], flags=re.DOTALL)  # strip block comments, e.g. a .SYNOPSIS docstring

    cmdlet_pattern = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*)\b")
    allowed_bare_calls = {"Write-Step", "Write-Ok", "Write-Bad", "Write-Info"}

    for line in fn_text.splitlines():
        match = cmdlet_pattern.match(line)
        if not match:
            continue
        cmdlet_name = match.group(1)
        if cmdlet_name in allowed_bare_calls:
            continue
        # Anything else must be captured (assigned) or explicitly
        # suppressed on the same line -- a bare call is the bug.
        is_assigned_or_suppressed = ("=" in line and line.index("=") < match.start(1)) or "Out-Null" in line
        assert is_assigned_or_suppressed, (
            f"Test-Prerequisites calls {cmdlet_name!r} without capturing or suppressing its output -- "
            f"this would leak onto the pipeline and reintroduce the [OK]-counted-as-failure bug: {line!r}"
        )


def test_prerequisites_are_checked_before_any_mutating_step() -> None:
    """Test-Prerequisites must run (and gate an exit on failure) before install.ps1 touches the filesystem/URL ACL/firewall/scheduled task -- otherwise a failed prereq check leaves partial state behind."""
    text = _read()
    prereq_call_idx = _index_of(text, "$prereqFailures = Test-Prerequisites")
    copy_idx = _index_of(text, "Copy-Item -Path (Join-Path $sourceRoot 'adam_agent.ps1')")
    urlacl_idx = _index_of(text, '& netsh http add urlacl url="$urlAclTarget"')
    firewall_idx = _index_of(text, "New-NetFirewallRule")
    scheduled_task_idx = _index_of(text, "Register-ScheduledTask")

    assert prereq_call_idx < copy_idx
    assert prereq_call_idx < urlacl_idx
    assert prereq_call_idx < firewall_idx
    assert prereq_call_idx < scheduled_task_idx


def test_exits_nonzero_on_prerequisite_failure() -> None:
    text = _read()
    prereq_block = text[text.index("if ($prereqFailures.Count -gt 0)"): text.index('Write-Step "Installing agent files')]
    assert "exit 1" in prereq_block


# --------------------------------------------------------------------- #
# source == destination handling
# --------------------------------------------------------------------- #


def test_detects_source_equals_destination_before_copying() -> None:
    """The exact bug Task G flagged: install.ps1 must not attempt to copy adam_agent.ps1/modules onto themselves when run directly from the install directory."""
    text = _read()
    assert "$sourceRoot -ieq $resolvedInstallDir" in text
    same_dir_check_idx = _index_of(text, "$sourceRoot -ieq $resolvedInstallDir")
    first_copy_idx = _index_of(text, "Copy-Item -Path (Join-Path $sourceRoot 'adam_agent.ps1')")
    assert same_dir_check_idx < first_copy_idx, "the source==destination check must precede the actual Copy-Item calls"


def test_skips_copy_when_source_equals_destination() -> None:
    text = _read()
    # The branch taken when source==destination must NOT itself call Copy-Item.
    match = re.search(
        r"if\s*\(\$sourceRoot -ieq \$resolvedInstallDir\)\s*\{([^}]*)\}\s*else\s*\{(.*?)\n\}",
        text,
        re.DOTALL,
    )
    assert match is not None, "expected an if/else around the source==destination check"
    same_dir_branch, different_dir_branch = match.group(1), match.group(2)
    assert "Copy-Item" not in same_dir_branch
    assert "Copy-Item" in different_dir_branch


# --------------------------------------------------------------------- #
# Idempotency: URL ACL / firewall / scheduled task / config
# --------------------------------------------------------------------- #


def test_url_acl_checked_before_adding() -> None:
    text = _read()
    assert "function Test-UrlAclReserved" in text
    check_idx = _index_of(text, "if (Test-UrlAclReserved -Url $urlAclTarget)")
    add_idx = _index_of(text, '& netsh http add urlacl url="$urlAclTarget"')
    assert check_idx < add_idx


def test_url_acl_check_does_not_rely_solely_on_exit_code() -> None:
    """netsh returns exit code 0 even when a urlacl reservation doesn't exist -- existence must be determined by matching the URL in the command's text output, not $LASTEXITCODE alone."""
    text = _read()
    fn_start = _index_of(text, "function Test-UrlAclReserved")
    fn_text = text[fn_start: fn_start + 600]
    assert "-match" in fn_text
    assert "netsh http show urlacl" in fn_text


def test_firewall_rule_checked_before_creating() -> None:
    text = _read()
    check_idx = _index_of(text, "Get-NetFirewallRule -DisplayName $Script:RuleName")
    create_idx = _index_of(text, "New-NetFirewallRule -DisplayName $Script:RuleName")
    assert check_idx < create_idx


def test_firewall_rule_recreated_if_port_changed() -> None:
    text = _read()
    assert "Get-NetFirewallPortFilter" in text
    assert "Remove-NetFirewallRule -DisplayName $Script:RuleName" in text


def test_scheduled_task_checked_before_registering() -> None:
    text = _read()
    check_idx = _index_of(text, "Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue")
    register_idx = _index_of(text, "Register-ScheduledTask -TaskName $Script:TaskName")
    assert check_idx < register_idx


def test_scheduled_task_reregisters_on_action_mismatch() -> None:
    text = _read()
    assert "$existingAction.Arguments -eq $expectedArgument" in text
    assert "Unregister-ScheduledTask -TaskName $Script:TaskName" in text


def test_config_file_merges_missing_keys_instead_of_only_write_if_absent() -> None:
    """A re-run against an existing agent.config.json from an older install.ps1 revision must gain any new default keys, not silently keep using an incomplete config."""
    text = _read()
    assert "-not (Test-Path -LiteralPath $configPath)" in text
    assert "existingHash.Contains($key)" in text
    assert "Merged new config keys into existing" in text


def test_config_file_never_clobbers_existing_values() -> None:
    """The merge loop must only ADD missing keys, never overwrite a key that's already present (an admin's edited tool paths must survive a re-run)."""
    text = _read()
    merge_block_start = _index_of(text, "foreach ($key in $defaultConfig.Keys)")
    merge_block = text[merge_block_start: merge_block_start + 400]
    assert "if (-not $existingHash.Contains($key))" in merge_block


# --------------------------------------------------------------------- #
# Post-install verification
# --------------------------------------------------------------------- #


def test_has_deployment_verification_function() -> None:
    text = _read()
    assert "function Test-Deployment" in text


def test_verification_checks_scheduled_task_exists_and_running() -> None:
    text = _read()
    fn_start = _index_of(text, "function Test-Deployment")
    fn_text = text[fn_start: fn_start + 3500]
    assert "ScheduledTaskExists" in fn_text
    assert "ScheduledTaskRunning" in fn_text


def test_verification_checks_config_file_exists() -> None:
    text = _read()
    fn_start = _index_of(text, "function Test-Deployment")
    fn_text = text[fn_start: fn_start + 3500]
    assert "ConfigFileExists" in fn_text


def test_verification_imports_every_module() -> None:
    text = _read()
    fn_start = _index_of(text, "function Test-Deployment")
    fn_text = text[fn_start: fn_start + 3500]
    assert "ModulesImportCleanly" in fn_text
    assert "Import-Module $psm1.FullName -Force -ErrorAction Stop" in fn_text


def test_verification_checks_health_endpoint() -> None:
    text = _read()
    fn_start = _index_of(text, "function Test-Deployment")
    fn_text = text[fn_start: fn_start + 3500]
    assert "HealthEndpointResponds" in fn_text
    assert "/health" in fn_text
    assert "response.success -eq $true -and $response.data.status -eq 'ok'" in fn_text


def test_verification_runs_after_all_install_steps() -> None:
    text = _read()
    scheduled_task_start_idx = _index_of(text, "Start-ScheduledTask -TaskName $Script:TaskName")
    verify_call_idx = _index_of(text, "$verification = Test-Deployment")
    assert scheduled_task_start_idx < verify_call_idx


def test_exits_nonzero_when_verification_fails() -> None:
    text = _read()
    verify_section = text[text.index("if (-not $allOk) {"):]
    assert "exit 1" in verify_section


def test_exits_zero_on_full_success() -> None:
    text = _read()
    tail = text[text.rindex("Deployment verified OK"):]
    assert "exit 0" in tail


def test_skip_verification_switch_exists_and_is_documented_as_opt_in() -> None:
    text = _read()
    assert "[switch]$SkipVerification" in text
    assert "if ($SkipVerification)" in text


# --------------------------------------------------------------------- #
# Uninstall / rollback
# --------------------------------------------------------------------- #


def test_uninstall_switch_reverses_every_install_step() -> None:
    text = _read()
    assert "[switch]$Uninstall" in text
    fn_start = _index_of(text, "function Invoke-Uninstall")
    fn_text = text[fn_start: fn_start + 2000]
    assert "Unregister-ScheduledTask" in fn_text
    assert "Remove-NetFirewallRule" in fn_text
    assert "netsh http delete urlacl" in fn_text


def test_uninstall_does_not_delete_install_dir_unless_remove_files_passed() -> None:
    text = _read()
    fn_start = _index_of(text, "function Invoke-Uninstall")
    fn_text = text[fn_start: fn_start + 2500]
    assert "if ($RemoveFiles)" in fn_text
    assert "Remove-Item -LiteralPath $InstallDir -Recurse -Force" in fn_text
