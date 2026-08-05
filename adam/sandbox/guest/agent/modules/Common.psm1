#requires -Version 5.1
<#
.SYNOPSIS
    Common.psm1 -- shared envelope/error/logging helpers for every guest
    agent manager module.

.DESCRIPTION
    Implements the response envelope and error-code vocabulary from
    docs/phase5-http-agent-api.md sections 2 and 2.1. Every manager module
    (FilesystemManager, ProcessManager, ProcmonManager, NetworkManager,
    SysmonManager, DiagnosticsManager, SampleManager, ArtifactManager)
    returns its result through New-SuccessEnvelope / New-ErrorEnvelope so
    every endpoint's JSON shape is produced in exactly one place, not
    reimplemented per-module.

    PowerShell 5.1 / .NET Framework only (ARCHITECTURE.md constraint C4 --
    "No .NET Core assumption"). No cmdlet in this file or any module that
    imports it shells out to cmd.exe for control flow; where an external
    tool must be launched (Procmon64.exe, tshark.exe, wevtutil.exe) it is
    always via System.Diagnostics.Process/ProcessStartInfo, with every
    argument quoted/escaped per-element via ConvertTo-Win32ArgumentString
    below (see Invoke-NativeProcess's own comment for why
    ProcessStartInfo.ArgumentList itself -- the more obvious choice --
    cannot be relied on here), never a shell, never naive
    space-joined string concatenation.
#>

Set-StrictMode -Version Latest

# --------------------------------------------------------------------- #
# Error codes -- mirrors adam/sandbox/guest/http_models.py's ErrorCode
# class and docs/phase5-http-agent-api.md section 2.1 exactly. Kept as
# plain strings (not a PowerShell enum) so the JSON value round-trips
# byte-for-byte with the Python side without a cast on either end.
# --------------------------------------------------------------------- #

$Script:ErrorCodes = @{
    NotFound          = 'NOT_FOUND'
    AlreadyExists     = 'ALREADY_EXISTS'
    AccessDenied      = 'ACCESS_DENIED'
    InvalidArgument   = 'INVALID_ARGUMENT'
    Timeout           = 'TIMEOUT'
    ToolNotConfigured = 'TOOL_NOT_CONFIGURED'
    ToolUnavailable   = 'TOOL_UNAVAILABLE'
    InternalError     = 'INTERNAL_ERROR'
}

# HTTP status mapping -- spec section 2.1's table, used by adam_agent.ps1
# when writing the HttpListenerResponse's StatusCode.
$Script:ErrorHttpStatus = @{
    NOT_FOUND          = 404
    ALREADY_EXISTS     = 409
    ACCESS_DENIED      = 403
    INVALID_ARGUMENT   = 400
    TIMEOUT            = 504
    TOOL_NOT_CONFIGURED = 412
    TOOL_UNAVAILABLE   = 503
    INTERNAL_ERROR     = 500
}

function New-SuccessEnvelope {
    <#
    .SYNOPSIS
        Builds the {"success": true, "data": {...}} envelope (spec section 2).
    .PARAMETER Data
        A hashtable/PSCustomObject to place under "data". May be $null for
        endpoints with no payload.
    #>
    param(
        [Parameter(Mandatory = $false)]
        $Data = $null
    )
    return [ordered]@{
        success       = $true
        error_code    = $null
        error_message = $null
        data          = $Data
    }
}

function New-ErrorEnvelope {
    <#
    .SYNOPSIS
        Builds the {"success": false, "error_code": ..., "error_message": ...} envelope.
    .PARAMETER ErrorCode
        One of $Script:ErrorCodes' values. Callers should use
        $Script:ErrorCodes.AccessDenied etc. rather than a raw string, to
        keep every call site consistent with the one vocabulary defined
        here.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ErrorCode,
        [Parameter(Mandatory = $true)][string]$ErrorMessage
    )
    return [ordered]@{
        success       = $false
        error_code    = $ErrorCode
        error_message = $ErrorMessage
        data          = $null
    }
}

function Get-ErrorHttpStatus {
    param([Parameter(Mandatory = $true)][string]$ErrorCode)
    if ($Script:ErrorHttpStatus.ContainsKey($ErrorCode)) {
        return $Script:ErrorHttpStatus[$ErrorCode]
    }
    return 500
}

function Write-AgentLog {
    <#
    .SYNOPSIS
        Timestamped log line to both the console (if attached) and a
        rolling log file under the agent's own install directory --
        mirrors agent.py's two-tier logging philosophy (a readable
        timeline; nothing here is DEBUG-gated since the guest agent has
        no host-side --verbose flag to react to, so everything is always
        logged, kept terse instead).

    .DESCRIPTION
        Uses Write-Host, not Write-Output, deliberately -- this is the
        same pipeline-pollution bug class install.ps1's Write-Step/
        Write-Ok/Write-Bad/Write-Info helpers shipped with (see this
        repo's own regression test for that fix,
        test_installer_logic.py::test_console_helpers_never_write_to_the_pipeline),
        just never applied here at the time. Write-Output puts its
        argument on the success/pipeline stream, so a call to
        Write-AgentLog from INSIDE a function whose OWN return value
        matters -- e.g. Invoke-ProcmonStart logging "Procmon started"
        immediately before its own `return New-SuccessEnvelope -Data
        @{ pid = ... }` -- leaked that log line into the CALLER's
        aggregate return value alongside the real hashtable:
        PowerShell aggregates every uncaptured pipeline object as a
        function's result, not just the value after `return`. This was
        a real, shipped bug: every endpoint whose handler called
        Write-AgentLog before its own success/error return (/procmon/
        start, /procmon/stop, /sysmon/export, and others -- see
        Write-AgentLog's callers across modules/*.psm1) returned a
        2-element `Object[]` (the log line string, then the real
        envelope hashtable) instead of a single Hashtable. adam_agent.
        ps1's Write-JsonResponse/Write-EnvelopeResponse both declare a
        `[hashtable]$Envelope` parameter, so PowerShell's own parameter
        binder rejected that array with "Cannot process argument
        transformation on parameter 'Envelope'. Cannot convert the
        "System.Object[]" value of type "System.Object[]" to type
        "System.Collections.Hashtable"." -- AFTER the real operation
        (Procmon/Sysmon/etc.) had already completed successfully, since
        the log call happens right before the return, not before the
        actual work. Write-Host writes straight to the console host and
        never touches the pipeline, so this log line can never again
        contaminate a caller's real return value.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $line = "[$timestamp] [$Level] $Message"
    Write-Host $line
    try {
        $logDir = Join-Path -Path $PSScriptRoot -ChildPath '..\logs'
        if (-not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        Add-Content -LiteralPath (Join-Path $logDir 'adam_agent.log') -Value $line -Encoding UTF8
    } catch {
        # Logging must never crash a request -- if the log file itself is
        # unwritable, the console/stdout line above is still emitted.
    }
}

function ConvertTo-Win32ArgumentString {
    <#
    .SYNOPSIS
        Builds a single, correctly quoted/escaped Win32 command-line
        string from an array of literal argument values -- the
        PowerShell 5.1 / .NET Framework compatible replacement for
        ProcessStartInfo.ArgumentList (see Invoke-NativeProcess's own
        comment, right below this function, for why that property cannot
        be relied on here).

    .DESCRIPTION
        Real, shipped bug this fixes: ProcessStartInfo.ArgumentList (a
        Collection<string> that lets each argument be added as its own
        opaque element, with .NET itself doing the quoting) was only
        added to ProcessStartInfo in .NET Framework 4.7.2 / .NET Core 2.1
        -- NOT ".NET 4.6.1", as an earlier version of this file's own
        comment incorrectly claimed. PowerShell 5.1 always runs on
        whatever .NET Framework happens to be installed on the host OS
        (unlike PowerShell 7, which bundles its own .NET Core/5+ runtime
        where ArgumentList is always present) -- ADAM_WIN10_OFFICE's
        installed .NET Framework predates 4.7.2, so
        `$psi.ArgumentList.Add(...)` compiled/parsed fine (PowerShell
        doesn't type-check property existence ahead of time) but threw
        "The property 'ArgumentList' cannot be found on this object" the
        first time it actually ran, on every endpoint that launches a
        process: /procmon/start, /procmon/stop (via Invoke-ProcmonStop's
        taskkill-equivalent path), /procmon/export, /network/interfaces,
        /network/start, /network/stop, /network/convert, /sysmon/export,
        plus ProcessManager.psm1's own /process/* routes and
        DiagnosticsManager.psm1's whoami-based token queries -- literally
        every Invoke-NativeProcess caller, since they all funnel through
        this one helper.

        This function replaces that dependency with
        ProcessStartInfo.Arguments -- a single string property that has
        existed on ProcessStartInfo since .NET Framework 1.1 and is
        therefore present on every Windows/.NET combination this guest
        image could possibly have -- built using the SAME argument
        quoting/escaping algorithm the Win32 C runtime's argv parser (and
        .NET's own internal ArgumentList-to-command-line conversion) use:
        an argument is left bare only if it contains no space, tab, or
        double-quote; otherwise it is wrapped in double quotes, with
        embedded double quotes escaped as \" and any run of backslashes
        doubled ONLY when it immediately precedes a quote character
        (either an embedded quote being escaped, or the argument's own
        closing quote) -- backslashes not adjacent to a quote pass
        through completely unchanged. This is real per-argument
        quoting/escaping applied to each element independently, not a
        naive space-joined string -- functionally equivalent to what
        ArgumentList would have produced, just built by hand because the
        property itself cannot be trusted to exist.

    .PARAMETER Arguments
        Literal argument values, unescaped -- e.g. a path containing a
        space is passed as-is (`'C:\Program Files\Wireshark\tshark.exe'`),
        not pre-quoted by the caller. Matches ArgumentList's own calling
        convention exactly, so every existing call site (which already
        passes an -ArgumentList array of literal values) needed no
        changes.
    #>
    param([Parameter(Mandatory = $false)][string[]]$Arguments = @())

    $parts = foreach ($arg in $Arguments) {
        if ($arg.Length -gt 0 -and $arg -notmatch '[\s"]') {
            # No space/tab/quote anywhere in this argument -- safe bare,
            # exactly as ArgumentList would have passed it through
            # unquoted.
            $arg
            continue
        }

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('"')
        $backslashCount = 0
        foreach ($ch in $arg.ToCharArray()) {
            if ($ch -eq '\') {
                $backslashCount++
                continue
            }
            if ($ch -eq '"') {
                # Every pending backslash must be doubled (once for
                # itself, once more because a literal quote follows),
                # then the quote itself is escaped.
                [void]$sb.Append('\' * (($backslashCount * 2) + 1))
                [void]$sb.Append('"')
            } else {
                # Pending backslashes were NOT followed by a quote -- they
                # pass through completely literally, never doubled.
                [void]$sb.Append('\' * $backslashCount)
                [void]$sb.Append($ch)
            }
            $backslashCount = 0
        }
        # Trailing backslashes (the argument ends in one or more '\')
        # must be doubled -- otherwise the closing quote we're about to
        # append would be read as escaping the last one instead of
        # closing the argument.
        [void]$sb.Append('\' * ($backslashCount * 2))
        [void]$sb.Append('"')
        $sb.ToString()
    }

    return ($parts -join ' ')
}

function Invoke-NativeProcess {
    <#
    .SYNOPSIS
        Launches an external executable via System.Diagnostics.Process --
        the one, central place every manager module launches
        Procmon64.exe/tshark.exe/wevtutil.exe/etc. from, so "no shell, no
        manual command-line quoting" (API spec sections 5/7/8) is
        enforced in one place rather than trusted per call site.

    .PARAMETER FilePath
        Absolute path to the executable. Passed to ProcessStartInfo as
        FileName directly (the .NET equivalent of CreateProcessW's
        lpApplicationName) -- a space-containing path needs no quoting
        here, unlike a shell command line, because this is never
        re-parsed as text.

    .PARAMETER ArgumentList
        A real array of separate, literal argument strings, each quoted
        and escaped independently by ConvertTo-Win32ArgumentString (above)
        into ProcessStartInfo.Arguments -- see that function's own
        docstring for exactly why (ProcessStartInfo.ArgumentList itself,
        the more obvious API, cannot be relied on under this guest's
        PowerShell 5.1 / .NET Framework combination). Still never a shell,
        never naive space-joined string concatenation -- just built
        without the newer property.

    .PARAMETER RedirectStandardOutputTo
        Optional file path -- if set, stdout is streamed directly to this
        file (the native replacement for cmd.exe's `>` redirection used
        by tshark's EK JSON conversion, API spec section 7).

    .PARAMETER TimeoutMs
        Milliseconds to wait for exit before treating this as a timeout.
        $null means launch and return immediately without waiting
        (detached, for long-running captures).

    .OUTPUTS
        Hashtable: @{ Pid=<int>; Exited=<bool>; ExitCode=<int|$null>;
        StdOut=<string>; StdErr=<string>; TimedOut=<bool> }
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $false)][string[]]$ArgumentList = @(),
        [Parameter(Mandatory = $false)][string]$RedirectStandardOutputTo = $null,
        [Parameter(Mandatory = $false)][Nullable[int]]$TimeoutMs = $null,
        [Parameter(Mandatory = $false)][string]$WorkingDirectory = $null
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # Explicit UTF-8, not left to default to the OEM console code page --
    # matters most for tshark's EK JSON output (NetworkManager.psm1's
    # RedirectStandardOutputTo path), which is UTF-8 and can legitimately
    # contain non-ASCII bytes (e.g. internationalized domain names).
    # Must be set before Start(); only takes effect because
    # RedirectStandard{Output,Error} are both already true above.
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }

    # NOT $psi.ArgumentList.Add(...): that property was only added to
    # ProcessStartInfo in .NET Framework 4.7.2 / .NET Core 2.1, and this
    # guest's PowerShell 5.1 runs on whatever .NET Framework the OS image
    # actually has installed (unlike PowerShell 7, which bundles its own
    # runtime and always has it) -- a real, shipped bug here threw "The
    # property 'ArgumentList' cannot be found on this object" at runtime
    # on every single Invoke-NativeProcess call. $psi.Arguments (a plain
    # string, present on ProcessStartInfo since .NET Framework 1.1) is
    # built instead via ConvertTo-Win32ArgumentString (above), which
    # quotes/escapes each element exactly as ArgumentList would have --
    # see that function's own docstring for the full explanation and
    # this class of bug's other guest-startup precedent
    # (Write-AgentLog's Import-Module -Force nested-reimport crash).
    $psi.Arguments = ConvertTo-Win32ArgumentString -Arguments $ArgumentList

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi

    try {
        $process.Start() | Out-Null
    } catch {
        return @{
            Pid = $null; Exited = $false; ExitCode = $null
            StdOut = ''; StdErr = $_.Exception.Message; TimedOut = $false
        }
    }

    # NOT $pid: $PID is PowerShell's own read-only automatic variable
    # (the CURRENT process's id) -- see adam_agent.ps1's GET
    # /process/query route for the real, shipped bug this exact pattern
    # caused there ("Cannot overwrite variable PID because it is
    # read-only or constant"). Not currently observed to fail at this
    # particular call site, but it's the identical anti-pattern, purely
    # a local variable with no external contract riding on its name
    # (the returned Hashtable's `Pid` KEY, capital P, is unrelated and
    # unchanged) -- renamed defensively rather than leaving the same
    # footgun in place.
    $processId = $process.Id

    if ($null -eq $TimeoutMs) {
        # Detached launch (Procmon/tshark capture start) -- do not wait,
        # do not read stdout/stderr streams (that would block on a
        # process that's expected to keep running).
        return @{ Pid = $processId; Exited = $false; ExitCode = $null; StdOut = ''; StdErr = ''; TimedOut = $false }
    }

    $stdOutTask = $process.StandardOutput.ReadToEndAsync()
    $stdErrTask = $process.StandardError.ReadToEndAsync()
    $exited = $process.WaitForExit($TimeoutMs)

    if (-not $exited) {
        try { $process.Kill() } catch { }
        return @{ Pid = $processId; Exited = $false; ExitCode = $null; StdOut = ''; StdErr = ''; TimedOut = $true }
    }

    $stdOut = $stdOutTask.Result
    $stdErr = $stdErrTask.Result

    if ($RedirectStandardOutputTo) {
        # Native replacement for `cmd.exe /c ... > file` -- write the
        # captured stdout stream directly to disk, no shell redirection
        # operator anywhere in this path.
        [System.IO.File]::WriteAllText($RedirectStandardOutputTo, $stdOut)
    }

    return @{
        Pid = $processId; Exited = $true; ExitCode = $process.ExitCode
        StdOut = $stdOut; StdErr = $stdErr; TimedOut = $false
    }
}

Export-ModuleMember -Function New-SuccessEnvelope, New-ErrorEnvelope, Get-ErrorHttpStatus, Write-AgentLog, Invoke-NativeProcess -Variable ErrorCodes
