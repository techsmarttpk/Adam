#requires -Version 5.1
<#
.SYNOPSIS
    ProcessManager.psm1 -- implements docs/phase5-http-agent-api.md
    section 5 (/process/*).

.DESCRIPTION
    start/terminate/wait/query all use System.Diagnostics.Process and
    Get-CimInstance Win32_Process directly -- no `tasklist`/`taskkill`
    text output parsed anywhere. Process launches go through
    Common.psm1's Invoke-NativeProcess, the one place ArgumentList-based
    (no shell) launching is implemented.
#>

Set-StrictMode -Version Latest
# No -Force: Common.psm1 is already imported once by adam_agent.ps1 at
# top level; -Force here would remove that instance's exports from the
# top-level script's scope and re-add them only nested in this module,
# invisible to adam_agent.ps1 itself (PowerShell/PowerShell#7367) -- see
# ArtifactManager.psm1's own comment on this same line for the full
# explanation; this was a real, shipped startup crash
# ("Write-AgentLog is not recognized").
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')

function Invoke-ProcessStart {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $false)][string[]]$Arguments = @(),
        [Parameter(Mandatory = $false)][string]$WorkingDirectory = $null,
        [Parameter(Mandatory = $false)][bool]$Wait = $false,
        [Parameter(Mandatory = $false)][Nullable[double]]$TimeoutS = $null
    )
    try {
        $timeoutMs = if ($Wait) { if ($TimeoutS) { [int]($TimeoutS * 1000) } else { -1 } } else { $null }
        $result = Invoke-NativeProcess -FilePath $Executable -ArgumentList $Arguments -WorkingDirectory $WorkingDirectory -TimeoutMs $timeoutMs

        if ($null -eq $result.Pid) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $result.StdErr
        }
        if ($Wait -and $result.TimedOut) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.Timeout -ErrorMessage "process did not exit within ${TimeoutS}s"
        }
        return New-SuccessEnvelope -Data @{
            pid       = $result.Pid
            exit_code = $result.ExitCode
            stdout    = $result.StdOut
            stderr    = $result.StdErr
        }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-ProcessTerminate {
    param(
        [Parameter(Mandatory = $false)][Nullable[int]]$ProcessId = $null,
        [Parameter(Mandatory = $false)][string]$Name = $null
    )
    try {
        $targets = @()
        if ($ProcessId) {
            $targets = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        } elseif ($Name) {
            $bare = $Name -replace '\.exe$', ''
            $targets = Get-Process -Name $bare -ErrorAction SilentlyContinue
        } else {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InvalidArgument -ErrorMessage "either pid or name is required"
        }

        $count = 0
        foreach ($proc in $targets) {
            try {
                $proc.Kill()
                $count++
            } catch {
                # A process that exits between enumeration and Kill() is
                # not an error -- same idempotency stance as filesystem
                # delete-of-absent-path.
            }
        }
        return New-SuccessEnvelope -Data @{ terminated_count = $count }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-ProcessWait {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][double]$TimeoutS
    )
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc) {
            # Already exited -- report as exited rather than NOT_FOUND,
            # since "wait for a process that already finished" is a
            # normal, successful outcome for a caller.
            return New-SuccessEnvelope -Data @{ exited = $true; exit_code = $null }
        }
        $exited = $proc.WaitForExit([int]($TimeoutS * 1000))
        if (-not $exited) {
            return New-SuccessEnvelope -Data @{ exited = $false; exit_code = $null }
        }
        return New-SuccessEnvelope -Data @{ exited = $true; exit_code = $proc.ExitCode }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-ProcessQuery {
    <#
    .SYNOPSIS
        `tasklist` equivalent, but structured -- uses Get-CimInstance
        Win32_Process for CommandLine + SessionId, neither of which
        `tasklist` itself exposes (the same real API the compatibility
        backend's Issue #2 diagnostics use, now as this architecture's
        normal path rather than an added probe).
    #>
    param(
        [Parameter(Mandatory = $false)][string]$Name = $null,
        [Parameter(Mandatory = $false)][Nullable[int]]$ProcessId = $null
    )
    try {
        $filter = $null
        if ($ProcessId) {
            $filter = "ProcessId=$ProcessId"
        } elseif ($Name) {
            $bare = $Name
            if (-not $bare.ToLower().EndsWith('.exe')) { $bare = "$bare.exe" }
            $filter = "Name='$bare'"
        }

        $cimProcesses = if ($filter) {
            Get-CimInstance Win32_Process -Filter $filter
        } else {
            Get-CimInstance Win32_Process
        }

        $processes = @()
        foreach ($p in $cimProcesses) {
            $processes += @{
                pid          = [int]$p.ProcessId
                name         = $p.Name
                command_line = $(if ($p.CommandLine) { $p.CommandLine } else { '' })
                session_id   = [int]$p.SessionId
            }
        }
        return New-SuccessEnvelope -Data @{ processes = $processes }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

Export-ModuleMember -Function Invoke-ProcessStart, Invoke-ProcessTerminate, Invoke-ProcessWait, Invoke-ProcessQuery
