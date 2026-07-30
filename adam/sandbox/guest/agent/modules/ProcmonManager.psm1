#requires -Version 5.1
<#
.SYNOPSIS
    ProcmonManager.psm1 -- implements docs/phase5-http-agent-api.md
    section 6 (/procmon/*).

.DESCRIPTION
    Every Procmon64.exe invocation includes /AcceptEula unconditionally
    (the native reimplementation of agent.py's `_procmon_args()` helper
    and its Bug #3 fix -- same reasoning, independent implementation
    since PowerShell and Python share no runtime).
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

# session_id -> PID, so /procmon/stop knows which process to signal
# without relying on a single global "the" Procmon instance -- mirrors
# agent.py's own per-session PML path naming.
$Script:RunningCaptures = @{}

function Invoke-ProcmonStart {
    param(
        [Parameter(Mandatory = $true)][string]$ProcmonPath,
        [Parameter(Mandatory = $true)][string]$SessionId,
        [Parameter(Mandatory = $true)][string]$BackingFile
    )
    if (-not (Test-Path -LiteralPath $ProcmonPath)) {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.ToolUnavailable -ErrorMessage "Procmon not found at $ProcmonPath"
    }
    try {
        $args = @('/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', $BackingFile)
        $result = Invoke-NativeProcess -FilePath $ProcmonPath -ArgumentList $args -TimeoutMs $null
        if ($null -eq $result.Pid) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $result.StdErr
        }
        $Script:RunningCaptures[$SessionId] = $result.Pid
        Write-AgentLog -Message "session=$SessionId Procmon started pid=$($result.Pid) backing_file=$BackingFile"
        return New-SuccessEnvelope -Data @{ pid = $result.Pid }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-ProcmonStop {
    param(
        [Parameter(Mandatory = $true)][string]$ProcmonPath,
        [Parameter(Mandatory = $true)][string]$SessionId
    )
    if (-not (Test-Path -LiteralPath $ProcmonPath)) {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.ToolUnavailable -ErrorMessage "Procmon not found at $ProcmonPath"
    }
    try {
        # /Terminate always carries /AcceptEula too -- see module docstring.
        $args = @('/AcceptEula', '/Terminate')
        $result = Invoke-NativeProcess -FilePath $ProcmonPath -ArgumentList $args -TimeoutMs 15000
        $Script:RunningCaptures.Remove($SessionId) | Out-Null
        if ($result.TimedOut) {
            Write-AgentLog -Level WARN -Message "session=$SessionId Procmon /Terminate timed out"
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.Timeout -ErrorMessage "/Terminate did not complete in time"
        }
        Write-AgentLog -Message "session=$SessionId Procmon /Terminate exit_code=$($result.ExitCode)"
        return New-SuccessEnvelope -Data @{ stopped = $true }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-ProcmonExport {
    param(
        [Parameter(Mandatory = $true)][string]$ProcmonPath,
        [Parameter(Mandatory = $true)][string]$PmlPath,
        [Parameter(Mandatory = $true)][string]$CsvPath
    )
    if (-not (Test-Path -LiteralPath $PmlPath)) {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.NotFound -ErrorMessage "backing file not found: $PmlPath"
    }
    try {
        $args = @('/AcceptEula', '/OpenLog', $PmlPath, '/SaveAs', $CsvPath, '/Quiet')
        $result = Invoke-NativeProcess -FilePath $ProcmonPath -ArgumentList $args -TimeoutMs 120000
        if ($result.TimedOut) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.Timeout -ErrorMessage "PML->CSV conversion did not complete in time"
        }
        if (-not (Test-Path -LiteralPath $CsvPath)) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage "conversion reported completion but $CsvPath does not exist"
        }
        return New-SuccessEnvelope -Data @{ csv_path = $CsvPath }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Get-ProcmonBackingFileStatus {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return New-SuccessEnvelope -Data @{ exists = $false; size_bytes = $null }
        }
        $item = Get-Item -LiteralPath $Path
        return New-SuccessEnvelope -Data @{ exists = $true; size_bytes = $item.Length }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

Export-ModuleMember -Function Invoke-ProcmonStart, Invoke-ProcmonStop, Invoke-ProcmonExport, Get-ProcmonBackingFileStatus
