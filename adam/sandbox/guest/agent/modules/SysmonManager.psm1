#requires -Version 5.1
<#
.SYNOPSIS
    SysmonManager.psm1 -- implements docs/phase5-http-agent-api.md
    section 8 (/sysmon/*).

.DESCRIPTION
    /sysmon/export tries `wevtutil.exe epl` first, then falls back to a
    raw copy of the channel's own backing .evtx file on ACCESS_DENIED --
    the native reimplementation of agent.py's
    `_export_sysmon_raw_copy_fallback()` (Issue #3), reporting which
    mechanism actually worked via the `mechanism` field so the host side
    never has to guess.
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

function Invoke-SysmonExport {
    param(
        [Parameter(Mandatory = $true)][string]$Channel,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )
    try {
        $wevtutil = Join-Path $env:WINDIR 'System32\wevtutil.exe'
        $result = Invoke-NativeProcess -FilePath $wevtutil -ArgumentList @('epl', $Channel, $OutputPath) -TimeoutMs 15000

        if (-not $result.TimedOut -and $result.ExitCode -eq 0 -and (Test-Path -LiteralPath $OutputPath)) {
            Write-AgentLog -Message "sysmon export via wevtutil epl succeeded: $OutputPath"
            return New-SuccessEnvelope -Data @{ output_path = $OutputPath; mechanism = 'wevtutil' }
        }

        Write-AgentLog -Level WARN -Message "wevtutil epl failed (exit_code=$($result.ExitCode) stderr=$($result.StdErr)) -- trying raw-copy fallback"

        # Issue #3 fallback: copy the channel's own backing .evtx file
        # directly. Standard "Applications and Services Logs" naming
        # convention: forward slashes in the channel name become '%4' in
        # the file name (Microsoft's own Event Log architecture, not
        # Sysmon-specific).
        $rawSourcePath = Join-Path $env:WINDIR "System32\winevt\Logs\$($Channel -replace '/', '%4').evtx"
        if (-not (Test-Path -LiteralPath $rawSourcePath)) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.AccessDenied -ErrorMessage "wevtutil epl failed and raw log file not found at $rawSourcePath. wevtutil stderr: $($result.StdErr)"
        }
        try {
            Copy-Item -LiteralPath $rawSourcePath -Destination $OutputPath -Force
        } catch {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.AccessDenied -ErrorMessage "both wevtutil epl and a raw file copy were denied: $($_.Exception.Message)"
        }
        Write-AgentLog -Message "sysmon export via raw copy fallback succeeded: $rawSourcePath -> $OutputPath"
        return New-SuccessEnvelope -Data @{ output_path = $OutputPath; mechanism = 'raw_copy' }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Get-SysmonDiagnostics {
    param([Parameter(Mandatory = $true)][string]$Channel)
    try {
        $available = $true
        $eventCount = $null
        try {
            $log = Get-WinEvent -ListLog $Channel -ErrorAction Stop
            $eventCount = $log.RecordCount
        } catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
            $available = $false
        } catch {
            # Try wevtutil gl probe as fallback
            $wevtutil = Join-Path $env:WINDIR 'System32\wevtutil.exe'
            $gl = Invoke-NativeProcess -FilePath $wevtutil -ArgumentList @('gl', $Channel) -TimeoutMs 5000
            if (-not $gl.TimedOut -and $gl.ExitCode -eq 0 -and $gl.StdOut -match 'enabled:\s*true') {
                $available = $true
            } else {
                $available = $false
            }
        }
        return New-SuccessEnvelope -Data @{ channel_available = $available; event_count = $eventCount }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

Export-ModuleMember -Function Invoke-SysmonExport, Get-SysmonDiagnostics
