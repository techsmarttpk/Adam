#requires -Version 5.1
<#
.SYNOPSIS
    NetworkManager.psm1 -- implements docs/phase5-http-agent-api.md
    section 7 (/network/*), the tshark-backed capture/convert manager.

.DESCRIPTION
    /network/convert is the native fix for Issue #1 (the compatibility
    backend's "'C:\Program' is not recognized" bug): tshark.exe is
    launched with ArgumentList = @('-r', $PcapPath, '-T', 'ek') and its
    StandardOutput stream is written directly to $EkJsonPath by
    Invoke-NativeProcess -RedirectStandardOutputTo -- no cmd.exe, no `>`,
    no argument ever needs manual quoting regardless of spaces in
    $TsharkPath, because FileName is never part of a parsed command-line
    string.
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

$Script:RunningCaptures = @{}

function Get-NetworkInterfaces {
    param([Parameter(Mandatory = $true)][string]$TsharkPath)
    if (-not (Test-Path -LiteralPath $TsharkPath)) {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.ToolUnavailable -ErrorMessage "tshark not found at $TsharkPath"
    }
    try {
        $result = Invoke-NativeProcess -FilePath $TsharkPath -ArgumentList @('-D') -TimeoutMs 15000
        if ($result.TimedOut) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.Timeout -ErrorMessage "tshark -D did not complete in time"
        }
        $interfaces = @()
        foreach ($line in ($result.StdOut -split "`r?`n")) {
            if ($line -match '^(\d+)\.\s+(.*)$') {
                $interfaces += @{ index = $Matches[1]; description = $Matches[2] }
            }
        }
        return New-SuccessEnvelope -Data @{ interfaces = $interfaces }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-NetworkStart {
    param(
        [Parameter(Mandatory = $true)][string]$TsharkPath,
        [Parameter(Mandatory = $true)][string]$SessionId,
        [Parameter(Mandatory = $true)][string]$Interface,
        [Parameter(Mandatory = $true)][string]$PcapPath
    )
    if (-not (Test-Path -LiteralPath $TsharkPath)) {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.ToolUnavailable -ErrorMessage "tshark not found at $TsharkPath"
    }
    try {
        $args = @('-i', $Interface, '-w', $PcapPath)
        $result = Invoke-NativeProcess -FilePath $TsharkPath -ArgumentList $args -TimeoutMs $null
        if ($null -eq $result.Pid) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $result.StdErr
        }
        $Script:RunningCaptures[$SessionId] = $result.Pid
        Write-AgentLog -Message "session=$SessionId tshark started pid=$($result.Pid) interface=$Interface pcap=$PcapPath"
        return New-SuccessEnvelope -Data @{ pid = $result.Pid }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-NetworkStop {
    param([Parameter(Mandatory = $true)][string]$SessionId)
    try {
        # tshark spawns a privileged dumpcap.exe helper that actually
        # performs the capture (agent.py's own docstring note, still
        # true here) -- both are stopped independently, best-effort.
        $stoppedAny = $false
        if ($Script:RunningCaptures.ContainsKey($SessionId)) {
            $tsharkPid = $Script:RunningCaptures[$SessionId]
            $proc = Get-Process -Id $tsharkPid -ErrorAction SilentlyContinue
            if ($proc) { $proc.Kill(); $stoppedAny = $true }
            $Script:RunningCaptures.Remove($SessionId) | Out-Null
        }
        foreach ($dumpcap in (Get-Process -Name 'dumpcap' -ErrorAction SilentlyContinue)) {
            try { $dumpcap.Kill(); $stoppedAny = $true } catch { }
        }
        return New-SuccessEnvelope -Data @{ stopped = $stoppedAny }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-NetworkConvert {
    param(
        [Parameter(Mandatory = $true)][string]$TsharkPath,
        [Parameter(Mandatory = $true)][string]$PcapPath,
        [Parameter(Mandatory = $true)][string]$EkJsonPath
    )
    if (-not (Test-Path -LiteralPath $TsharkPath)) {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.ToolUnavailable -ErrorMessage "tshark not found at $TsharkPath"
    }
    if (-not (Test-Path -LiteralPath $PcapPath)) {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.NotFound -ErrorMessage "capture file not found: $PcapPath"
    }
    try {
        # Issue #1 fix, native form: '-r', pcap, '-T', 'ek' as their own
        # ArgumentList entries; stdout streamed straight to $EkJsonPath.
        # No cmd.exe, no '>' operator, nothing to mis-quote.
        $args = @('-r', $PcapPath, '-T', 'ek')
        $result = Invoke-NativeProcess -FilePath $TsharkPath -ArgumentList $args -TimeoutMs 60000 -RedirectStandardOutputTo $EkJsonPath
        if ($result.TimedOut) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.Timeout -ErrorMessage "EK JSON conversion did not complete in time"
        }
        if (-not (Test-Path -LiteralPath $EkJsonPath)) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage "conversion reported completion but $EkJsonPath does not exist"
        }
        return New-SuccessEnvelope -Data @{ ek_json_path = $EkJsonPath }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

Export-ModuleMember -Function Get-NetworkInterfaces, Invoke-NetworkStart, Invoke-NetworkStop, Invoke-NetworkConvert
