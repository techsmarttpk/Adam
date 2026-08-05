#requires -Version 5.1
<#
.SYNOPSIS
    SampleManager.psm1 -- implements docs/phase5-http-agent-api.md
    section 10 (/sample/*).

.DESCRIPTION
    Samples travel as base64 JSON (spec section 10's documented scaling
    limitation -- fine for this project's single-sample-per-session
    scope). SHA-256 is verified guest-side, via .NET's own
    System.Security.Cryptography.SHA256, against the decoded bytes before
    anything is written to disk.
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

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($Bytes)
        return -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    } finally {
        $sha256.Dispose()
    }
}

function Invoke-SampleUpload {
    param(
        [Parameter(Mandatory = $true)][string]$SampleDir,
        [Parameter(Mandatory = $true)][string]$Filename,
        [Parameter(Mandatory = $true)][string]$Sha256,
        [Parameter(Mandatory = $true)][string]$ContentBase64
    )
    try {
        $bytes = [Convert]::FromBase64String($ContentBase64)
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InvalidArgument -ErrorMessage "content_base64 is not valid base64: $($_.Exception.Message)"
    }

    $actualHash = Get-Sha256Hex -Bytes $bytes
    $verified = $actualHash.ToLower() -eq $Sha256.ToLower()
    if (-not $verified) {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InvalidArgument -ErrorMessage "sha256 mismatch: expected $Sha256, computed $actualHash"
    }

    try {
        if (-not (Test-Path -LiteralPath $SampleDir)) {
            New-Item -ItemType Directory -Path $SampleDir -Force | Out-Null
        }
        $stagedPath = Join-Path $SampleDir $Filename
        [System.IO.File]::WriteAllBytes($stagedPath, $bytes)
        Write-AgentLog -Message "sample staged: $stagedPath ($($bytes.Length) bytes, sha256=$actualHash)"
        return New-SuccessEnvelope -Data @{ staged_path = $stagedPath; sha256_verified = $true }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-SampleStage {
    <# Moves/copies an already-uploaded sample to its final execution target path (e.g. after a rename). #>
    param(
        [Parameter(Mandatory = $true)][string]$StagedPath,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )
    try {
        if (-not (Test-Path -LiteralPath $StagedPath)) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.NotFound -ErrorMessage "staged sample not found: $StagedPath"
        }
        $targetDir = Split-Path -Path $TargetPath -Parent
        if ($targetDir -and -not (Test-Path -LiteralPath $targetDir)) {
            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        }
        Copy-Item -LiteralPath $StagedPath -Destination $TargetPath -Force
        return New-SuccessEnvelope -Data @{ target_path = $TargetPath }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

Export-ModuleMember -Function Invoke-SampleUpload, Invoke-SampleStage, Get-Sha256Hex
