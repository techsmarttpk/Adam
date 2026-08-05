#requires -Version 5.1
<#
.SYNOPSIS
    ArtifactManager.psm1 -- implements docs/phase5-http-agent-api.md
    section 11 (/artifact/*).

.DESCRIPTION
    /artifact/package uses System.IO.Compression.ZipFile directly -- no
    external zip.exe / Compress-Archive subprocess, per "no cmd.exe
    unless absolutely unavoidable": the guest's own .NET runtime already
    provides zip creation natively.
#>

Set-StrictMode -Version Latest
# NOTE: no -Force here. Common.psm1 is already imported once, directly,
# by adam_agent.ps1 (the top-level entrypoint) before any manager module
# is loaded. Re-importing it with -Force from inside a nested module
# scope removes the ALREADY-loaded instance (wherever its exports were
# originally added -- the top-level script's own scope) and re-adds it
# only into THIS module's private nested scope, invisible to
# adam_agent.ps1 itself -- a real, documented PowerShell behavior
# (PowerShell/PowerShell#7367) that was the actual root cause of a real
# guest-side startup crash ("Write-AgentLog is not recognized"). Plain
# Import-Module (no -Force) is idempotent: if Common.psm1's already
# loaded, it's a no-op, so the original top-level-scope copy survives.
Import-Module (Join-Path $PSScriptRoot 'Common.psm1')
# SampleManager.psm1 is no longer imported here -- this module used to
# call its Get-Sha256Hex, but Get-ArtifactMetadata now uses its own
# streaming Get-Sha256HexFromFile below instead (see that function's own
# docstring). Re-adding this import would only reintroduce the same
# -Force nested-reimport risk against SampleManager's own top-level
# exports for no actual benefit.

Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue

function Get-ArtifactKind {
    param([string]$Path)
    $ext = [System.IO.Path]::GetExtension($Path).ToLower()
    switch ($ext) {
        '.evtx' { return 'sysmon_evtx' }
        '.csv'  { return 'procmon_csv' }
        '.json' { return 'network_ek_json' }
        '.pcapng' { return 'network_pcap' }
        '.pml'  { return 'procmon_pml' }
        default { return 'other' }
    }
}

function Invoke-ArtifactList {
    param([Parameter(Mandatory = $true)][string]$CaptureDir, [Parameter(Mandatory = $true)][string]$SessionId)
    try {
        if (-not (Test-Path -LiteralPath $CaptureDir)) {
            return New-SuccessEnvelope -Data @{ artifacts = @() }
        }
        $artifacts = @()
        foreach ($item in (Get-ChildItem -LiteralPath $CaptureDir -Filter "$SessionId*" -File -ErrorAction SilentlyContinue)) {
            $artifacts += @{
                name       = $item.Name
                path       = $item.FullName
                size_bytes = $item.Length
                kind       = Get-ArtifactKind -Path $item.FullName
            }
        }
        return New-SuccessEnvelope -Data @{ artifacts = $artifacts }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-ArtifactPackage {
    param(
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [Parameter(Mandatory = $true)][string]$OutputZip
    )
    try {
        if (Test-Path -LiteralPath $OutputZip) {
            Remove-Item -LiteralPath $OutputZip -Force
        }
        $zip = [System.IO.Compression.ZipFile]::Open($OutputZip, [System.IO.Compression.ZipArchiveMode]::Create)
        $entryCount = 0
        try {
            foreach ($path in $Paths) {
                if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                    continue
                }
                $entryName = [System.IO.Path]::GetFileName($path)
                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $path, $entryName) | Out-Null
                $entryCount++
            }
        } finally {
            $zip.Dispose()
        }
        return New-SuccessEnvelope -Data @{ zip_path = $OutputZip; entry_count = $entryCount }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Get-Sha256HexFromFile {
    <#
    Streaming SHA-256 over a FileStream, not a full ReadAllBytes -- a
    multi-hundred-MB pcap or EVTX artifact (this project's expected
    telemetry sizes, see docs/phase5-migration-guide.md's sample-upload
    scaling note for the same class of concern on the upload side) should
    never need to be fully buffered in the guest agent's own process
    memory just to compute a hash.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $hashBytes = $sha256.ComputeHash($stream)
        return -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    } finally {
        $stream.Dispose()
        $sha256.Dispose()
    }
}

function Get-ArtifactMetadata {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.NotFound -ErrorMessage "artifact not found: $Path"
        }
        $item = Get-Item -LiteralPath $Path
        $sha256 = Get-Sha256HexFromFile -Path $Path
        return New-SuccessEnvelope -Data @{
            size_bytes   = $item.Length
            sha256       = $sha256
            modified_utc = $item.LastWriteTimeUtc.ToString('o')
        }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

Export-ModuleMember -Function Invoke-ArtifactList, Invoke-ArtifactPackage, Get-ArtifactMetadata
