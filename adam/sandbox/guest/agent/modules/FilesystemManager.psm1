#requires -Version 5.1
<#
.SYNOPSIS
    FilesystemManager.psm1 -- implements docs/phase5-http-agent-api.md
    section 4 (/filesystem/*) plus /filesystem/read (section 12.1).

.DESCRIPTION
    Every operation uses .NET's System.IO APIs (Directory/File/FileInfo)
    directly -- no `dir`, `copy`, `del`, `if exist` shelled out to
    cmd.exe. This is the structural fix for Bug #1's entire class of
    quoting problems in the compatibility backend: there is no command
    line here to mis-quote, because there is no shell in the path at all.
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

function Invoke-FilesystemMkdir {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $alreadyExisted = Test-Path -LiteralPath $Path
        if (-not $alreadyExisted) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
        return New-SuccessEnvelope -Data @{ created = (-not $alreadyExisted); already_existed = $alreadyExisted }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-FilesystemExists {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $exists = Test-Path -LiteralPath $Path
        if (-not $exists) {
            return New-SuccessEnvelope -Data @{ exists = $false; is_directory = $false; size_bytes = $null }
        }
        $item = Get-Item -LiteralPath $Path
        $isDir = $item.PSIsContainer
        $size = if ($isDir) { $null } else { $item.Length }
        return New-SuccessEnvelope -Data @{ exists = $true; is_directory = $isDir; size_bytes = $size }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-FilesystemCopy {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $false)][bool]$Overwrite = $false
    )
    try {
        if (-not (Test-Path -LiteralPath $Source)) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.NotFound -ErrorMessage "source not found: $Source"
        }
        if ((Test-Path -LiteralPath $Destination) -and -not $Overwrite) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.AlreadyExists -ErrorMessage "destination exists: $Destination"
        }
        Copy-Item -LiteralPath $Source -Destination $Destination -Force:$Overwrite
        return New-SuccessEnvelope -Data @{ copied = $true }
    } catch [System.UnauthorizedAccessException] {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.AccessDenied -ErrorMessage $_.Exception.Message
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-FilesystemMove {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $false)][bool]$Overwrite = $false
    )
    try {
        if (-not (Test-Path -LiteralPath $Source)) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.NotFound -ErrorMessage "source not found: $Source"
        }
        if ((Test-Path -LiteralPath $Destination)) {
            if (-not $Overwrite) {
                return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.AlreadyExists -ErrorMessage "destination exists: $Destination"
            }
            Remove-Item -LiteralPath $Destination -Force -Recurse
        }
        Move-Item -LiteralPath $Source -Destination $Destination -Force
        return New-SuccessEnvelope -Data @{ moved = $true }
    } catch [System.UnauthorizedAccessException] {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.AccessDenied -ErrorMessage $_.Exception.Message
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-FilesystemDelete {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][bool]$Recursive = $false
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            # Deleting something already absent is treated as success --
            # matches agent.py's own "cleanup failure is logged, never
            # raised" idempotency philosophy for the compatibility backend.
            return New-SuccessEnvelope -Data @{ deleted = $false }
        }
        Remove-Item -LiteralPath $Path -Force -Recurse:$Recursive
        return New-SuccessEnvelope -Data @{ deleted = $true }
    } catch [System.UnauthorizedAccessException] {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.AccessDenied -ErrorMessage $_.Exception.Message
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Invoke-FilesystemList {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.NotFound -ErrorMessage "path not found: $Path"
        }
        $entries = @()
        foreach ($item in Get-ChildItem -LiteralPath $Path -Force) {
            $entries += @{
                name          = $item.Name
                is_directory  = $item.PSIsContainer
                size_bytes    = if ($item.PSIsContainer) { 0 } else { $item.Length }
                modified_utc  = $item.LastWriteTimeUtc.ToString('o')
            }
        }
        return New-SuccessEnvelope -Data @{ entries = $entries }
    } catch [System.UnauthorizedAccessException] {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.AccessDenied -ErrorMessage $_.Exception.Message
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Get-FilesystemReadBytes {
    <#
    .SYNOPSIS
        Backing implementation for GET /filesystem/read (API spec
        12.1) -- returns raw bytes and a boolean, NOT an envelope; the
        HTTP-status/X-Error-Code handling is adam_agent.ps1's own
        responsibility for this one endpoint, per the spec's documented
        exception.
    .OUTPUTS
        Hashtable: @{ Success=<bool>; ErrorCode=<string|$null>; Bytes=<byte[]|$null> }
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return @{ Success = $false; ErrorCode = $Script:ErrorCodes.NotFound; Bytes = $null }
        }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        return @{ Success = $true; ErrorCode = $null; Bytes = $bytes }
    } catch [System.UnauthorizedAccessException] {
        return @{ Success = $false; ErrorCode = $Script:ErrorCodes.AccessDenied; Bytes = $null }
    } catch {
        return @{ Success = $false; ErrorCode = $Script:ErrorCodes.InternalError; Bytes = $null }
    }
}

Export-ModuleMember -Function Invoke-FilesystemMkdir, Invoke-FilesystemExists, Invoke-FilesystemCopy, Invoke-FilesystemMove, Invoke-FilesystemDelete, Invoke-FilesystemList, Get-FilesystemReadBytes
