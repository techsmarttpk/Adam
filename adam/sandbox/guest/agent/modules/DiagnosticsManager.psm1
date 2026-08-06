#requires -Version 5.1
<#
.SYNOPSIS
    DiagnosticsManager.psm1 -- implements docs/phase5-http-agent-api.md
    section 9 (/diagnostics/*).

.DESCRIPTION
    /diagnostics/token is the single biggest upgrade this architecture
    provides over the compatibility backend's Bug #4 / Issue #2
    diagnostics (agent.py's `_whoami_diagnostics()`, which runs
    `whoami /groups` + `whoami /priv` and treats their TEXT OUTPUT as
    evidence). This module instead P/Invokes the real Win32 token APIs
    (OpenProcessToken / GetTokenInformation with TokenGroups,
    TokenPrivileges, TokenIntegrityLevel) via a small C# helper type
    loaded with Add-Type, returning structured booleans/strings instead
    of a block of text a human has to read. This is the standard,
    well-established P/Invoke recipe for token introspection -- the
    struct layouts (LUID, LUID_AND_ATTRIBUTES, SID_AND_ATTRIBUTES,
    TOKEN_PRIVILEGES/TOKEN_GROUPS' "count + trailing array" shape) are
    fixed, documented Win32 ABI, not guesswork.

    RISK DISCLOSURE: this file could not be executed against a real
    Windows guest from the sandbox this was written in (no Windows/.NET
    runtime available there -- see the final delivery report). It is the
    highest-risk file in this deliverable structurally (P/Invoke
    marshaling is inherently less forgiving than the plain .NET cmdlets
    the other manager modules use) -- every function therefore wraps its
    P/Invoke call in try/catch and falls back to parsing `whoami
    /groups`/`whoami /priv` (the same mechanism the compatibility backend
    already uses and has been verified against a real VM) if the P/Invoke
    path throws for any reason, so a bug here degrades to a known-working
    behavior rather than breaking the endpoint outright. Prioritize
    validating this file first on a real VM.
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

# Load the P/Invoke helper type once per process.
if (-not ('Adam.TokenInterop' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Adam {
    public static class TokenInterop {
        public const uint TOKEN_QUERY = 0x0008;
        public const int TokenGroups = 2;
        public const int TokenPrivileges = 3;
        public const int TokenIntegrityLevel = 25;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeNameW(string lpSystemName, ref LUID lpLuid, System.Text.StringBuilder lpName, ref int cchName);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ConvertSidToStringSidW(IntPtr pSID, out IntPtr ptrSid);
    }
}
'@ -ErrorAction Stop
}

function Get-TokenPrivilegesNative {
    <# Returns a list of @{ name; state } or $null if the P/Invoke path fails for any reason. #>
    $tokenHandle = [IntPtr]::Zero
    try {
        if (-not [Adam.TokenInterop]::OpenProcessToken([Adam.TokenInterop]::GetCurrentProcess(), [Adam.TokenInterop]::TOKEN_QUERY, [ref]$tokenHandle)) {
            return $null
        }

        $returnLength = 0
        [Adam.TokenInterop]::GetTokenInformation($tokenHandle, [Adam.TokenInterop]::TokenPrivileges, [IntPtr]::Zero, 0, [ref]$returnLength) | Out-Null
        if ($returnLength -le 0) { return $null }

        $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($returnLength)
        try {
            $ok = [Adam.TokenInterop]::GetTokenInformation($tokenHandle, [Adam.TokenInterop]::TokenPrivileges, $buffer, $returnLength, [ref]$returnLength)
            if (-not $ok) { return $null }

            $privilegeCount = [Runtime.InteropServices.Marshal]::ReadInt32($buffer)
            $luidAttrSize = [Runtime.InteropServices.Marshal]::SizeOf([type][Adam.TokenInterop+LUID_AND_ATTRIBUTES])
            $arrayStart = [IntPtr]::Add($buffer, 4)  # TOKEN_PRIVILEGES.PrivilegeCount is a DWORD (4 bytes)

            $results = @()
            for ($i = 0; $i -lt $privilegeCount; $i++) {
                $entryPtr = [IntPtr]::Add($arrayStart, $i * $luidAttrSize)
                $entry = [Runtime.InteropServices.Marshal]::PtrToStructure($entryPtr, [type][Adam.TokenInterop+LUID_AND_ATTRIBUTES])

                $nameLen = 256
                $sb = New-Object System.Text.StringBuilder $nameLen
                $luid = $entry.Luid
                if (-not [Adam.TokenInterop]::LookupPrivilegeNameW($null, [ref]$luid, $sb, [ref]$nameLen)) {
                    continue
                }

                # SE_PRIVILEGE_ENABLED = 0x2, SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1
                $state = if (($entry.Attributes -band 0x2) -ne 0) { 'Enabled' } else { 'Disabled' }
                $results += @{ name = $sb.ToString(); state = $state }
            }
            return $results
        } finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        }
    } catch {
        return $null
    } finally {
        if ($tokenHandle -ne [IntPtr]::Zero) { [Adam.TokenInterop]::CloseHandle($tokenHandle) | Out-Null }
    }
}

function Get-TokenIntegrityLevelNative {
    <# Returns a friendly integrity-level string, or $null on any failure. #>
    $tokenHandle = [IntPtr]::Zero
    try {
        if (-not [Adam.TokenInterop]::OpenProcessToken([Adam.TokenInterop]::GetCurrentProcess(), [Adam.TokenInterop]::TOKEN_QUERY, [ref]$tokenHandle)) {
            return $null
        }
        $returnLength = 0
        [Adam.TokenInterop]::GetTokenInformation($tokenHandle, [Adam.TokenInterop]::TokenIntegrityLevel, [IntPtr]::Zero, 0, [ref]$returnLength) | Out-Null
        if ($returnLength -le 0) { return $null }

        $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($returnLength)
        try {
            $ok = [Adam.TokenInterop]::GetTokenInformation($tokenHandle, [Adam.TokenInterop]::TokenIntegrityLevel, $buffer, $returnLength, [ref]$returnLength)
            if (-not $ok) { return $null }

            # TOKEN_MANDATORY_LABEL is a single SID_AND_ATTRIBUTES; its Sid
            # field is the first pointer-sized value in the buffer.
            $sidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($buffer)
            $stringSidPtr = [IntPtr]::Zero
            if (-not [Adam.TokenInterop]::ConvertSidToStringSidW($sidPtr, [ref]$stringSidPtr)) {
                return $null
            }
            $sidString = [Runtime.InteropServices.Marshal]::PtrToStringAuto($stringSidPtr)

            # Well-known mandatory-label RIDs (Windows' own fixed values).
            switch -Regex ($sidString) {
                'S-1-16-0$'     { return 'Untrusted' }
                'S-1-16-4096$'  { return 'Low' }
                'S-1-16-8192$'  { return 'Medium' }
                'S-1-16-8448$'  { return 'MediumPlus' }
                'S-1-16-12288$' { return 'High' }
                'S-1-16-16384$' { return 'System' }
                default         { return $sidString }
            }
        } finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        }
    } catch {
        return $null
    } finally {
        if ($tokenHandle -ne [IntPtr]::Zero) { [Adam.TokenInterop]::CloseHandle($tokenHandle) | Out-Null }
    }
}

function Get-TokenGroupsFallbackText {
    <#
    Group enumeration deliberately always uses whoami /groups text-parsing
    (the same mechanism agent.py's compatibility backend already uses),
    not a native TOKEN_GROUPS P/Invoke path -- unlike privileges/integrity
    level above, resolving TOKEN_GROUPS' SID array to display names would
    need a second P/Invoke chain (LookupAccountSid) with its own variable-
    length-buffer marshaling, doubling this file's untested surface area
    for one field. Attributes (e.g. "deny-only") are therefore reported
    as the raw whoami line text rather than a structured flag -- a
    disclosed simplification, not an oversight; see this module's
    docstring RISK DISCLOSURE.
    #>
    try {
        $whoami = Join-Path $env:WINDIR 'System32\whoami.exe'
        $result = Invoke-NativeProcess -FilePath $whoami -ArgumentList @('/groups') -TimeoutMs 15000
        $groups = @()
        foreach ($line in ($result.StdOut -split "`r?`n")) {
            if ($line -match '^\S') {
                $groups += @{ name = $line.Trim(); attributes = @('parsed_from_whoami_text') }
            }
        }
        return $groups
    } catch {
        return @()
    }
}

function Get-DiagnosticsToken {
    try {
        $privileges = Get-TokenPrivilegesNative
        $usedFallback = $false
        if ($null -eq $privileges) {
            $usedFallback = $true
            $whoami = Join-Path $env:WINDIR 'System32\whoami.exe'
            $privResult = Invoke-NativeProcess -FilePath $whoami -ArgumentList @('/priv') -TimeoutMs 15000
            $privileges = @()
            foreach ($line in ($privResult.StdOut -split "`r?`n")) {
                if ($line -match '^(Se\w+)\s+.*\s+(Enabled|Disabled)\s*$') {
                    $privileges += @{ name = $Matches[1]; state = $Matches[2] }
                }
            }
        }

        $integrityLevel = Get-TokenIntegrityLevelNative
        if ($null -eq $integrityLevel) {
            $usedFallback = $true
            $integrityLevel = 'Unknown'
        }

        $groups = Get-TokenGroupsFallbackText
        $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($usedFallback) {
            Write-AgentLog -Level WARN -Message 'diagnostics/token: native P/Invoke path failed for one or more fields -- used whoami text-parsing fallback'
        }

        return New-SuccessEnvelope -Data @{
            groups          = $groups
            privileges      = $privileges
            integrity_level = $integrityLevel
            is_elevated     = [bool]$isElevated
        }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Get-DiagnosticsServices {
    param([Parameter(Mandatory = $false)][string]$Name = $null)
    try {
        $services = if ($Name) { Get-Service -Name $Name -ErrorAction SilentlyContinue } else { Get-Service }
        $result = @()
        foreach ($svc in $services) {
            $result += @{
                name       = $svc.Name
                status     = $svc.Status.ToString()
                start_type = $svc.StartType.ToString()
            }
        }
        return New-SuccessEnvelope -Data @{ services = $result }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

function Get-DiagnosticsDrivers {
    param([Parameter(Mandatory = $false)][string]$Name = $null)
    try {
        $drivers = Get-CimInstance Win32_SystemDriver
        if ($Name) {
            $drivers = $drivers | Where-Object { $_.Name -like "*$Name*" }
        }
        $result = @()
        foreach ($drv in $drivers) {
            $result += @{ name = $drv.Name; state = $drv.State }
        }
        return New-SuccessEnvelope -Data @{ drivers = $result }
    } catch {
        return New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
    }
}

Export-ModuleMember -Function Get-DiagnosticsToken, Get-DiagnosticsServices, Get-DiagnosticsDrivers
