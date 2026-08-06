<#
.SYNOPSIS
    install.ps1 -- guest-side setup for adam_agent.ps1: idempotent,
    prerequisite-checked, and self-verifying.

.DESCRIPTION
    Makes adam_agent.ps1 start automatically and stay running, by:
      1. Copying adam_agent.ps1 + modules/ into $InstallDir (skipped if
         already running from that exact directory -- see "source ==
         destination" handling below).
      2. Writing (or, on re-run, merging new keys into) agent.config.json.
      3. Reserving a URL ACL (`netsh http add urlacl`) so HttpListener can
         bind $Port.
      4. Opening a Windows Firewall inbound rule for $Port.
      5. Registering + starting a Scheduled Task (as SYSTEM, -RunLevel
         Highest, AtStartup) so the agent survives reboots and snapshot
         restores without a human present -- SYSTEM also happens to carry
         SeLoadDriverPrivilege genuinely active, which is this
         architecture's implicit fix for the GuestControl-era filtered-
         token Procmon/Sysmon problem documented in agent.py.

    Every step above is written to be safe to run more than once:
      - Re-running from the SAME directory it already installed to does
        not try to copy files onto themselves.
      - Re-running does not fail on an already-reserved URL ACL, an
        already-present firewall rule, or an already-registered scheduled
        task -- each is detected and either left alone or updated in
        place.
      - An existing agent.config.json is never clobbered; only missing
        keys (e.g. from an older install) are merged in.

    Before doing any of the above, Test-Prerequisites checks PowerShell
    version, Administrator rights, that this is actually Windows, and
    that System.Net.HttpListener can be instantiated -- and fails fast
    with a specific, actionable message per failed check, rather than
    relying on PowerShell's own generic #requires error text.

    After installation, Test-Deployment re-checks the scheduled task
    exists and is Running, the config file exists, every .psm1 module
    imports without error, and GET /health actually responds with
    {"success":true,"data":{"status":"ok"}} -- printing a clear pass/fail
    line per check and exiting non-zero with troubleshooting guidance if
    anything failed, instead of the previous revision's unverified "should
    be reachable shortly" message.

    Per this project's Sysmon-log-freshness / guest-workspace-layout
    precedent (agent.py's own module docstring), whatever this script
    does must be baked into the VM's `clean` snapshot -- run this once,
    verify it passes, then take (or re-take) the snapshot the sandbox
    controller restores to before every session.

.PARAMETER InstallDir
    Where the agent should live. Default C:\ADAM\agent. May be run from
    inside this same directory (e.g. re-running install.ps1 in place to
    pick up a config merge or re-verify) or from a staging location such
    as Downloads\agent -- both are handled correctly.

.PARAMETER Port
    TCP port the agent's HttpListener binds. Default 8765.

.PARAMETER SkipVerification
    Skips the post-install Test-Deployment pass. Useful only for staged
    provisioning where networking/firewall isn't up yet and verification
    is expected to be run separately afterward; do not use this for a
    deployment you intend to trust without ever verifying it.

.PARAMETER Uninstall
    Reverses this script's guest-side changes: stops + unregisters the
    scheduled task, removes the firewall rule, removes the URL ACL
    reservation. Does NOT delete $InstallDir or agent.config.json (those
    may hold configuration or logs worth keeping) -- pass -RemoveFiles to
    also delete $InstallDir itself.

.PARAMETER RemoveFiles
    Only meaningful with -Uninstall. Also deletes $InstallDir (including
    agent.config.json and modules/) after reversing the scheduled
    task/firewall/urlacl changes.

.NOTES
    NOT EXECUTED against a real Windows guest as part of this delivery --
    see adam_agent.ps1's own NOTES section for the same disclosure. Every
    API used here (netsh, Get/New/Remove-NetFirewallRule,
    Get/Register/Unregister/Start-ScheduledTask, Get-CimInstance,
    System.Net.HttpListener, Invoke-RestMethod) is a well-documented
    PowerShell 5.1 / Windows 10 built-in; this should be run and its
    Test-Deployment output inspected on a real guest before being trusted
    in production, per docs/phase5-migration-guide.md's "Remaining Phase
    5 gaps".
#>

param(
    [string]$InstallDir = 'C:\ADAM\agent',
    [int]$Port = 8765,
    [switch]$SkipVerification,
    [switch]$Uninstall,
    [switch]$RemoveFiles
)

$ErrorActionPreference = 'Stop'
$Script:TaskName = 'ADAM Guest Agent'
$Script:RuleName = 'ADAM Guest Agent'

# NOTE: these four print helpers use Write-Host, not Write-Output,
# deliberately. Write-Output puts its argument on the success/pipeline
# stream, which means a call to one of these from INSIDE a function (e.g.
# Test-Prerequisites' Write-Ok calls for each passing check) leaks that
# string into the function's own return value alongside whatever it
# explicitly returns -- PowerShell aggregates all uncaptured pipeline
# output as a function's result, not just the value after `return`. That
# was a real, shipped bug here: every Write-Ok string emitted inside
# Test-Prerequisites ended up appended to $failures in the caller, so
# $prereqFailures.Count was > 0 (one entry per PASSING check) even when
# every prerequisite check succeeded, and the script exited via the
# failure branch printing those same "[OK] ..." lines as if they were
# failures. Write-Host writes straight to the console host and never
# touches the pipeline, so these are purely human-readable status lines
# and can never again contaminate a function's real return value.
function Write-Step { param([string]$Message) Write-Host "`n==> $Message" }
function Write-Ok   { param([string]$Message) Write-Host "    [OK]   $Message" }
function Write-Bad  { param([string]$Message) Write-Host "    [FAIL] $Message" }
function Write-Info { param([string]$Message) Write-Host "    $Message" }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

function Test-Prerequisites {
    <#
    Returns an array of failure strings (empty = all prerequisites met).
    Deliberately does NOT rely on #requires -Version / #requires
    -RunAsAdministrator, because those abort with PowerShell's own generic
    error text before a single line of this script runs -- this function
    exists specifically to give an actionable diagnostic per failed check
    instead.
    #>
    $failures = @()

    if ($PSVersionTable.PSVersion -lt [Version]'5.1') {
        $failures += "PowerShell 5.1+ required -- found $($PSVersionTable.PSVersion). " +
            "This agent targets PowerShell 5.1 / .NET Framework specifically (ARCHITECTURE.md constraint C4); " +
            "install/enable Windows PowerShell 5.1 (already built into Windows 10) and re-run from that host, not PowerShell Core (pwsh)."
    } else {
        Write-Ok "PowerShell version $($PSVersionTable.PSVersion)"
    }

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $failures += "Administrator privileges required -- right-click PowerShell and choose 'Run as Administrator', then re-run this script. " +
            "(URL ACL reservation, firewall rule creation, and Scheduled Task registration as SYSTEM all require elevation.)"
    } else {
        Write-Ok 'Running elevated (Administrator)'
    }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($null -eq $os) {
        $failures += 'Could not query OS version via Get-CimInstance Win32_OperatingSystem -- is this actually a Windows host, and is the WMI service running?'
    } elseif ($os.Caption -notmatch 'Windows') {
        $failures += "This does not look like Windows (Win32_OperatingSystem.Caption='$($os.Caption)') -- the ADAM guest agent is Windows-only."
    } else {
        Write-Ok "OS: $($os.Caption) (build $($os.BuildNumber))"
    }

    try {
        $probeListener = New-Object System.Net.HttpListener
        $probeListener.Close()
        Write-Ok 'System.Net.HttpListener is available'
    } catch {
        $failures += "System.Net.HttpListener could not be instantiated: $($_.Exception.Message). " +
            'This .NET Framework class ships with every supported Windows 10 build; if this fails, .NET Framework itself may be damaged or missing -- run "sfc /scannow" or repair .NET Framework via Windows Features.'
    }

    return $failures
}

# ---------------------------------------------------------------------------
# Uninstall path
# ---------------------------------------------------------------------------

function Invoke-Uninstall {
    Write-Step "Uninstalling ADAM guest agent (InstallDir=$InstallDir, Port=$Port)"

    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq 'Running') {
            Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        }
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false
        Write-Ok "Removed scheduled task '$Script:TaskName'"
    } else {
        Write-Info "Scheduled task '$Script:TaskName' was not present"
    }

    $rule = Get-NetFirewallRule -DisplayName $Script:RuleName -ErrorAction SilentlyContinue
    if ($rule) {
        Remove-NetFirewallRule -DisplayName $Script:RuleName
        Write-Ok "Removed firewall rule '$Script:RuleName'"
    } else {
        Write-Info "Firewall rule '$Script:RuleName' was not present"
    }

    $urlAclTarget = "http://+:$Port/"
    if (Test-UrlAclReserved -Url $urlAclTarget) {
        & netsh http delete urlacl url="$urlAclTarget" | Out-Null
        Write-Ok "Removed URL ACL for $urlAclTarget"
    } else {
        Write-Info "URL ACL for $urlAclTarget was not present"
    }

    if ($RemoveFiles) {
        if (Test-Path -LiteralPath $InstallDir) {
            Remove-Item -LiteralPath $InstallDir -Recurse -Force
            Write-Ok "Deleted $InstallDir"
        } else {
            Write-Info "$InstallDir did not exist"
        }
    } else {
        Write-Info "Leaving $InstallDir in place (pass -RemoveFiles to also delete it)"
    }

    Write-Output "`nUninstall complete. Re-capture the VM's 'clean' snapshot to persist this rollback."
}

# ---------------------------------------------------------------------------
# URL ACL helpers (idempotency)
# ---------------------------------------------------------------------------

function Test-UrlAclReserved {
    <#
    `netsh http show urlacl url=<url>` exits 0 even when the reservation
    does not exist (it just prints "URL reservation for ... does not
    exist" to stdout) -- so existence is determined by text-matching the
    URL in the output, not by exit code.
    #>
    param([string]$Url)
    $output = (& netsh http show urlacl url="$Url" 2>&1 | Out-String)
    return $output -match [regex]::Escape($Url)
}

# ---------------------------------------------------------------------------
# Post-install verification
# ---------------------------------------------------------------------------

function Test-Deployment {
    param(
        [string]$InstallDir,
        [int]$Port,
        [string]$TaskName
    )

    $result = [ordered]@{
        ScheduledTaskExists    = $false
        ScheduledTaskRunning   = $false
        ConfigFileExists       = $false
        ModulesImportCleanly   = $false
        ModuleErrors           = @()
        HealthEndpointResponds = $false
        HealthEndpointDetail   = ''
    }

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $result.ScheduledTaskExists = [bool]$task

    if ($task) {
        for ($i = 0; $i -lt 10; $i++) {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            if ($task -and $task.State -eq 'Running') {
                $result.ScheduledTaskRunning = $true
                break
            }
            Start-Sleep -Seconds 1
        }
    }

    $result.ConfigFileExists = Test-Path -LiteralPath (Join-Path $InstallDir 'agent.config.json')

    $modulesOk = $true
    $moduleErrors = @()
    $modulesPath = Join-Path $InstallDir 'modules'
    $moduleFiles = Get-ChildItem -Path $modulesPath -Filter '*.psm1' -ErrorAction SilentlyContinue
    if (-not $moduleFiles) {
        $modulesOk = $false
        $moduleErrors += "no .psm1 files found under $modulesPath"
    }
    foreach ($psm1 in $moduleFiles) {
        try {
            Import-Module $psm1.FullName -Force -ErrorAction Stop
        } catch {
            $modulesOk = $false
            $moduleErrors += "$($psm1.Name): $($_.Exception.Message)"
        }
    }
    $result.ModulesImportCleanly = $modulesOk
    $result.ModuleErrors = $moduleErrors

    $healthOk = $false
    $healthDetail = ''
    for ($i = 0; $i -lt 10; $i++) {
        try {
            $response = Invoke-RestMethod -Uri "http://localhost:$Port/health" -Method Get -TimeoutSec 3
            if ($response.success -eq $true -and $response.data.status -eq 'ok') {
                $healthOk = $true
                break
            }
            $healthDetail = "responded but success/status unexpected: $($response | ConvertTo-Json -Compress)"
        } catch {
            $healthDetail = $_.Exception.Message
        }
        Start-Sleep -Seconds 1
    }
    $result.HealthEndpointResponds = $healthOk
    $result.HealthEndpointDetail = $healthDetail

    return $result
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if ($Uninstall) {
    Invoke-Uninstall
    exit 0
}

Write-Step 'Checking prerequisites'
$prereqFailures = Test-Prerequisites
if ($prereqFailures.Count -gt 0) {
    Write-Output "`nPrerequisite check FAILED -- fix the following and re-run:"
    foreach ($f in $prereqFailures) { Write-Output "  - $f" }
    exit 1
}

Write-Step "Installing agent files to $InstallDir"
if (-not (Test-Path -LiteralPath $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
$sourceRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path.TrimEnd('\')
$resolvedInstallDir = (Resolve-Path -LiteralPath $InstallDir).Path.TrimEnd('\')

if ($sourceRoot -ieq $resolvedInstallDir) {
    Write-Ok "Already running from the install directory ($resolvedInstallDir) -- skipping file copy"
} else {
    Copy-Item -Path (Join-Path $sourceRoot 'adam_agent.ps1') -Destination $resolvedInstallDir -Force

    $destModules = Join-Path $resolvedInstallDir 'modules'
    if (Test-Path -LiteralPath $destModules) {
        # Full replace, not a merge -- guarantees a stale/renamed module
        # from a previous install doesn't linger alongside the new set.
        Remove-Item -LiteralPath $destModules -Recurse -Force
    }
    Copy-Item -Path (Join-Path $sourceRoot 'modules') -Destination $resolvedInstallDir -Recurse -Force
    Write-Ok "Copied adam_agent.ps1 and modules/ from $sourceRoot to $resolvedInstallDir"
}

Write-Step 'Writing / merging configuration'
$configPath = Join-Path $resolvedInstallDir 'agent.config.json'
$defaultConfig = [ordered]@{
    ListenPrefix = "http://+:$Port/"
    ProcmonPath  = 'C:\Users\Admin\Downloads\ProcessMonitor\Procmon64.exe'
    TsharkPath   = 'C:\Program Files\Wireshark\tshark.exe'
    SysmonLog    = 'Microsoft-Windows-Sysmon/Operational'
    CaptureDir   = 'C:\ADAM\telemetry'
    SampleDir    = 'C:\ADAM\samples'
}

if (-not (Test-Path -LiteralPath $configPath)) {
    $defaultConfig | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
    Write-Ok "Wrote default config to $configPath -- edit tool paths if this guest's install locations differ"
} else {
    try {
        $existing = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        $existingHash = [ordered]@{}
        foreach ($prop in $existing.PSObject.Properties) { $existingHash[$prop.Name] = $prop.Value }

        $changed = $false
        foreach ($key in $defaultConfig.Keys) {
            if (-not $existingHash.Contains($key)) {
                $existingHash[$key] = $defaultConfig[$key]
                $changed = $true
            }
        }

        if ($changed) {
            $existingHash | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8
            Write-Ok "Merged new config keys into existing $configPath (existing values preserved)"
        } else {
            Write-Ok "Existing config at $configPath already has every required key -- left untouched"
        }
    } catch {
        Write-Bad "Existing config at $configPath could not be parsed ($($_.Exception.Message)) -- leaving it untouched"
        Write-Info "Delete $configPath and re-run install.ps1 to regenerate defaults, or fix the JSON manually"
    }
}

Write-Step 'Reserving URL ACL for HttpListener'
$urlAclTarget = "http://+:$Port/"
if (Test-UrlAclReserved -Url $urlAclTarget) {
    Write-Ok "URL ACL for $urlAclTarget already reserved"
} else {
    & netsh http add urlacl url="$urlAclTarget" user="Everyone" | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Reserved URL ACL for $urlAclTarget"
    } else {
        Write-Bad "netsh http add urlacl failed for $urlAclTarget (exit code $LASTEXITCODE)"
    }
}

Write-Step 'Opening firewall port'
$existingRule = Get-NetFirewallRule -DisplayName $Script:RuleName -ErrorAction SilentlyContinue
$needsRule = $true
if ($existingRule) {
    $portFilter = $existingRule | Get-NetFirewallPortFilter
    if ($portFilter.LocalPort -eq "$Port") {
        Write-Ok "Firewall rule '$Script:RuleName' already allows TCP $Port"
        $needsRule = $false
    } else {
        Write-Info "Existing firewall rule '$Script:RuleName' targets port $($portFilter.LocalPort), not $Port -- recreating"
        Remove-NetFirewallRule -DisplayName $Script:RuleName
    }
}
if ($needsRule) {
    New-NetFirewallRule -DisplayName $Script:RuleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
    Write-Ok "Created firewall rule '$Script:RuleName' for TCP $Port"
}

Write-Step 'Registering scheduled task'
$expectedArgument = "-NoProfile -ExecutionPolicy Bypass -File `"$resolvedInstallDir\adam_agent.ps1`""
$existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
$needsRegister = $true
if ($existingTask) {
    $existingAction = $existingTask.Actions | Select-Object -First 1
    if ($existingAction -and $existingAction.Execute -eq 'powershell.exe' -and $existingAction.Arguments -eq $expectedArgument) {
        Write-Ok "Scheduled task '$Script:TaskName' already registered with the correct action"
        $needsRegister = $false
    } else {
        Write-Info "Existing scheduled task action differs from the expected install path -- re-registering"
        if ($existingTask.State -eq 'Running') {
            Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        }
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false
    }
}
if ($needsRegister) {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $expectedArgument
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
    Write-Ok "Registered scheduled task '$Script:TaskName'"
}

$task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
if ($task -and $task.State -eq 'Running') {
    Write-Ok "Scheduled task '$Script:TaskName' already running"
} else {
    try {
        Start-ScheduledTask -TaskName $Script:TaskName
        Write-Ok "Started scheduled task '$Script:TaskName'"
    } catch {
        Write-Bad "Could not start scheduled task now: $($_.Exception.Message) -- it should still start at next boot"
    }
}

if ($SkipVerification) {
    Write-Output "`n-SkipVerification set -- installation steps ran, but nothing was re-checked. Run install.ps1 again without -SkipVerification once networking is up to confirm the deployment."
    exit 0
}

Write-Step 'Verifying deployment'
$verification = Test-Deployment -InstallDir $resolvedInstallDir -Port $Port -TaskName $Script:TaskName

$checks = [ordered]@{
    'Scheduled task exists'     = $verification.ScheduledTaskExists
    'Scheduled task running'    = $verification.ScheduledTaskRunning
    'Configuration file exists' = $verification.ConfigFileExists
    'Modules import cleanly'    = $verification.ModulesImportCleanly
    '/health responds'          = $verification.HealthEndpointResponds
}

$allOk = $true
foreach ($name in $checks.Keys) {
    if ($checks[$name]) {
        Write-Ok $name
    } else {
        Write-Bad $name
        $allOk = $false
    }
}

if ($verification.ModuleErrors.Count -gt 0) {
    Write-Output "    Module import errors:"
    foreach ($e in $verification.ModuleErrors) { Write-Output "      - $e" }
}
if (-not $verification.HealthEndpointResponds -and $verification.HealthEndpointDetail) {
    Write-Output "    /health detail: $($verification.HealthEndpointDetail)"
}

if (-not $allOk) {
    Write-Output "`nDeployment verification FAILED. Common causes:"
    Write-Output "  - Scheduled task not running: 'Get-ScheduledTask -TaskName ""$Script:TaskName"" | Get-ScheduledTaskInfo' and check LastTaskResult"
    Write-Output "  - /health not responding: confirm the URL ACL and firewall steps above both reported [OK], and check $resolvedInstallDir\logs\adam_agent.log if present"
    Write-Output "  - Module import errors: fix the reported .psm1 issue in $resolvedInstallDir\modules and re-run install.ps1"
    Write-Output "  - If none of the above explains it, run '$resolvedInstallDir\adam_agent.ps1' directly in a foreground PowerShell window to see the raw startup error"
    exit 1
}

Write-Output "`nDeployment verified OK. Agent reachable at http://<guest-ip>:$Port/health"
Write-Output "Remember: re-capture the VM's 'clean' snapshot now, or these changes are lost on the next session's snapshot restore."
exit 0
