#requires -Version 5.1
<#
.SYNOPSIS
    adam_agent.ps1 -- guest-resident HTTP agent entrypoint. The Phase 5
    architecture's "Guest Agent Service" (see this project's own EXECUTION
    MODE architecture diagram): host <-HTTP-> Guest Agent Service, owning
    all Windows interactions so the host never invokes cmd.exe/
    powershell.exe for normal operations.

.DESCRIPTION
    Built on PowerShell 5.1's built-in System.Net.HttpListener (.NET
    Framework, not .NET Core) per ARCHITECTURE.md constraint C4 ("The
    guest agent is PowerShell 5.1 compatible. No .NET Core assumption")
    and this project's own explicit decision to resolve the FastAPI-vs-
    PowerShell fork in favor of staying within that documented constraint
    rather than introducing a new Python/FastAPI dependency into the
    guest image.

    Routing is a flat table of (Method, PathPattern) -> handler, matched
    in Invoke-Route below. Every handler returns a hashtable in the
    response-envelope shape (Common.psm1's New-SuccessEnvelope/
    New-ErrorEnvelope) except GET /filesystem/read, which is special-
    cased to write raw bytes (API spec section 12.1).

    Run directly for foreground/manual testing:
        powershell.exe -ExecutionPolicy Bypass -File adam_agent.ps1
    Run as an unattended background service: see install.ps1, which
    registers this script as a Scheduled Task set to run at logon /
    system startup.

.NOTES
    NOT EXECUTED OR SYNTAX-CHECKED AGAINST A REAL WINDOWS/PowerShell 5.1
    RUNTIME as part of this delivery -- the environment this was written
    in has no Windows or PowerShell available (see the delivery report's
    "what still needs a real VM" section). Written carefully against
    well-documented PowerShell 5.1 / .NET Framework APIs, but should be
    run and exercised on a real guest before being trusted in production.
#>

param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'agent.config.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ModulesDir = Join-Path $PSScriptRoot 'modules'
Import-Module (Join-Path $ModulesDir 'Common.psm1') -Force
Import-Module (Join-Path $ModulesDir 'AgentConfig.psm1') -Force
Import-Module (Join-Path $ModulesDir 'FilesystemManager.psm1') -Force
Import-Module (Join-Path $ModulesDir 'ProcessManager.psm1') -Force
Import-Module (Join-Path $ModulesDir 'ProcmonManager.psm1') -Force
Import-Module (Join-Path $ModulesDir 'NetworkManager.psm1') -Force
Import-Module (Join-Path $ModulesDir 'SysmonManager.psm1') -Force
Import-Module (Join-Path $ModulesDir 'DiagnosticsManager.psm1') -Force
Import-Module (Join-Path $ModulesDir 'SampleManager.psm1') -Force
Import-Module (Join-Path $ModulesDir 'ArtifactManager.psm1') -Force

# Every function this script calls, grouped by the module that must
# export it -- kept as an explicit list (not derived by scanning this
# file's own text) specifically because a scan misses bare-statement
# calls that aren't wrapped in parentheses (e.g. `Write-AgentLog -Level
# ERROR -Message ...` or `$Config = Get-AgentConfig ...`, neither of
# which appear as `(Verb-Noun ...)`), so a text-scanning version of this
# check would have silently skipped the exact two functions most likely
# to matter -- Write-AgentLog itself is called this way. When adding a
# new route to Invoke-Route below that calls a new module function, add
# that function name to the relevant group here too.
$Script:RequiredCommandsByModule = [ordered]@{
    'Common.psm1'             = @('New-SuccessEnvelope', 'New-ErrorEnvelope', 'Get-ErrorHttpStatus', 'Write-AgentLog', 'Invoke-NativeProcess')
    'AgentConfig.psm1'        = @('Get-AgentConfig')
    'FilesystemManager.psm1'  = @('Invoke-FilesystemMkdir', 'Invoke-FilesystemExists', 'Invoke-FilesystemCopy', 'Invoke-FilesystemMove', 'Invoke-FilesystemDelete', 'Invoke-FilesystemList', 'Get-FilesystemReadBytes')
    'ProcessManager.psm1'     = @('Invoke-ProcessStart', 'Invoke-ProcessTerminate', 'Invoke-ProcessWait', 'Invoke-ProcessQuery')
    'ProcmonManager.psm1'     = @('Invoke-ProcmonStart', 'Invoke-ProcmonStop', 'Invoke-ProcmonExport', 'Get-ProcmonBackingFileStatus')
    'NetworkManager.psm1'     = @('Get-NetworkInterfaces', 'Invoke-NetworkStart', 'Invoke-NetworkStop', 'Invoke-NetworkConvert')
    'SysmonManager.psm1'      = @('Invoke-SysmonExport', 'Get-SysmonDiagnostics')
    'DiagnosticsManager.psm1' = @('Get-DiagnosticsToken', 'Get-DiagnosticsServices', 'Get-DiagnosticsDrivers')
    'SampleManager.psm1'      = @('Invoke-SampleUpload', 'Invoke-SampleStage')
    'ArtifactManager.psm1'    = @('Invoke-ArtifactList', 'Invoke-ArtifactPackage', 'Get-ArtifactMetadata')
}

function Test-RequiredCommandsAvailable {
    <#
    .SYNOPSIS
        Startup self-test: fails immediately, naming exactly which
        function(s) are missing and which module was supposed to export
        them, instead of crashing later -- possibly mid-request, inside
        whichever route handler happens to call the first missing
        function -- with a bare "term ... is not recognized" error and no
        indication of why.

    .DESCRIPTION
        A real, shipped bug motivates this: every manager module used to
        re-import Common.psm1 with -Force internally, which (a
        documented PowerShell behavior -- PowerShell/PowerShell issue
        7367 on GitHub) removed Common.psm1's exports from adam_agent.ps1's
        OWN top-level scope every time, since -Force on an already-loaded
        module removes it from wherever it was previously loaded and
        re-adds it only into the CURRENT (nested) importer's scope. The
        practical symptom was the Write-AgentLog function throwing
        "is not recognized" the first time Start-AdamAgent called it --
        well after every Import-Module line above had already reported
        success, so nothing about the import sequence itself looked
        wrong. That root cause is fixed (see the comment on each
        module's own Common.psm1 import line under modules/), but this
        self-test exists so ANY future recurrence of the same class of
        bug -- a module failing to export what this script expects, a
        rename that misses one call site, a new nested -Force reimport
        reintroducing the exact same wipeout -- is caught here, at
        startup, before the HttpListener ever binds, rather than three
        minutes later against a live request.
    #>
    $missing = @()
    foreach ($moduleName in $Script:RequiredCommandsByModule.Keys) {
        foreach ($commandName in $Script:RequiredCommandsByModule[$moduleName]) {
            if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
                $missing += [pscustomobject]@{ Module = $moduleName; Command = $commandName }
            }
        }
    }

    if ($missing.Count -gt 0) {
        Write-Host "FATAL: adam_agent.ps1 startup self-test failed." -ForegroundColor Red
        Write-Host "The following $($missing.Count) required command(s) are not available after module import:" -ForegroundColor Red
        foreach ($entry in $missing) { Write-Host "  - $($entry.Command) (expected from $($entry.Module))" -ForegroundColor Red }
        Write-Host "Likely causes: that module failed to import silently, the function was renamed without updating its Export-ModuleMember list, the function was never added to Export-ModuleMember at all, or a nested 'Import-Module ... -Force' inside one module wiped another module's exports back out of this scope (see the comment on Common.psm1's own import line in any modules/*.psm1 file for the exact, previously-shipped bug of this last kind)." -ForegroundColor Red
        exit 1
    }
}

Test-RequiredCommandsAvailable

$Config = Get-AgentConfig -ConfigPath $ConfigPath
$AgentVersion = '1.0.0'
$ApiVersion = '1'
$StartTime = Get-Date

function Read-JsonBody {
    param([System.Net.HttpListenerRequest]$Request)
    if (-not $Request.HasEntityBody) { return $null }
    $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
    try {
        $raw = $reader.ReadToEnd()
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return $raw | ConvertFrom-Json
    } finally {
        $reader.Dispose()
    }
}

function Get-QueryParam {
    param([System.Net.HttpListenerRequest]$Request, [string]$Name)
    $value = $Request.QueryString[$Name]
    if ($null -eq $value) { return $null }
    return $value
}

function Write-JsonResponse {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [hashtable]$Envelope,
        [int]$StatusCode = 200
    )
    $json = $Envelope | ConvertTo-Json -Depth 10 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Response.StatusCode = $StatusCode
    $Response.ContentType = 'application/json; charset=utf-8'
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

function Write-EnvelopeResponse {
    <# Picks the HTTP status from the envelope's own error_code (spec section 2.1) so success and failure share one code path. #>
    param([System.Net.HttpListenerResponse]$Response, [hashtable]$Envelope)
    $status = if ($Envelope.success) { 200 } else { Get-ErrorHttpStatus -ErrorCode $Envelope.error_code }
    Write-JsonResponse -Response $Response -Envelope $Envelope -StatusCode $status
}

function Write-FileResponse {
    <# GET /filesystem/read's raw-bytes special case (API spec 12.1). #>
    param([System.Net.HttpListenerResponse]$Response, [hashtable]$ReadResult)
    if (-not $ReadResult.Success) {
        $Response.StatusCode = Get-ErrorHttpStatus -ErrorCode $ReadResult.ErrorCode
        $Response.Headers.Add('X-Error-Code', $ReadResult.ErrorCode)
        $Response.ContentLength64 = 0
        $Response.OutputStream.Close()
        return
    }
    $Response.StatusCode = 200
    $Response.ContentType = 'application/octet-stream'
    $Response.ContentLength64 = $ReadResult.Bytes.Length
    $Response.OutputStream.Write($ReadResult.Bytes, 0, $ReadResult.Bytes.Length)
    $Response.OutputStream.Close()
}

function Invoke-Route {
    param(
        [string]$Method,
        [string]$Path,
        [System.Net.HttpListenerRequest]$Request
    )

    switch ("$Method $Path") {
        'GET /health' {
            $uptime = ((Get-Date) - $StartTime).TotalSeconds
            return @{ Kind = 'json'; Envelope = (New-SuccessEnvelope -Data @{ status = 'ok'; uptime_s = $uptime }) }
        }
        'GET /version' {
            return @{ Kind = 'json'; Envelope = (New-SuccessEnvelope -Data @{ agent_version = $AgentVersion; api_version = $ApiVersion }) }
        }

        # ---------------- Filesystem ----------------
        'POST /filesystem/mkdir' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-FilesystemMkdir -Path $body.path) }
        }
        'GET /filesystem/exists' {
            $path = Get-QueryParam -Request $Request -Name 'path'
            return @{ Kind = 'json'; Envelope = (Invoke-FilesystemExists -Path $path) }
        }
        'POST /filesystem/copy' {
            $body = Read-JsonBody -Request $Request
            $overwrite = if ($body.PSObject.Properties.Name -contains 'overwrite') { [bool]$body.overwrite } else { $false }
            return @{ Kind = 'json'; Envelope = (Invoke-FilesystemCopy -Source $body.source -Destination $body.destination -Overwrite $overwrite) }
        }
        'POST /filesystem/move' {
            $body = Read-JsonBody -Request $Request
            $overwrite = if ($body.PSObject.Properties.Name -contains 'overwrite') { [bool]$body.overwrite } else { $false }
            return @{ Kind = 'json'; Envelope = (Invoke-FilesystemMove -Source $body.source -Destination $body.destination -Overwrite $overwrite) }
        }
        'POST /filesystem/delete' {
            $body = Read-JsonBody -Request $Request
            $recursive = if ($body.PSObject.Properties.Name -contains 'recursive') { [bool]$body.recursive } else { $false }
            return @{ Kind = 'json'; Envelope = (Invoke-FilesystemDelete -Path $body.path -Recursive $recursive) }
        }
        'GET /filesystem/list' {
            $path = Get-QueryParam -Request $Request -Name 'path'
            return @{ Kind = 'json'; Envelope = (Invoke-FilesystemList -Path $path) }
        }
        'GET /filesystem/read' {
            $path = Get-QueryParam -Request $Request -Name 'path'
            return @{ Kind = 'file'; Result = (Get-FilesystemReadBytes -Path $path) }
        }

        # ---------------- Process ----------------
        'POST /process/start' {
            $body = Read-JsonBody -Request $Request
            $arguments = @()
            if ($body.PSObject.Properties.Name -contains 'arguments' -and $body.arguments) { $arguments = @($body.arguments) }
            $wait = if ($body.PSObject.Properties.Name -contains 'wait') { [bool]$body.wait } else { $false }
            $timeoutS = if ($body.PSObject.Properties.Name -contains 'timeout_s') { $body.timeout_s } else { $null }
            $workDir = if ($body.PSObject.Properties.Name -contains 'working_directory') { $body.working_directory } else { $null }
            return @{ Kind = 'json'; Envelope = (Invoke-ProcessStart -Executable $body.executable -Arguments $arguments -WorkingDirectory $workDir -Wait $wait -TimeoutS $timeoutS) }
        }
        'POST /process/terminate' {
            $body = Read-JsonBody -Request $Request
            # NOT $pid: $PID is PowerShell's own automatic variable
            # (the CURRENT process's id) and is read-only -- assigning
            # to it throws "Cannot overwrite variable PID because it is
            # read-only or constant" (see GET /process/query's own
            # comment below for the real, shipped bug this caused).
            # $requestedPid is just a locally-scoped name that doesn't
            # collide with it.
            $requestedPid = if ($body.PSObject.Properties.Name -contains 'pid') { $body.pid } else { $null }
            $name = if ($body.PSObject.Properties.Name -contains 'name') { $body.name } else { $null }
            return @{ Kind = 'json'; Envelope = (Invoke-ProcessTerminate -ProcessId $requestedPid -Name $name) }
        }
        'POST /process/wait' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-ProcessWait -ProcessId $body.pid -TimeoutS $body.timeout_s) }
        }
        'GET /process/query' {
            $name = Get-QueryParam -Request $Request -Name 'name'
            $pidRaw = Get-QueryParam -Request $Request -Name 'pid'
            # NOT $pid -- a real, shipped bug here: $PID is PowerShell's
            # own read-only automatic variable holding the CURRENT
            # process's id, and `$pid = ...` (no scope qualifier)
            # resolves to that same variable rather than creating a new
            # local one, so every GET /process/query request failed
            # with "Cannot overwrite variable PID because it is
            # read-only or constant." $requestedPid avoids the name
            # collision entirely -- functionally identical otherwise.
            $requestedPid = if ($pidRaw) { [int]$pidRaw } else { $null }
            return @{ Kind = 'json'; Envelope = (Invoke-ProcessQuery -Name $name -ProcessId $requestedPid) }
        }

        # ---------------- Procmon ----------------
        'POST /procmon/start' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-ProcmonStart -ProcmonPath $Config.ProcmonPath -SessionId $body.session_id -BackingFile $body.backing_file) }
        }
        'POST /procmon/stop' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-ProcmonStop -ProcmonPath $Config.ProcmonPath -SessionId $body.session_id) }
        }
        'POST /procmon/export' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-ProcmonExport -ProcmonPath $Config.ProcmonPath -PmlPath $body.pml_path -CsvPath $body.csv_path) }
        }
        'GET /procmon/verify-backing-file' {
            $path = Get-QueryParam -Request $Request -Name 'path'
            return @{ Kind = 'json'; Envelope = (Get-ProcmonBackingFileStatus -Path $path) }
        }

        # ---------------- Network / tshark ----------------
        'GET /network/interfaces' {
            return @{ Kind = 'json'; Envelope = (Get-NetworkInterfaces -TsharkPath $Config.TsharkPath) }
        }
        'POST /network/start' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-NetworkStart -TsharkPath $Config.TsharkPath -SessionId $body.session_id -Interface $body.interface -PcapPath $body.pcap_path) }
        }
        'POST /network/stop' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-NetworkStop -SessionId $body.session_id) }
        }
        'POST /network/convert' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-NetworkConvert -TsharkPath $Config.TsharkPath -PcapPath $body.pcap_path -EkJsonPath $body.ek_json_path) }
        }

        # ---------------- Sysmon ----------------
        'POST /sysmon/export' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-SysmonExport -Channel $body.channel -OutputPath $body.output_path) }
        }
        'GET /sysmon/diagnostics' {
            $channel = Get-QueryParam -Request $Request -Name 'channel'
            if (-not $channel) { $channel = $Config.SysmonLog }
            return @{ Kind = 'json'; Envelope = (Get-SysmonDiagnostics -Channel $channel) }
        }

        # ---------------- Diagnostics ----------------
        'GET /diagnostics/token' {
            return @{ Kind = 'json'; Envelope = (Get-DiagnosticsToken) }
        }
        'GET /diagnostics/services' {
            $name = Get-QueryParam -Request $Request -Name 'name'
            return @{ Kind = 'json'; Envelope = (Get-DiagnosticsServices -Name $name) }
        }
        'GET /diagnostics/drivers' {
            $name = Get-QueryParam -Request $Request -Name 'name'
            return @{ Kind = 'json'; Envelope = (Get-DiagnosticsDrivers -Name $name) }
        }

        # ---------------- Sample ----------------
        'POST /sample/upload' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-SampleUpload -SampleDir $Config.SampleDir -Filename $body.filename -Sha256 $body.sha256 -ContentBase64 $body.content_base64) }
        }
        'POST /sample/stage' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-SampleStage -StagedPath $body.staged_path -TargetPath $body.target_path) }
        }

        # ---------------- Artifact ----------------
        'GET /artifact/list' {
            $sessionId = Get-QueryParam -Request $Request -Name 'session_id'
            return @{ Kind = 'json'; Envelope = (Invoke-ArtifactList -CaptureDir $Config.CaptureDir -SessionId $sessionId) }
        }
        'POST /artifact/package' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-ArtifactPackage -Paths @($body.paths) -OutputZip $body.output_zip) }
        }
        'GET /artifact/metadata' {
            $path = Get-QueryParam -Request $Request -Name 'path'
            return @{ Kind = 'json'; Envelope = (Get-ArtifactMetadata -Path $path) }
        }

        default {
            return @{ Kind = 'json'; Envelope = (New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.NotFound -ErrorMessage "no route for $Method $Path") }
        }
    }
}

function Start-AdamAgent {
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($Config.ListenPrefix)
    try {
        $listener.Start()
    } catch {
        Write-AgentLog -Level ERROR -Message "failed to start HttpListener on $($Config.ListenPrefix): $($_.Exception.Message). On Windows, binding a non-localhost prefix without admin rights requires a prior 'netsh http add urlacl' grant -- see install.ps1."
        throw
    }
    Write-AgentLog -Message "adam_agent listening on $($Config.ListenPrefix) (agent_version=$AgentVersion api_version=$ApiVersion)"

    while ($listener.IsListening) {
        try {
            $context = $listener.GetContext()
        } catch [System.Net.HttpListenerException] {
            # Thrown when the listener is stopped while GetContext() is
            # blocking -- normal shutdown path, not an error.
            break
        }

        $request = $context.Request
        $response = $context.Response
        $path = $request.Url.AbsolutePath.TrimEnd('/')
        if ([string]::IsNullOrEmpty($path)) { $path = '/' }

        try {
            $outcome = Invoke-Route -Method $request.HttpMethod -Path $path -Request $request
            if ($outcome.Kind -eq 'file') {
                Write-FileResponse -Response $response -ReadResult $outcome.Result
            } else {
                Write-EnvelopeResponse -Response $response -Envelope $outcome.Envelope
            }
        } catch {
            Write-AgentLog -Level ERROR -Message "unhandled exception routing $($request.HttpMethod) $path : $($_.Exception.Message)"
            try {
                $errorEnvelope = New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
                Write-JsonResponse -Response $response -Envelope $errorEnvelope -StatusCode 500
            } catch {
                # Response already closed/broken -- nothing more we can do for this request.
            }
        }
    }

    $listener.Stop()
    $listener.Close()
    Write-AgentLog -Message 'adam_agent stopped'
}

Start-AdamAgent
