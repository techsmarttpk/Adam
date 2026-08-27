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

$Script:Config = Get-AgentConfig -ConfigPath $ConfigPath
$Script:AgentVersion = '1.0.0'
$Script:ApiVersion = '1'
$Script:StartTime = Get-Date

function Read-JsonBody {
    param([System.Net.HttpListenerRequest]$Request)
    if (-not $Request.HasEntityBody -or $Request.ContentLength64 -le 0) { return $null }
    $encoding = if ($Request.ContentEncoding) { $Request.ContentEncoding } else { [System.Text.Encoding]::UTF8 }
    $buffer = New-Object byte[] $Request.ContentLength64
    $totalRead = 0
    while ($totalRead -lt $Request.ContentLength64) {
        $read = $Request.InputStream.Read($buffer, $totalRead, $Request.ContentLength64 - $totalRead)
        if ($read -le 0) { break }
        $totalRead += $read
    }
    $raw = $encoding.GetString($buffer, 0, $totalRead)
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json)
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
            $uptime = ((Get-Date) - $Script:StartTime).TotalSeconds
            return @{ Kind = 'json'; Envelope = (New-SuccessEnvelope -Data @{ status = 'ok'; uptime_s = $uptime }) }
        }
        'GET /version' {
            return @{ Kind = 'json'; Envelope = (New-SuccessEnvelope -Data @{ agent_version = $Script:AgentVersion; api_version = $Script:ApiVersion }) }
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
            $pArgs = $body.PSObject.Properties['arguments']
            if ($pArgs -and $pArgs.Value) { $arguments = @($pArgs.Value) }
            $pWait = $body.PSObject.Properties['wait']
            $wait = if ($pWait -and $pWait.Value -ne $null) { [bool]$pWait.Value } else { $false }
            $pTimeout = $body.PSObject.Properties['timeout_s']
            $timeoutS = if ($pTimeout -and $pTimeout.Value -ne $null) { $pTimeout.Value } else { $null }
            $pWorkDir = $body.PSObject.Properties['working_directory']
            $workDir = if ($pWorkDir -and $pWorkDir.Value) { [string]$pWorkDir.Value } else { $null }
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
            $pPid = $body.PSObject.Properties['pid']
            $requestedPid = if ($pPid -and $pPid.Value -ne $null) { $pPid.Value } else { $null }
            $pName = $body.PSObject.Properties['name']
            $name = if ($pName -and $pName.Value) { [string]$pName.Value } else { $null }
            return @{ Kind = 'json'; Envelope = (Invoke-ProcessTerminate -ProcessId $requestedPid -Name $name) }
        }
        'POST /process/wait' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-ProcessWait -ProcessId $body.pid -TimeoutS $body.timeout_s) }
        }
        'GET /process/query' {
            $name = Get-QueryParam -Request $Request -Name 'name'
            $pidRaw = Get-QueryParam -Request $Request -Name 'pid'
            $requestedPid = if ($pidRaw) { [int]$pidRaw } else { $null }
            return @{ Kind = 'json'; Envelope = (Invoke-ProcessQuery -Name $name -ProcessId $requestedPid) }
        }

        # ---------------- Procmon ----------------
        'POST /procmon/start' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-ProcmonStart -ProcmonPath $Script:Config['ProcmonPath'] -SessionId $body.session_id -BackingFile $body.backing_file) }
        }
        'POST /procmon/stop' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-ProcmonStop -ProcmonPath $Script:Config['ProcmonPath'] -SessionId $body.session_id) }
        }
        'POST /procmon/export' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-ProcmonExport -ProcmonPath $Script:Config['ProcmonPath'] -PmlPath $body.pml_path -CsvPath $body.csv_path) }
        }
        'GET /procmon/verify-backing-file' {
            $path = Get-QueryParam -Request $Request -Name 'path'
            return @{ Kind = 'json'; Envelope = (Get-ProcmonBackingFileStatus -Path $path) }
        }

        # ---------------- Network / tshark ----------------
        'GET /network/interfaces' {
            return @{ Kind = 'json'; Envelope = (Get-NetworkInterfaces -TsharkPath $Script:Config['TsharkPath']) }
        }
        'POST /network/start' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-NetworkStart -TsharkPath $Script:Config['TsharkPath'] -SessionId $body.session_id -Interface $body.interface -PcapPath $body.pcap_path) }
        }
        'POST /network/stop' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-NetworkStop -SessionId $body.session_id) }
        }
        'POST /network/convert' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-NetworkConvert -TsharkPath $Script:Config['TsharkPath'] -PcapPath $body.pcap_path -EkJsonPath $body.ek_json_path) }
        }

        # ---------------- Sysmon ----------------
        'POST /sysmon/export' {
            $body = Read-JsonBody -Request $Request
            return @{ Kind = 'json'; Envelope = (Invoke-SysmonExport -Channel $body.channel -OutputPath $body.output_path) }
        }
        'GET /sysmon/diagnostics' {
            $channel = Get-QueryParam -Request $Request -Name 'channel'
            if (-not $channel) { $channel = $Script:Config['SysmonLog'] }
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
            return @{ Kind = 'json'; Envelope = (Invoke-SampleUpload -SampleDir $Script:Config['SampleDir'] -Filename $body.filename -Sha256 $body.sha256 -ContentBase64 $body.content_base64) }
        }
        'POST /sample/stage' {
            $body = Read-JsonBody -Request $Request
            $stageParams = @{
                TargetPath = [string]$body.target_path
            }
            $pStaged = $body.PSObject.Properties['staged_path']
            if ($pStaged -and $pStaged.Value) {
                $stageParams['StagedPath'] = [string]$pStaged.Value
            }
            $pContent = $body.PSObject.Properties['content_base64']
            if ($pContent -and $pContent.Value) {
                $stageParams['ContentBase64'] = [string]$pContent.Value
            }
            $pSha = $body.PSObject.Properties['sha256']
            if ($pSha -and $pSha.Value) {
                $stageParams['Sha256'] = [string]$pSha.Value
            }
            return @{ Kind = 'json'; Envelope = (Invoke-SampleStage @stageParams) }
        }

        # ---------------- Artifact ----------------
        'GET /artifact/list' {
            $sessionId = Get-QueryParam -Request $Request -Name 'session_id'
            return @{ Kind = 'json'; Envelope = (Invoke-ArtifactList -CaptureDir $Script:Config['CaptureDir'] -SessionId $sessionId) }
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
    # Self-healing: ensure firewall rule, URL ACL, Sysmon channel permissions, and decoy directory permissions are present
    try {
        & netsh advfirewall firewall add rule name="ADAM_Agent" dir=in action=allow protocol=TCP localport=8765 | Out-Null
        & netsh http add urlacl url="http://+:8765/" user="Everyone" | Out-Null
        & wevtutil sl "Microsoft-Windows-Sysmon/Operational" "/ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;AU)(A;;0x1;;;WD)" | Out-Null
        if (-not (Test-Path -LiteralPath "C:\Users\Admin\Documents")) {
            New-Item -ItemType Directory -Path "C:\Users\Admin\Documents" -Force | Out-Null
        }
        & icacls "C:\Users\Admin\Documents" /grant "Everyone:(OI)(CI)F" /C /Q | Out-Null
        if (-not (Test-Path -LiteralPath "C:\Users\Adam\Documents")) {
            New-Item -ItemType Directory -Path "C:\Users\Adam\Documents" -Force | Out-Null
        }
        & icacls "C:\Users\Adam\Documents" /grant "Everyone:(OI)(CI)F" /C /Q | Out-Null
        if (-not (Test-Path -LiteralPath "C:\ADAM\telemetry")) {
            New-Item -ItemType Directory -Path "C:\ADAM\telemetry" -Force | Out-Null
        }
        & icacls "C:\ADAM" /grant "Everyone:(OI)(CI)F" /C /Q | Out-Null
    } catch {
        # Best effort
    }

    $prefix = $Script:Config['ListenPrefix']
    $listener = $null
    $started = $false
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            $listener = New-Object System.Net.HttpListener
            $listener.Prefixes.Add($prefix)
            $listener.Start()
            $started = $true
            break
        } catch {
            Write-AgentLog -Level WARN -Message "attempt $attempt failed to start HttpListener on $prefix : $($_.Exception.Message)"
            if ($listener) {
                try { $listener.Close() } catch { }
                $listener = $null
            }
            Start-Sleep -Seconds 2
        }
    }
    if (-not $started -or $null -eq $listener) {
        Write-AgentLog -Level ERROR -Message "failed to start HttpListener on $prefix after 30 attempts"
        throw "HttpListener could not start on $prefix"
    }
    Write-AgentLog -Message "adam_agent listening on $prefix (agent_version=$Script:AgentVersion api_version=$Script:ApiVersion)"

    while ($listener.IsListening) {
        try {
            $context = $listener.GetContext()
        } catch [System.Net.HttpListenerException] {
            # Thrown when the listener is stopped while GetContext() is blocking
            break
        } catch {
            Write-AgentLog -Level WARN -Message "GetContext threw: $($_.Exception.Message)"
            continue
        }

        try {
            $request = $context.Request
            $response = $context.Response
            $path = $request.Url.AbsolutePath.TrimEnd('/')
            if ([string]::IsNullOrEmpty($path)) { $path = '/' }

            # Enforce agent authentication token if configured
            $expectedToken = $Script:Config['AuthToken']
            if (-not [string]::IsNullOrEmpty($expectedToken)) {
                $headerToken = $request.Headers['X-Adam-Token']
                if ([string]::IsNullOrEmpty($headerToken)) {
                    $authHeader = $request.Headers['Authorization']
                    if (-not [string]::IsNullOrEmpty($authHeader) -and $authHeader.StartsWith('Bearer ')) {
                        $headerToken = $authHeader.Substring(7).Trim()
                    }
                }
                if ($headerToken -ne $expectedToken) {
                    Write-AgentLog -Level WARN -Message "rejected request to $($path): missing or invalid authentication token"
                    $authEnvelope = New-ErrorEnvelope -ErrorCode 'UNAUTHORIZED' -ErrorMessage 'Authentication failed: missing or invalid agent token'
                    Write-JsonResponse -Response $response -Envelope $authEnvelope -StatusCode 401
                    continue
                }
            }

            $outcome = Invoke-Route -Method $request.HttpMethod -Path $path -Request $request
            if ($outcome.Kind -eq 'file') {
                Write-FileResponse -Response $response -ReadResult $outcome.Result
            } else {
                Write-EnvelopeResponse -Response $response -Envelope $outcome.Envelope
            }
        } catch {
            Write-AgentLog -Level ERROR -Message "unhandled exception routing request: $($_.Exception.Message)"
            try {
                if ($context -and $context.Response) {
                    $errorEnvelope = New-ErrorEnvelope -ErrorCode $Script:ErrorCodes.InternalError -ErrorMessage $_.Exception.Message
                    Write-JsonResponse -Response $context.Response -Envelope $errorEnvelope -StatusCode 500
                }
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
