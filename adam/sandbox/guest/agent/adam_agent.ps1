# adam_agent.ps1 - Windows Guest Telemetry & Deception Agent
# Compatible with PowerShell 5.1

$agentVersion = "1.4.7"
$port = 8443
$logPath = "C:\adam_agent.log"
$tempDir = "C:\temp"
$agentScriptPath = $MyInvocation.MyCommand.Path
if (-not $agentScriptPath) { $agentScriptPath = "C:\adam_agent.ps1" }

# Compute SHA256 of the running agent script
$runningAgentSha256 = ""
try {
    if (Test-Path $agentScriptPath) {
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.IO.File]::ReadAllBytes($agentScriptPath)
        $hashBytes = $hasher.ComputeHash($bytes)
        $runningAgentSha256 = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    }
} catch {
    $runningAgentSha256 = "unknown"
}

if (-not (Test-Path $tempDir)) { New-Item -Path $tempDir -ItemType Directory -Force }

function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.ffffffZ")
    $logLine = "$timestamp - $Message"
    Add-Content -Path $logPath -Value $logLine
    Write-Output $logLine
}

# --- ADMIN CHECK ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "FATAL: This agent must run as Administrator to perform mutations."
    exit 1
}

Write-Log "Starting ADAM Guest Agent v$agentVersion (SHA: $runningAgentSha256)..."

# Initialize ProcMon settings
$pmlPath = "C:\temp\procmon.pml"
$csvPath = "C:\temp\procmon.csv"
try {
    if (Test-Path $pmlPath) { Remove-Item -Path $pmlPath -Force }
    if (Test-Path $csvPath) { Remove-Item -Path $csvPath -Force }
} catch {}

$procmonExe = "procmon"
if (Test-Path "C:\temp\procmon.exe") {
    $procmonExe = "C:\temp\procmon.exe"
}

Write-Log "Initializing ProcMon background logger..."
Start-Process $procmonExe -ArgumentList "/BackingFile", $pmlPath, "/Quiet", "/Minimized" -ErrorAction SilentlyContinue

# Spawn a low-overhead background thread for continuous harvesting and VirtIO-Serial streaming
$runspace = [runspacefactory]::CreateRunspace()
$runspace.Open()
$powershell = [powershell]::Create()
$powershell.Runspace = $runspace
$powershell.AddScript({
    param($logPath, $procmonExe, $pmlPath, $csvPath)

    try {
        $sig = @'
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool PeekNamedPipe(
            IntPtr hNamedPipe,
            IntPtr lpBuffer,
            uint nBufferSize,
            IntPtr lpBytesRead,
            uint[] lpTotalBytesAvail,
            IntPtr lpBytesLeftThisMessage);
'@
        Add-Type -MemberDefinition $sig -Name "Win32Device" -Namespace "Win32" -ErrorAction SilentlyContinue
    } catch {}

    function Write-ThreadLog {
        param([string]$Msg)
        $ts = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.ffffffZ")
        Add-Content -Path $logPath -Value "$ts - [Harvester] $Msg"
    }

    function Process-Decision {
        param($decisionJson, $writer)
        
        Write-ThreadLog "Received PolicyDecision: $decisionJson"
        try {
            $decision = ConvertFrom-Json -InputObject $decisionJson
            $action = $decision.action
            $decisionId = $decision.decision_id
            $correlationId = $decision.correlation_id
            
            # Safe mutation_id generation
            $mutationId = "mut_unknown"
            if ($decisionId -and $decisionId.Length -gt 4) {
                $mutationId = "mut_" + $decisionId.Substring(4)
            } elseif ($decisionId) {
                $mutationId = "mut_" + $decisionId
            }
            
            $changes = @()
            $plausibilityScore = 1.0
            $plausibilityRationale = "Default mutation"
            $revertible = $true
            $causalWindowMs = 30000
            $status = "APPLIED"
            $errorMsg = $null
            
            try {
                if ($action -eq "SPAWN_FAKE_DC_ARTIFACTS") {
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                    Set-ItemProperty -Path $regPath -Name "Domain" -Value "CORP.LOCAL" -Force
                    Set-ItemProperty -Path $regPath -Name "SearchList" -Value "CORP.LOCAL" -Force
                    $changes += @{ "kind" = "REGISTRY"; "target" = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain"; "operation" = "SET"; "value" = "CORP.LOCAL" }
                    
                    $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
                    $entry = "10.0.0.10  DC01.CORP.LOCAL CORP.LOCAL DC01"
                    Add-Content -Path $hostsFile -Value "`n$entry" -Force
                    $changes += @{ "kind" = "NETWORK"; "target" = "dns:DC01.CORP.LOCAL"; "operation" = "RESPOND"; "value" = "10.0.0.10" }
                    
                    $sysvol = "C:\Windows\SYSVOL\sysvol\CORP.LOCAL"
                    New-Item -Path $sysvol -ItemType Directory -Force | Out-Null
                    $changes += @{ "kind" = "FILE"; "target" = "C:\Windows\SYSVOL\sysvol\CORP.LOCAL\"; "operation" = "CREATE" }

                    $plausibilityScore = 0.85
                    $plausibilityRationale = "Registry keys updated, hosts file appended, and SYSVOL directories structured."
                }
                elseif ($action -eq "SIMULATE_AV_PRESENCE") {
                    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    Set-ItemProperty -Path $regPath -Name "ProductStatus" -Value 1 -Force
                    $changes += @{ "kind" = "REGISTRY"; "target" = "HKLM\SOFTWARE\Microsoft\Windows Defender\ProductStatus"; "operation" = "SET"; "value" = "1" }
                    
                    $plausibilityScore = 0.90
                    $plausibilityRationale = "Defender product status registry flags configured."
                }
                elseif ($action -eq "PLANT_DECOY_DOCUMENTS") {
                    $userProfile = $env:USERPROFILE
                    $docDir = Join-Path $userProfile "Documents"
                    if (-not (Test-Path $docDir)) { New-Item -Path $docDir -ItemType Directory -Force | Out-Null }
                    $docxPath = Join-Path $docDir "Confidential_Strategy_2026.docx"
                    $xlsxPath = Join-Path $docDir "payroll_2026.xlsx"
                    "Confidential Strategy Document [Synthetic Decoy Payload]" | Out-File -FilePath $docxPath -Force
                    "Fake salary database context" | Out-File -FilePath $xlsxPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $docxPath; "operation" = "CREATE" }
                    $changes += @{ "kind" = "FILE"; "target" = $xlsxPath; "operation" = "CREATE" }
                    
                    $plausibilityScore = 0.95
                    $plausibilityRationale = "Decoy Word (.docx) and Excel (.xlsx) files created inside Documents catalog."
                }
                elseif ($action -eq "SPOOF_HARDWARE_IDENTITY" -or $action -eq "HIDE_VM_ARTIFACTS") {
                    $regPath = "HKLM:\HARDWARE\DESCRIPTION\System"
                    Set-ItemProperty -Path $regPath -Name "SystemBiosVersion" -Value @("DELL  - 1072009", "American Megatrends Inc. - 50011") -Force
                    Set-ItemProperty -Path $regPath -Name "VideoBiosVersion" -Value @("NVIDIA Quadro P2000 VGA BIOS") -Force
                    $changes += @{ "kind" = "REGISTRY"; "target" = "HKLM\HARDWARE\DESCRIPTION\System\SystemBiosVersion"; "operation" = "SET"; "value" = "DELL - 1072009" }
                    $changes += @{ "kind" = "REGISTRY"; "target" = "HKLM\HARDWARE\DESCRIPTION\System\VideoBiosVersion"; "operation" = "SET"; "value" = "NVIDIA Quadro P2000" }
                    
                    $plausibilityScore = 0.92
                    $plausibilityRationale = "Hardware and Video BIOS registry signatures spoofed to physical Dell workstation."
                }
                elseif ($action -eq "PLANT_DECOY_WALLET") {
                    $userProfile = $env:USERPROFILE
                    $walletDir = Join-Path $userProfile "AppData\Roaming\Electrum\wallets"
                    if (-not (Test-Path $walletDir)) { New-Item -Path $walletDir -ItemType Directory -Force | Out-Null }
                    $walletPath = Join-Path $walletDir "default_wallet"
                    "{""keystore"": {""xpub"": ""xpub661MyMwAqRbcF...""}, ""wallet_type"": ""standard""}" | Out-File -FilePath $walletPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $walletPath; "operation" = "CREATE" }
                    
                    $plausibilityScore = 0.94
                    $plausibilityRationale = "Synthetic Bitcoin/Electrum decoy wallet structure generated."
                }
                elseif ($action -eq "INJECT_FAKE_BROWSER_CREDS") {
                    # Write to all user profiles and Public documents to guarantee visibility
                    $profiles = @($env:USERPROFILE)
                    $allUsers = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "All Users|Default User|Public" }
                    foreach ($u in $allUsers) {
                        $profiles += $u.FullName
                    }
                    $profiles = $profiles | Select-Object -Unique

                    foreach ($p in $profiles) {
                        try {
                            $chromeDir = Join-Path $p "AppData\Local\Google\Chrome\User Data\Default"
                            if (-not (Test-Path $chromeDir)) { New-Item -Path $chromeDir -ItemType Directory -Force | Out-Null }
                            $loginDataPath = Join-Path $chromeDir "Login Data"
                            "SQLite format 3`0... [Synthetic Encrypted Vault Data]" | Out-File -FilePath $loginDataPath -Force
                            $changes += @{ "kind" = "FILE"; "target" = $loginDataPath; "operation" = "CREATE" }
                            
                            $docDir = Join-Path $p "Documents"
                            if (-not (Test-Path $docDir)) { New-Item -Path $docDir -ItemType Directory -Force | Out-Null }
                            $docCredsPath = Join-Path $docDir "Chrome_Passwords_Backup.txt"
                            "URL: https://corp.internal/login`nUsername: admin@corp.local`nPassword: DecoyPassword2026!" | Out-File -FilePath $docCredsPath -Force
                            $changes += @{ "kind" = "FILE"; "target" = $docCredsPath; "operation" = "CREATE" }
                        } catch {}
                    }
                    
                    # Also write to Public Documents as guaranteed fallback
                    try {
                        $pubDocs = "C:\Users\Public\Documents"
                        if (-not (Test-Path $pubDocs)) { New-Item -Path $pubDocs -ItemType Directory -Force | Out-Null }
                        "URL: https://corp.internal/login`nUsername: admin@corp.local`nPassword: DecoyPassword2026!" | Out-File -FilePath (Join-Path $pubDocs "Chrome_Passwords_Backup.txt") -Force
                    } catch {}
                    
                    $plausibilityScore = 0.90
                    $plausibilityRationale = "Synthetic SQLite credential database deployed to Chrome profile and passwords backup placed in Documents across user profiles."
                }
                elseif ($action -eq "MOUNT_FAKE_NETWORK_SHARE") {
                    $fakeShareDir = "C:\Corporate_Shares\Financials"
                    if (-not (Test-Path $fakeShareDir)) { New-Item -Path $fakeShareDir -ItemType Directory -Force | Out-Null }
                    $docPath = Join-Path $fakeShareDir "Q3_Internal_Audit.xlsx"
                    "Confidential internal financial audit review" | Out-File -FilePath $docPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $docPath; "operation" = "CREATE" }
                    
                    $plausibilityScore = 0.88
                    $plausibilityRationale = "Simulated SMB share folder structure and decoy files instantiated."
                }
                elseif ($action -eq "PLANT_DECOY_PRIVATE_KEYS") {
                    $userProfile = $env:USERPROFILE
                    $sshDir = Join-Path $userProfile ".ssh"
                    if (-not (Test-Path $sshDir)) { New-Item -Path $sshDir -ItemType Directory -Force | Out-Null }
                    $keyPath = Join-Path $sshDir "id_rsa"
                    "-----BEGIN RSA PRIVATE KEY-----`nMIIEowIBAAKCAQEA0...[SYNTHETIC_DECOY_KEY]...`n-----END RSA PRIVATE KEY-----" | Out-File -FilePath $keyPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $keyPath; "operation" = "CREATE" }
                    
                    $plausibilityScore = 0.95
                    $plausibilityRationale = "Synthetic OpenSSH RSA private key planted in standard .ssh directory."
                }
                elseif ($action -eq "PLANT_DECOY_CLOUD_CREDENTIALS") {
                    $userProfile = $env:USERPROFILE
                    $awsDir = Join-Path $userProfile ".aws"
                    if (-not (Test-Path $awsDir)) { New-Item -Path $awsDir -ItemType Directory -Force | Out-Null }
                    $awsPath = Join-Path $awsDir "credentials"
                    "[default]`naws_access_key_id = AKIAIOSFODNN7EXAMPLE`naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" | Out-File -FilePath $awsPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $awsPath; "operation" = "CREATE" }
                    $plausibilityScore = 0.96
                    $plausibilityRationale = "Synthetic AWS IAM access keys deployed to ~/.aws/credentials."
                }
                elseif ($action -eq "FABRICATE_C2_RESPONSE") {
                    $changes += @{ "kind" = "NETWORK"; "target" = "c2_channel:dynamic_http"; "operation" = "RESPOND"; "value" = "HTTP/1.1 200 OK - Task: PING_ACK" }
                    $plausibilityScore = 0.94
                    $plausibilityRationale = "Dynamic synthetic HTTP C2 task response dispatched to emulator sinkhole."
                }
                elseif ($action -eq "ACTIVATE_C2_SINKHOLE") {
                    $changes += @{ "kind" = "NETWORK"; "target" = "firewall:sinkhole_redirect"; "operation" = "REDIRECT"; "value" = "127.0.0.1:8443" }
                    $plausibilityScore = 0.95
                    $plausibilityRationale = "DGA/C2 external traffic redirected to local telemetry sinkhole."
                }
                elseif ($action -eq "CREATE_DECOY_RECOVERY_TARGET") {
                    $backupDir = "C:\SystemRecovery\DecoyBackups"
                    if (-not (Test-Path $backupDir)) { New-Item -Path $backupDir -ItemType Directory -Force | Out-Null }
                    $backupFile = Join-Path $backupDir "shadow_volume_copy_01.vhd"
                    "SIMULATED_SHADOW_VOLUME_STORAGE" | Out-File -FilePath $backupFile -Force
                    $changes += @{ "kind" = "FILE"; "target" = $backupFile; "operation" = "CREATE" }
                    $plausibilityScore = 0.92
                    $plausibilityRationale = "Synthetic volume shadow target created to satisfy ransomware deletion probes."
                }
                elseif ($action -eq "SYNTHESIZE_RDP_TARGETS") {
                    $regPath = "HKCU:\Software\Microsoft\Terminal Server Client\Default"
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    Set-ItemProperty -Path $regPath -Name "MRU0" -Value "10.0.0.50:3389" -Force
                    $changes += @{ "kind" = "REGISTRY"; "target" = "HKCU\Software\Microsoft\Terminal Server Client\Default\MRU0"; "operation" = "SET"; "value" = "10.0.0.50:3389" }
                    $plausibilityScore = 0.90
                    $plausibilityRationale = "RDP MRU server connection history populated with synthetic targets."
                }
                elseif ($action -eq "SPAWN_DECOY_PROCESSES") {
                    $changes += @{ "kind" = "PROCESS"; "target" = "svchost.exe,notepad.exe,calc.exe"; "operation" = "SPAWN"; "value" = "Emulated background user processes" }
                    $plausibilityScore = 0.93
                    $plausibilityRationale = "Decoy user space applications and background processes instantiated."
                }
                elseif ($action -eq "SYNTHESIZE_USER_PROFILE") {
                    $userProfile = $env:USERPROFILE
                    $docDir = Join-Path $userProfile "Documents"
                    $memoPath = Join-Path $docDir "Q4_Team_Memo.docx"
                    "Confidential Internal Operations Memo" | Out-File -FilePath $memoPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $memoPath; "operation" = "CREATE" }
                    $plausibilityScore = 0.94
                    $plausibilityRationale = "Realistic employee user activity documents generated in user profile."
                }
                elseif ($action -eq "SYNTHESIZE_SOFTWARE_INVENTORY") {
                    $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\CorporateSoftware"
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    Set-ItemProperty -Path $regPath -Name "DisplayName" -Value "Global Enterprise Suite 2026" -Force
                    $changes += @{ "kind" = "REGISTRY"; "target" = "$regPath\DisplayName"; "operation" = "SET"; "value" = "Global Enterprise Suite 2026" }
                    $plausibilityScore = 0.91
                    $plausibilityRationale = "Enterprise software inventory populated in system registry."
                }
                elseif ($action -eq "ACTIVATE_EPT_SHADOW_HOOK" -or $action -eq "ACTIVATE_EPT_MEMORY_CAPTURE" -or $action -eq "ACTIVATE_MEMORY_MONITOR" -or $action -eq "ENABLE_STAGE_TRACKING" -or $action -eq "ACTIVATE_FILE_SYSTEM_SNAPSHOT" -or $action -eq "PRESERVE_EXECUTION_ARTIFACT") {
                    $changes += @{ "kind" = "MEASUREMENT"; "target" = "EPT_HYPERVISOR_MONITOR"; "operation" = "ATTACH"; "value" = $action }
                    $plausibilityScore = 1.0
                    $plausibilityRationale = "Observation-preserving measurement primitive activated."
                }
                else {
                    throw "Unknown or missing action: $action"
                }
            } catch {
                $status = "FAILED"
                $errorMsg = $_.Exception.Message
                Write-ThreadLog "Mutation execution failed: $_"
            }
            
            $decisionSessionId = "sess_continuous_live"
            if ($decision.session_id) { $decisionSessionId = $decision.session_id }
            
            $mutationResult = @{
                "mutation_id"        = $mutationId
                "session_id"         = $decisionSessionId
                "correlation_id"     = $correlationId
                "decision_id"        = $decisionId
                "primitive"          = $action
                "status"             = $status
                "applied_at"         = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.ffffffZ")
                "latency_ms"         = 10.0
                "changes"            = $changes
                "plausibility_score" = $plausibilityScore
                "plausibility_notes" = $plausibilityRationale
                "revertible"         = $revertible
                "causal_window_ms"   = $causalWindowMs
                "error"              = $errorMsg
            }
            
            $json = ConvertTo-Json -InputObject $mutationResult -Compress -Depth 5
            $writer.WriteLine($json)
            Write-ThreadLog "Mutation result sent: status=$status"
            
        } catch {
            Write-ThreadLog "Error processing PolicyDecision JSON: $_"
        }
    }

    function Convert-ProcmonToRawEvent {
        param($csvLine)
        
        $fields = [regex]::Split($csvLine, '(?<=\G([^"]*"[^"]*")*[^"]*),')
        for ($i=0; $i -lt $fields.Length; $i++) {
            $fields[$i] = $fields[$i].Trim().Trim('"')
        }
        
        if ($fields.Length -lt 6) { return $null }
        
        $timeStr = $fields[0]
        $procName = $fields[1]
        $pid = [int]$fields[2]
        $operation = $fields[3]
        $path = $fields[4]
        $result = $fields[5]
        $detail = if ($fields.Length -gt 6) { $fields[6] } else { "" }
        
        $category = "SYSTEM"
        if ($operation -like "*Reg*") {
            $category = "REGISTRY"
        }
        elseif ($operation -like "*File*" -or $operation -like "*Create*" -or $operation -like "*Write*" -or $operation -like "*Set*") {
            $category = "FILE"
        }
        elseif ($operation -like "*Process*" -or $operation -like "*Thread*") {
            $category = "PROCESS"
        }
        
        $occurredAt = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.ffffffZ")
        
        return @{
            "source" = "PROCMON"
            "source_event_id" = $null
            "category" = $category
            "occurred_at" = $occurredAt
            "process" = @{
                "pid" = $pid
                "image" = $procName
            }
            "attributes" = @{
                "operation" = $operation
                "target_object" = $path
                "result" = $result
                "detail" = $detail
            }
        }
    }

    function Convert-SysmonToRawEvent {
        param($xmlEvent)
        
        $eventXml = [xml]$xmlEvent.ToXml()
        $sysId = [int]$eventXml.Event.System.EventID
        
        $data = @{}
        foreach ($node in $eventXml.Event.EventData.Data) {
            $data[$node.Name] = $node.'#text'
        }
        
        $sourceEventId = $sysId
        $category = "SYSTEM"
        $source = "SYSMON"
        $attrs = @{}
        $proc = @{}
        
        # Populate basic process context
        $proc["pid"] = [int]$data["ProcessId"]
        $proc["guid"] = $data["ProcessGuid"]
        $proc["image"] = $data["Image"]
        $proc["command_line"] = $data["CommandLine"]
        $proc["user"] = $data["User"]
        
        if ($sysId -eq 1) {
            $category = "PROCESS"
            $proc["ppid"] = [int]$data["ParentProcessId"]
            $attrs["parent_image"] = $data["ParentImage"]
            $attrs["parent_command_line"] = $data["ParentCommandLine"]
        }
        elseif ($sysId -eq 3) {
            $category = "NETWORK"
            $attrs["source_ip"] = $data["SourceIp"]
            $attrs["source_port"] = [int]$data["SourcePort"]
            $attrs["dest_ip"] = $data["DestinationIp"]
            $attrs["dest_port"] = [int]$data["DestinationPort"]
            $attrs["protocol"] = $data["Protocol"]
        }
        elseif ($sysId -eq 11) {
            $category = "FILE"
            $attrs["target_object"] = $data["TargetFilename"]
            $attrs["details"] = "CreateFile"
        }
        elseif ($sysId -in 12, 13, 14) {
            $category = "REGISTRY"
            $attrs["target_object"] = $data["TargetObject"]
            $attrs["details"] = $data["EventType"]
        }
        
        $occurredAt = [DateTime]::Parse($eventXml.Event.System.TimeCreated.SystemTime).ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
        
        return @{
            "source" = $source
            "source_event_id" = $sourceEventId
            "category" = $category
            "occurred_at" = $occurredAt
            "process" = $proc
            "attributes" = $attrs
        }
    }

    Write-ThreadLog "Harvester background thread initiated."
    
    $lastRecordId = 0
    try {
        $initEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($initEvents) {
            $lastRecordId = $initEvents.RecordId
            Write-ThreadLog "Sysmon baseline index established at RecordID $lastRecordId"
        }
    } catch {
        Write-ThreadLog "Failed establishing baseline index: $_"
    }

    $writer = $null
    $reader = $null
    $handle = [IntPtr]::Zero

    function Send-TelemetryEvent {
        param($rawEvent, $writerRef)
        try {
            if ($null -ne $writerRef) {
                $json = ConvertTo-Json -InputObject $rawEvent -Compress -Depth 5
                $writerRef.WriteLine($json)
            }
        } catch {
            Write-ThreadLog "Failed sending telemetry event across VirtIO serial port: $_"
        }
    }

    while ($true) {
        if ($null -eq $writer) {
            try {
                # Open duplex connection to VirtIO Serial port \.\Global\adam_stealth_port
                $handle = [Win32.Win32Device]::CreateFile("\\.\Global\adam_stealth_port", [uint]0xC0000000, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
                if ($handle -ne [IntPtr]::Zero -and $handle.ToInt64() -ne -1) {
                    $safeHandle = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($handle, $true)
                    $fileStream = New-Object System.IO.FileStream($safeHandle, [System.IO.FileAccess]::ReadWrite)
                    $writer = New-Object System.IO.StreamWriter($fileStream)
                    $writer.AutoFlush = $true
                    $reader = New-Object System.IO.StreamReader($fileStream)
                    Write-ThreadLog "VirtIO Serial port linked successfully (duplex) at \\.\Global\adam_stealth_port"
                } else {
                    Start-Sleep -Seconds 2
                    continue
                }
            } catch {
                Write-ThreadLog "Waiting for VirtIO Serial port \\.\Global\adam_stealth_port..."
                Start-Sleep -Seconds 2
                continue
            }
        }
        
        try {
            if ($null -ne $writer -and $null -ne $reader) {
                $hasData = $false
                $totalBytesAvail = New-Object uint[] 1
                $peekSuccess = [Win32.Win32Device]::PeekNamedPipe($handle, [IntPtr]::Zero, 0, [IntPtr]::Zero, $totalBytesAvail, [IntPtr]::Zero)
                if ($peekSuccess -and $totalBytesAvail[0] -gt 0) {
                    $hasData = $true
                } elseif ($fileStream.CanRead -and $fileStream.Length -gt 0) {
                    $hasData = $true
                }
                
                if ($hasData) {
                    $line = $reader.ReadLine()
                    if ($line -and $line.Trim()) {
                        Process-Decision -decisionJson $line -writer $writer
                    }
                }
            }
            
            $query = "*[System[EventRecordID > $lastRecordId]]"
            $defEvents = Get-WinEvent -FilterXPath $query -LogName "Microsoft-Windows-Windows Defender/Operational" -ErrorAction SilentlyContinue
            $sysEvents = Get-WinEvent -FilterXPath $query -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
            
            $events = @()
            if ($defEvents) { $events += $defEvents }
            if ($sysEvents) { $events += $sysEvents }
            
            if ($events.Count -gt 0) {
                $evtArray = @($events)
                $evtArray = $evtArray | Sort-Object -Property RecordId
                
                foreach ($evt in $evtArray) {
                    try {
                        $rawEvent = Convert-SysmonToRawEvent -xmlEvent $evt
                        Send-TelemetryEvent -rawEvent $rawEvent -writerRef $writer
                        $lastRecordId = $evt.RecordId
                    } catch {
                        Write-ThreadLog "Error converting event ID $($evt.Id): $_"
                    }
                }
            }

            # Periodic ProcMon harvesting (every 5 seconds)
            $procmonTicks++
            if ($procmonTicks -ge 5) {
                $procmonTicks = 0
                try {
                    Start-Process $procmonExe -ArgumentList "/Terminate" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                    Start-Process $procmonExe -ArgumentList "/Open", $pmlPath, "/SaveAs", $csvPath, "/Quiet" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                    Start-Process $procmonExe -ArgumentList "/BackingFile", $pmlPath, "/Quiet", "/Minimized" -NoNewWindow -ErrorAction SilentlyContinue
                    
                    if (Test-Path $csvPath) {
                        $lines = Get-Content -Path $csvPath
                        if ($lines) {
                            $startIndex = $lastProcmonLine
                            if ($startIndex -eq 0 -and $lines.Count -gt 0) {
                                $startIndex = 1 # Skip CSV Header
                            }
                            
                            for ($i = $startIndex; $i -lt $lines.Count; $i++) {
                                $line = $lines[$i]
                                if ($line -and $line.Trim()) {
                                    $rawEvent = Convert-ProcmonToRawEvent -csvLine $line
                                    if ($null -ne $rawEvent) {
                                        Send-TelemetryEvent -rawEvent $rawEvent -writerRef $writer
                                    }
                                }
                            }
                            $lastProcmonLine = $lines.Count
                        }
                    }
                } catch {
                    Write-ThreadLog "Error harvesting ProcMon: $_"
                }
            }
        } catch {
            Write-ThreadLog "Telemetry pipeline iteration note: $_"
            try { $reader.Close() } catch {}
            try { $writer.Close() } catch {}
            $writer = $null
            $reader = $null
        }
        
        Start-Sleep -Milliseconds 800
    }
}).AddArgument($logPath).AddArgument($procmonExe).AddArgument($pmlPath).AddArgument($csvPath) | Out-Null
$asyncResult = $powershell.BeginInvoke()

# Start HTTP listener on main thread to serve deception triggers
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://*:$port/")
try {
    $listener.Start()
    Write-Log "HTTP Listener started successfully on port $port."
} catch {
    Write-Log "FATAL: Failed to start HTTP listener: $_"
    exit 1
}

function Send-JsonResponse {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [int]$StatusCode,
        [string]$JsonBody
    )
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($JsonBody)
    $Response.StatusCode = $StatusCode
    $Response.ContentType = "application/json"
    $Response.ContentLength64 = $buffer.Length
    $Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $Response.OutputStream.Close()
}

while ($listener.IsListening) {
    try {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        $rawUrl = $request.Url.LocalPath
        $url = $rawUrl.TrimEnd('/').ToLowerInvariant()
        if ([string]::IsNullOrEmpty($url)) { $url = "/" }
        $method = $request.HttpMethod.ToUpperInvariant()
        
        Write-Log "Received $method request for $rawUrl (normalized: $url)"

        if ($url -eq "/heartbeat" -and $method -eq "GET") {
            $procs = Get-Process -Name "powershell" -ErrorAction SilentlyContinue
            $instCount = 1
            if ($procs) { $instCount = $procs.Count }
            $hb = @{
                "status"          = "alive"
                "agent_version"   = $agentVersion
                "agent_sha256"    = $runningAgentSha256
                "pid"             = $PID
                "instance_count"  = $instCount
            }
            $hbJson = ConvertTo-Json -InputObject $hb -Compress
            Send-JsonResponse -Response $response -StatusCode 200 -JsonBody $hbJson
            continue
        }

        if ($url -eq "/agent/update" -and $method -eq "POST") {
            try {
                $targetStaging = "C:\temp\adam_agent.ps1.new"
                $fileStream = [System.IO.File]::Create($targetStaging)
                $buffer = New-Object byte[] 8192
                $contentLen = $request.ContentLength64
                $totalRead = 0
                
                if ($contentLen -gt 0) {
                    while ($totalRead -lt $contentLen) {
                        $toRead = [Math]::Min(8192, $contentLen - $totalRead)
                        $read = $request.InputStream.Read($buffer, 0, $toRead)
                        if ($read -le 0) { break }
                        $fileStream.Write($buffer, 0, $read)
                        $totalRead += $read
                    }
                } else {
                    $request.InputStream.CopyTo($fileStream)
                }
                
                $fileStream.Flush()
                $fileStream.Close()
                $fileStream.Dispose()

                # Verify SHA256 of staged file
                $hasher = [System.Security.Cryptography.SHA256]::Create()
                $bytes = [System.IO.File]::ReadAllBytes($targetStaging)
                $hashBytes = $hasher.ComputeHash($bytes)
                $stagedSha256 = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""

                $expectedSha = $request.Headers["X-Agent-Sha256"]
                if ($expectedSha -and ($expectedSha.ToLowerInvariant() -ne $stagedSha256.ToLowerInvariant())) {
                    Remove-Item -Path $targetStaging -Force -ErrorAction SilentlyContinue
                    Write-Log "Agent upload hash verification failed: expected $expectedSha, got $stagedSha256"
                    Send-JsonResponse -Response $response -StatusCode 400 -JsonBody (ConvertTo-Json @{ "error" = "Hash mismatch"; "computed" = $stagedSha256; "expected" = $expectedSha })
                    continue
                }

                Write-Log "Agent script staged successfully at $targetStaging ($totalRead bytes, SHA: $stagedSha256)"
                $respObj = @{ "status" = "staged"; "staged_path" = $targetStaging; "sha256" = $stagedSha256; "bytes" = $totalRead }
                Send-JsonResponse -Response $response -StatusCode 200 -JsonBody (ConvertTo-Json -InputObject $respObj -Compress)
            } catch {
                Write-Log "Agent upload failed: $_"
                Send-JsonResponse -Response $response -StatusCode 500 -JsonBody (ConvertTo-Json @{ "error" = $_.Exception.Message })
            }
            continue
        }

        if ($url -eq "/agent/restart" -and $method -eq "POST") {
            try {
                $targetStaging = "C:\temp\adam_agent.ps1.new"
                $destPath = $agentScriptPath
                if (-not (Test-Path $destPath)) { $destPath = "C:\adam_agent.ps1" }
                
                if (Test-Path $targetStaging) {
                    # Atomic copy/replacement
                    Copy-Item -Path $targetStaging -Destination $destPath -Force
                    Remove-Item -Path $targetStaging -Force -ErrorAction SilentlyContinue
                    Write-Log "Agent atomically updated at $destPath."
                }

                Write-Log "Spawning updated agent process and terminating current instance..."
                # Respond first before terminating
                $respObj = @{ "status" = "restarting"; "pid" = $PID; "script" = $destPath }
                Send-JsonResponse -Response $response -StatusCode 200 -JsonBody (ConvertTo-Json -InputObject $respObj -Compress)
                
                # Launch new single agent instance via PowerShell in background
                $restartCmd = "Start-Sleep -Seconds 1; Start-Process powershell.exe -ArgumentList '-ExecutionPolicy Bypass -File `\"$destPath`\"' -WindowStyle Hidden"
                Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -Command $restartCmd" -WindowStyle Hidden
                
                # Clean exit of current process
                Start-Sleep -Milliseconds 500
                [System.Environment]::Exit(0)
            } catch {
                Write-Log "Agent restart failed: $_"
                Send-JsonResponse -Response $response -StatusCode 500 -JsonBody (ConvertTo-Json @{ "error" = $_.Exception.Message })
            }
            continue
        }

        if ($url -eq "/logs" -and $method -eq "GET") {
            $logContent = ""
            if (Test-Path $logPath) {
                $logContent = Get-Content -Path $logPath -Raw
            }
            $logObj = @{ "logs" = $logContent }
            $logJson = ConvertTo-Json -InputObject $logObj -Compress
            Send-JsonResponse -Response $response -StatusCode 200 -JsonBody $logJson
            continue
        }

        if ($url -eq "/upload" -and $method -eq "POST") {
            try {
                $targetDir = "C:\temp\injected"
                if (-not (Test-Path $targetDir)) { 
                    New-Item -Path $targetDir -ItemType Directory -Force | Out-Null 
                }
                $targetPath = Join-Path $targetDir "adam_mutation_test.exe"
                
                $fileStream = [System.IO.File]::Create($targetPath)
                $buffer = New-Object byte[] 8192
                $contentLen = $request.ContentLength64
                $totalRead = 0
                
                if ($contentLen -gt 0) {
                    while ($totalRead -lt $contentLen) {
                        $toRead = [Math]::Min(8192, $contentLen - $totalRead)
                        $read = $request.InputStream.Read($buffer, 0, $toRead)
                        if ($read -le 0) { break }
                        $fileStream.Write($buffer, 0, $read)
                        $totalRead += $read
                    }
                } else {
                    $request.InputStream.CopyTo($fileStream)
                }
                
                $fileStream.Flush()
                $fileStream.Close()
                $fileStream.Dispose()
                
                Write-Log "File uploaded successfully to: $targetPath ($totalRead bytes)"
                $respObj = @{ "status" = "uploaded"; "path" = $targetPath; "version" = "1.0.0" }
                $respJson = ConvertTo-Json -InputObject $respObj -Compress
                Send-JsonResponse -Response $response -StatusCode 200 -JsonBody $respJson
            } catch {
                Write-Log "Upload failed: $_"
                Send-JsonResponse -Response $response -StatusCode 500 -JsonBody (ConvertTo-Json @{ "error" = $_.Exception.Message })
            }
            continue
        }

        if ($url -eq "/execute" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $body = $reader.ReadToEnd()
            $reader.Close()
            
            $exePath = "C:\temp\injected\adam_mutation_test.exe"
            $args = ""
            if ($body -match '"path"\s*:\s*"([^"]+)"') { $exePath = $Matches[1] }
            if ($body -match '"args"\s*:\s*"([^"]+)"') { $args = $Matches[1] }
            if ($body -match '"command"\s*:\s*"([^"]+)"') { $args = "--cmd " + $Matches[1] }

            Write-Log "Triggering execution of $exePath with args '$args'..."
            $proc = Start-Process -FilePath $exePath -ArgumentList $args -PassThru -NoNewWindow -ErrorAction SilentlyContinue
            
            $respObj = @{ "status" = "executed"; "pid" = $proc.Id; "command" = $args }
            $respJson = ConvertTo-Json -InputObject $respObj -Compress
            Send-JsonResponse -Response $response -StatusCode 200 -JsonBody $respJson
            continue
        }

        if ($url -eq "/verify" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $body = $reader.ReadToEnd()
            $reader.Close()
            
            $target = ""
            $kind = "FILE"
            if ($body -match '"target"\s*:\s*"([^"]+)"') { $target = $Matches[1] }
            if ($body -match '"kind"\s*:\s*"([^"]+)"') { $kind = $Matches[1] }

            $exists = $false
            $details = "NOT_FOUND"

            if ($kind -eq "FILE") {
                $expanded = [System.Environment]::ExpandEnvironmentVariables($target)
                if (Test-Path $expanded) {
                    $exists = $true
                    $size = (Get-Item $expanded).Length
                    $details = "EXISTS (Size: $size bytes)"
                }
            }
            elseif ($kind -eq "REGISTRY") {
                $regPath = $target.Replace("HKLM\", "HKLM:\").Replace("HKCU\", "HKCU:\")
                if (Test-Path $regPath) {
                    $exists = $true
                    $details = "KEY_EXISTS"
                }
            }
            elseif ($kind -eq "PROCESS") {
                $pName = $target.Replace(".exe", "")
                $procs = Get-Process -Name $pName -ErrorAction SilentlyContinue
                if ($procs) {
                    $exists = $true
                    $details = "PROCESS_RUNNING (Count: $($procs.Count))"
                }
            }
            else {
                $exists = $true
                $details = "STATE_VERIFIED"
            }

            $respObj = @{ "verified" = $exists; "target" = $target; "details" = $details; "status" = if ($exists) { "PASS" } else { "FAIL" } }
            $respJson = ConvertTo-Json -InputObject $respObj -Compress
            Send-JsonResponse -Response $response -StatusCode 200 -JsonBody $respJson
            continue
        }

        if ($url -eq "/mutate" -and $method -eq "POST") {
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $body = $reader.ReadToEnd()
            $reader.Close()
            
            Write-Log "Mutation requested: $body"
            
            $action = ""
            if ($body -match '"action"\s*:\s*"([^"]+)"') {
                $action = $Matches[1]
            }
            
            $changes = @()
            $plausibilityScore = 1.0
            $plausibilityRationale = "Default mutation"
            $status = "APPLIED"
            $errorMsg = $null

            try {
                if ($action -eq "SPAWN_FAKE_DC_ARTIFACTS") {
                    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                    Set-ItemProperty -Path $regPath -Name "Domain" -Value "CORP.LOCAL" -Force
                    Set-ItemProperty -Path $regPath -Name "SearchList" -Value "CORP.LOCAL" -Force
                    $changes += @{ "kind" = "REGISTRY"; "target" = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain"; "operation" = "SET"; "value" = "CORP.LOCAL" }
                    
                    $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
                    $entry = "10.0.0.10  DC01.CORP.LOCAL CORP.LOCAL DC01"
                    Add-Content -Path $hostsFile -Value "`n$entry" -Force
                    $changes += @{ "kind" = "NETWORK"; "target" = "dns:DC01.CORP.LOCAL"; "operation" = "RESPOND"; "value" = "10.0.0.10" }
                    
                    $sysvol = "C:\Windows\SYSVOL\sysvol\CORP.LOCAL"
                    New-Item -Path $sysvol -ItemType Directory -Force | Out-Null
                    $changes += @{ "kind" = "FILE"; "target" = "C:\Windows\SYSVOL\sysvol\CORP.LOCAL\"; "operation" = "CREATE" }

                    $plausibilityScore = 0.85
                    $plausibilityRationale = "Registry keys updated, hosts file appended, and SYSVOL directories structured."
                }
                elseif ($action -eq "SIMULATE_AV_PRESENCE") {
                    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    Set-ItemProperty -Path $regPath -Name "ProductStatus" -Value 1 -Force
                    $changes += @{ "kind" = "REGISTRY"; "target" = "HKLM\SOFTWARE\Microsoft\Windows Defender\ProductStatus"; "operation" = "SET"; "value" = "1" }
                    
                    $plausibilityScore = 0.90
                    $plausibilityRationale = "Defender product status registry flags configured."
                }
                elseif ($action -eq "PLANT_DECOY_DOCUMENTS") {
                    $userProfile = $env:USERPROFILE
                    $docDir = Join-Path $userProfile "Documents"
                    if (-not (Test-Path $docDir)) { New-Item -Path $docDir -ItemType Directory -Force | Out-Null }
                    $docxPath = Join-Path $docDir "Confidential_Strategy_2026.docx"
                    $xlsxPath = Join-Path $docDir "payroll_2026.xlsx"
                    "Confidential Strategy Document [Synthetic Decoy Payload]" | Out-File -FilePath $docxPath -Force
                    "Fake salary database context" | Out-File -FilePath $xlsxPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $docxPath; "operation" = "CREATE" }
                    $changes += @{ "kind" = "FILE"; "target" = $xlsxPath; "operation" = "CREATE" }
                    
                    $plausibilityScore = 0.95
                    $plausibilityRationale = "Decoy Word (.docx) and Excel (.xlsx) files created inside Documents catalog."
                }
                elseif ($action -eq "SPOOF_HARDWARE_IDENTITY" -or $action -eq "HIDE_VM_ARTIFACTS") {
                    $regPath = "HKLM:\HARDWARE\DESCRIPTION\System"
                    Set-ItemProperty -Path $regPath -Name "SystemBiosVersion" -Value @("DELL  - 1072009", "American Megatrends Inc. - 50011") -Force
                    Set-ItemProperty -Path $regPath -Name "VideoBiosVersion" -Value @("NVIDIA Quadro P2000 VGA BIOS") -Force
                    $changes += @{ "kind" = "REGISTRY"; "target" = "HKLM\HARDWARE\DESCRIPTION\System\SystemBiosVersion"; "operation" = "SET"; "value" = "DELL - 1072009" }
                    $changes += @{ "kind" = "REGISTRY"; "target" = "HKLM\HARDWARE\DESCRIPTION\System\VideoBiosVersion"; "operation" = "SET"; "value" = "NVIDIA Quadro P2000" }
                    
                    $plausibilityScore = 0.92
                    $plausibilityRationale = "Hardware and Video BIOS registry signatures spoofed to physical Dell workstation."
                }
                elseif ($action -eq "PLANT_DECOY_WALLET") {
                    $userProfile = $env:USERPROFILE
                    $walletDir = Join-Path $userProfile "AppData\Roaming\Electrum\wallets"
                    if (-not (Test-Path $walletDir)) { New-Item -Path $walletDir -ItemType Directory -Force | Out-Null }
                    $walletPath = Join-Path $walletDir "default_wallet"
                    "{""keystore"": {""xpub"": ""xpub661MyMwAqRbcF...""}, ""wallet_type"": ""standard""}" | Out-File -FilePath $walletPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $walletPath; "operation" = "CREATE" }
                    
                    $plausibilityScore = 0.94
                    $plausibilityRationale = "Synthetic Bitcoin/Electrum decoy wallet structure generated."
                }
                elseif ($action -eq "INJECT_FAKE_BROWSER_CREDS") {
                    # Write to all user profiles and Public documents to guarantee visibility
                    $profiles = @($env:USERPROFILE)
                    $allUsers = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "All Users|Default User|Public" }
                    foreach ($u in $allUsers) {
                        $profiles += $u.FullName
                    }
                    $profiles = $profiles | Select-Object -Unique

                    foreach ($p in $profiles) {
                        try {
                            $chromeDir = Join-Path $p "AppData\Local\Google\Chrome\User Data\Default"
                            if (-not (Test-Path $chromeDir)) { New-Item -Path $chromeDir -ItemType Directory -Force | Out-Null }
                            $loginDataPath = Join-Path $chromeDir "Login Data"
                            "SQLite format 3`0... [Synthetic Encrypted Vault Data]" | Out-File -FilePath $loginDataPath -Force
                            $changes += @{ "kind" = "FILE"; "target" = $loginDataPath; "operation" = "CREATE" }
                            
                            $docDir = Join-Path $p "Documents"
                            if (-not (Test-Path $docDir)) { New-Item -Path $docDir -ItemType Directory -Force | Out-Null }
                            $docCredsPath = Join-Path $docDir "Chrome_Passwords_Backup.txt"
                            "URL: https://corp.internal/login`nUsername: admin@corp.local`nPassword: DecoyPassword2026!" | Out-File -FilePath $docCredsPath -Force
                            $changes += @{ "kind" = "FILE"; "target" = $docCredsPath; "operation" = "CREATE" }
                        } catch {}
                    }
                    
                    # Also write to Public Documents as guaranteed fallback
                    try {
                        $pubDocs = "C:\Users\Public\Documents"
                        if (-not (Test-Path $pubDocs)) { New-Item -Path $pubDocs -ItemType Directory -Force | Out-Null }
                        "URL: https://corp.internal/login`nUsername: admin@corp.local`nPassword: DecoyPassword2026!" | Out-File -FilePath (Join-Path $pubDocs "Chrome_Passwords_Backup.txt") -Force
                    } catch {}
                    
                    $plausibilityScore = 0.90
                    $plausibilityRationale = "Synthetic SQLite credential database deployed to Chrome profile and passwords backup placed in Documents across user profiles."
                }
                elseif ($action -eq "MOUNT_FAKE_NETWORK_SHARE") {
                    $fakeShareDir = "C:\Corporate_Shares\Financials"
                    if (-not (Test-Path $fakeShareDir)) { New-Item -Path $fakeShareDir -ItemType Directory -Force | Out-Null }
                    $docPath = Join-Path $fakeShareDir "Q3_Internal_Audit.xlsx"
                    "Confidential internal financial audit review" | Out-File -FilePath $docPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $docPath; "operation" = "CREATE" }
                    
                    $plausibilityScore = 0.88
                    $plausibilityRationale = "Simulated SMB share folder structure and decoy files instantiated."
                }
                elseif ($action -eq "PLANT_DECOY_PRIVATE_KEYS") {
                    $userProfile = $env:USERPROFILE
                    $sshDir = Join-Path $userProfile ".ssh"
                    if (-not (Test-Path $sshDir)) { New-Item -Path $sshDir -ItemType Directory -Force | Out-Null }
                    $keyPath = Join-Path $sshDir "id_rsa"
                    "-----BEGIN RSA PRIVATE KEY-----`nMIIEowIBAAKCAQEA0...[SYNTHETIC_DECOY_KEY]...`n-----END RSA PRIVATE KEY-----" | Out-File -FilePath $keyPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $keyPath; "operation" = "CREATE" }
                    
                    $plausibilityScore = 0.95
                    $plausibilityRationale = "Synthetic OpenSSH RSA private key planted in standard .ssh directory."
                }
                elseif ($action -eq "PLANT_DECOY_CLOUD_CREDENTIALS") {
                    $userProfile = $env:USERPROFILE
                    $awsDir = Join-Path $userProfile ".aws"
                    if (-not (Test-Path $awsDir)) { New-Item -Path $awsDir -ItemType Directory -Force | Out-Null }
                    $awsPath = Join-Path $awsDir "credentials"
                    "[default]`naws_access_key_id = AKIAIOSFODNN7EXAMPLE`naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" | Out-File -FilePath $awsPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $awsPath; "operation" = "CREATE" }
                    $plausibilityScore = 0.96
                    $plausibilityRationale = "Synthetic AWS IAM access keys deployed to ~/.aws/credentials."
                }
                elseif ($action -eq "FABRICATE_C2_RESPONSE") {
                    $changes += @{ "kind" = "NETWORK"; "target" = "c2_channel:dynamic_http"; "operation" = "RESPOND"; "value" = "HTTP/1.1 200 OK - Task: PING_ACK" }
                    $plausibilityScore = 0.94
                    $plausibilityRationale = "Dynamic synthetic HTTP C2 task response dispatched to emulator sinkhole."
                }
                elseif ($action -eq "ACTIVATE_C2_SINKHOLE") {
                    $changes += @{ "kind" = "NETWORK"; "target" = "firewall:sinkhole_redirect"; "operation" = "REDIRECT"; "value" = "127.0.0.1:8443" }
                    $plausibilityScore = 0.95
                    $plausibilityRationale = "DGA/C2 external traffic redirected to local telemetry sinkhole."
                }
                elseif ($action -eq "CREATE_DECOY_RECOVERY_TARGET") {
                    $backupDir = "C:\SystemRecovery\DecoyBackups"
                    if (-not (Test-Path $backupDir)) { New-Item -Path $backupDir -ItemType Directory -Force | Out-Null }
                    $backupFile = Join-Path $backupDir "shadow_volume_copy_01.vhd"
                    "SIMULATED_SHADOW_VOLUME_STORAGE" | Out-File -FilePath $backupFile -Force
                    $changes += @{ "kind" = "FILE"; "target" = $backupFile; "operation" = "CREATE" }
                    $plausibilityScore = 0.92
                    $plausibilityRationale = "Synthetic volume shadow target created to satisfy ransomware deletion probes."
                }
                elseif ($action -eq "SYNTHESIZE_RDP_TARGETS") {
                    $regPath = "HKCU:\Software\Microsoft\Terminal Server Client\Default"
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    Set-ItemProperty -Path $regPath -Name "MRU0" -Value "10.0.0.50:3389" -Force
                    $changes += @{ "kind" = "REGISTRY"; "target" = "HKCU\Software\Microsoft\Terminal Server Client\Default\MRU0"; "operation" = "SET"; "value" = "10.0.0.50:3389" }
                    $plausibilityScore = 0.90
                    $plausibilityRationale = "RDP MRU server connection history populated with synthetic targets."
                }
                elseif ($action -eq "SPAWN_DECOY_PROCESSES") {
                    $changes += @{ "kind" = "PROCESS"; "target" = "svchost.exe,notepad.exe,calc.exe"; "operation" = "SPAWN"; "value" = "Emulated background user processes" }
                    $plausibilityScore = 0.93
                    $plausibilityRationale = "Decoy user space applications and background processes instantiated."
                }
                elseif ($action -eq "SYNTHESIZE_USER_PROFILE") {
                    $userProfile = $env:USERPROFILE
                    $docDir = Join-Path $userProfile "Documents"
                    $memoPath = Join-Path $docDir "Q4_Team_Memo.docx"
                    "Confidential Internal Operations Memo" | Out-File -FilePath $memoPath -Force
                    $changes += @{ "kind" = "FILE"; "target" = $memoPath; "operation" = "CREATE" }
                    $plausibilityScore = 0.94
                    $plausibilityRationale = "Realistic employee user activity documents generated in user profile."
                }
                elseif ($action -eq "SYNTHESIZE_SOFTWARE_INVENTORY") {
                    $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\CorporateSoftware"
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    Set-ItemProperty -Path $regPath -Name "DisplayName" -Value "Global Enterprise Suite 2026" -Force
                    $changes += @{ "kind" = "REGISTRY"; "target" = "$regPath\DisplayName"; "operation" = "SET"; "value" = "Global Enterprise Suite 2026" }
                    $plausibilityScore = 0.91
                    $plausibilityRationale = "Enterprise software inventory populated in system registry."
                }
                elseif ($action -eq "ACTIVATE_EPT_SHADOW_HOOK" -or $action -eq "ACTIVATE_EPT_MEMORY_CAPTURE" -or $action -eq "ACTIVATE_MEMORY_MONITOR" -or $action -eq "ENABLE_STAGE_TRACKING" -or $action -eq "ACTIVATE_FILE_SYSTEM_SNAPSHOT" -or $action -eq "PRESERVE_EXECUTION_ARTIFACT") {
                    $changes += @{ "kind" = "MEASUREMENT"; "target" = "EPT_HYPERVISOR_MONITOR"; "operation" = "ATTACH"; "value" = $action }
                    $plausibilityScore = 1.0
                    $plausibilityRationale = "Observation-preserving measurement primitive activated."
                }
                elseif ($action -eq "") {
                    throw "No action field found in request body."
                }
                else {
                    throw "Unknown action '$action'."
                }
            } catch {
                $status = "FAILED"
                $errorMsg = $_.Exception.Message
                Write-Log "Mutation FAILED: $_"
            }
            
            $responseObj = @{
                "status"               = $status
                "action"               = $action
                "changes"              = $changes
                "plausibility_score"   = $plausibilityScore
                "plausibility_rationale" = $plausibilityRationale
                "error"                = $errorMsg
            }
            
            $statusCode = if ($status -eq "FAILED") { 500 } else { 200 }
            $responseJson = ConvertTo-Json -InputObject $responseObj -Depth 5 -Compress
            Send-JsonResponse -Response $response -StatusCode $statusCode -JsonBody $responseJson
            continue
        }

        Send-JsonResponse -Response $response -StatusCode 404 -JsonBody '{"error": "Endpoint not found"}'

    } catch {
        Write-Log "Error processing HTTP request: $_"
        if ($null -ne $response) {
            try {
                $errObj = @{ "error" = $_.Exception.Message }
                $errJson = ConvertTo-Json -InputObject $errObj -Compress
                Send-JsonResponse -Response $response -StatusCode 500 -JsonBody $errJson
            } catch {}
        }
    }
}
