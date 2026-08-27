#requires -Version 5.1
<#
.SYNOPSIS
    AgentConfig.psm1 -- loads the guest agent's own local configuration.

.DESCRIPTION
    Guest-side counterpart to adam.common.config.GuestToolsSettings --
    tool paths and defaults that only make sense from inside the guest,
    read from a JSON file next to adam_agent.ps1 (agent.config.json,
    installed by install.ps1) rather than hardcoded, so a re-imaged guest
    with different tool install paths doesn't require editing the script
    itself. Falls back to the same defaults config/default.toml's
    [guest_tools] section documents on the host side, for a fresh guest
    that hasn't had a config file dropped onto it yet.
#>

Set-StrictMode -Version Latest

function Get-AgentConfig {
    param(
        [Parameter(Mandatory = $false)][string]$ConfigPath = (Join-Path $PSScriptRoot '..\agent.config.json')
    )

    $defaults = @{
        ListenPrefix   = 'http://+:8765/'
        AuthToken      = ''
        ProcmonPath    = 'C:\Users\Admin\Downloads\ProcessMonitor\Procmon64.exe'
        TsharkPath     = 'C:\Program Files\Wireshark\tshark.exe'
        SysmonLog      = 'Microsoft-Windows-Sysmon/Operational'
        CaptureDir     = 'C:\ADAM\telemetry'
        SampleDir      = 'C:\ADAM\samples'
    }

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        return $defaults
    }

    try {
        $raw = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $merged = $defaults.Clone()
        foreach ($prop in $raw.PSObject.Properties) {
            $merged[$prop.Name] = $prop.Value
        }
        return $merged
    } catch {
        Write-Output "[WARN] failed to parse $ConfigPath -- using built-in defaults: $($_.Exception.Message)"
        return $defaults
    }
}

Export-ModuleMember -Function Get-AgentConfig
