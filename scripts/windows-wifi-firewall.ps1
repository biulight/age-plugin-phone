#requires -Version 5.1
<#
.SYNOPSIS
Inspect, enable, disable, or remove one narrowly scoped Wi-Fi discovery reply rule.
.DESCRIPTION
Run Inspect without elevation. Enable/Disable/Remove require an administrator session.
Use -WhatIf to preview a mutation. No network profile, default policy, or unrelated rule is changed.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Inspect', 'Enable', 'Disable', 'Remove')]
    [string] $Action = 'Inspect',
    [Parameter(Mandatory = $true)]
    [string] $Program,
    [Parameter(Mandatory = $true)]
    [string] $InterfaceAlias
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$group = 'age-plugin-phone scoped Wi-Fi discovery v1'
if ($Program -notmatch '^[A-Za-z]:[\\/]') { throw 'Use an absolute local executable path.' }
if ([string]::IsNullOrWhiteSpace($InterfaceAlias) -or $InterfaceAlias.IndexOfAny([char[]]'*?[]') -ge 0) {
    throw 'Use one exact physical interface alias without wildcard characters.'
}
# GetFullPath also permits inspection/removal after the executable has been moved or deleted.
$programPath = [IO.Path]::GetFullPath($Program)
if ([IO.Path]::GetFileName($programPath) -ine 'age-plugin-phone.exe') {
    throw 'Program must identify the exact age-plugin-phone.exe used by age/ Shine.'
}
if ($programPath.StartsWith('\\')) { throw 'Use a local executable path.' }
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $bytes = [Text.Encoding]::UTF8.GetBytes($programPath.ToLowerInvariant() + "`n" + $InterfaceAlias.ToLowerInvariant())
    $key = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
} finally { $sha.Dispose() }
$name = 'age-plugin-phone-discovery-' + $key
$rules = @(try {
    Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
} catch {
    if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }
})
if ($rules.Count -gt 1) { throw 'Ambiguous rule identity; inspect Windows Firewall manually.' }
if ($rules.Count -eq 1) {
    $rule = $rules[0]
    $app = $rule | Get-NetFirewallApplicationFilter
    $port = $rule | Get-NetFirewallPortFilter
    $address = $rule | Get-NetFirewallAddressFilter
    $iface = $rule | Get-NetFirewallInterfaceFilter
    # Refuse to adopt or mutate a conflicting rule, even when its name happens to match.
    if ($rule.Group -ne $group -or $rule.Direction -ne 'Inbound' -or
        $rule.Action -ne 'Allow' -or $rule.Profile.ToString() -ne 'Private' -or
        $app.Program -ine $programPath -or $port.Protocol -ne 'UDP' -or
        [string]$port.RemotePort -ne '47141' -or [string]$port.LocalPort -ne 'Any' -or
        [string]$address.RemoteAddress -ne 'LocalSubnet' -or
        [string]$address.LocalAddress -ne 'Any' -or
        [string]$iface.InterfaceAlias -ine $InterfaceAlias -or
        $rule.EdgeTraversalPolicy -ne 'Block') {
        throw 'Existing rule differs from the scoped definition; inspect it manually. Nothing changed.'
    }
}

if ($Action -eq 'Inspect') {
    [pscustomobject]@{
        RuleName = $name; Present = ($rules.Count -eq 1)
        Enabled = if ($rules.Count) { $rules[0].Enabled.ToString() } else { 'Absent' }
        Program = $programPath; InterfaceAlias = $InterfaceAlias
        Direction = 'Inbound'; Profile = 'Private'; Protocol = 'UDP'
        RemoteAddress = 'LocalSubnet'; RemotePort = 47141; LocalPort = 'Any (ephemeral query socket)'
    }
    Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory, IPv4Connectivity
    Get-NetFirewallProfile -PolicyStore ActiveStore |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowLocalFirewallRules
    if ($rules.Count) {
        Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction SilentlyContinue |
            Select-Object Name, Enabled, Profile, PrimaryStatus, EnforcementStatus, PolicyStoreSourceType
    }
    return
}

if ($Action -eq 'Enable') {
    if (-not (Test-Path -LiteralPath $programPath -PathType Leaf)) { throw 'Executable does not exist.' }
    $profiles = @(Get-NetConnectionProfile | Where-Object InterfaceAlias -EQ $InterfaceAlias)
    if ($profiles.Count -ne 1 -or $profiles[0].NetworkCategory -ne 'Private') {
        throw 'The selected interface must already be on a trusted Private network. No profile was changed.'
    }
}
if (-not $PSCmdlet.ShouldProcess("$programPath on $InterfaceAlias (Private, LocalSubnet, inbound UDP source 47141)", $Action)) { return }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this mutation in an administrator PowerShell session; Inspect and -WhatIf do not require elevation.'
}
switch ($Action) {
    'Enable' {
        if ($rules.Count) {
            $rules[0] | Enable-NetFirewallRule | Out-Null
        } else {
            New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group $group `
                -Direction Inbound -Action Allow -Enabled True -Profile Private -Program $programPath `
                -InterfaceAlias $InterfaceAlias -Protocol UDP -RemotePort 47141 -LocalPort Any `
                -RemoteAddress LocalSubnet -LocalAddress Any -EdgeTraversalPolicy Block | Out-Null
        }
    }
    'Disable' { if ($rules.Count) { $rules[0] | Disable-NetFirewallRule | Out-Null } }
    'Remove' { if ($rules.Count) { $rules[0] | Remove-NetFirewallRule } }
}
Write-Output "action=$Action result=completed rule=$name"
