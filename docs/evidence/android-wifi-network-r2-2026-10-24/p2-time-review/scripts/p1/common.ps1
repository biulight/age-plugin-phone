$p0 = Join-Path $PSScriptRoot '../windows-minimal-acceptance.ps1'
if (-not (Test-Path $p0)) { $p0 = Join-Path $PSScriptRoot 'windows-minimal-acceptance.ps1' }
. $p0
$script:P1CommonPath = Join-Path $PSScriptRoot 'common.ps1'
$script:P1BasePath = $p0
$script:P1BaseDiagnostic = (Get-Item Function:Get-AcceptanceDiagnostic).ScriptBlock
function Get-AcceptanceDiagnostic {
    param([string]$Diagnostic)
    $known = [ordered]@{
        'no matching foreground Wi-Fi listener was discovered' = 'wifi-discovery-no-match'
        'multiple matching foreground Wi-Fi listeners were discovered' = 'wifi-discovery-ambiguous'
        'local Wi-Fi discovery failed; check network permissions and active interfaces' = 'wifi-discovery-local-error'
        'phone Wi-Fi connection unavailable after discovery' = 'wifi-connect-failed'
        'phone response unavailable or malformed' = 'phone-response-unavailable'
    }
    foreach ($message in $known.Keys) { if ($Diagnostic.Contains($message)) { return $known[$message] } }
    & $script:P1BaseDiagnostic $Diagnostic
}
function Invoke-P1Adb {
    param([string[]]$Arguments)
    $r = Invoke-AcceptanceProcess (Get-Command adb -CommandType Application).Source $Arguments 15
    if ($r.ExitCode -ne 0) { throw 'adb_command_failed' }
    return $r.Output
}
function Assert-P1NoReverse {
    if ((Invoke-P1Adb @('reverse','--list')).Trim().Length -ne 0) { throw 'adb_reverse_residue' }
}
function Get-P1WifiState {
    $enabled = (Invoke-P1Adb @('shell','settings','get','global','wifi_on')).Trim()
    if ($enabled -notin @('0','1')) { throw 'wifi_state_invalid' }
    # An absent wlan0 is valid only after a successful all-interface query.
    $addresses = Invoke-P1Adb @('shell','ip','-o','-4','addr','show')
    $hasAddress = [bool]($addresses -match '(?m)^\d+:\s+wlan0\s+inet\s+\d+\.\d+\.\d+\.\d+/')
    return @{ enabled = ($enabled -eq '1'); ipv4_present = $hasAddress }
}
function Get-P1Provenance {
    param([string]$Driver)
    return @{
        driver_sha256=(Get-FileHash $Driver).Hash.ToLowerInvariant()
        common_sha256=(Get-FileHash $script:P1CommonPath).Hash.ToLowerInvariant()
        base_helper_sha256=(Get-FileHash $script:P1BasePath).Hash.ToLowerInvariant()
    }
}
