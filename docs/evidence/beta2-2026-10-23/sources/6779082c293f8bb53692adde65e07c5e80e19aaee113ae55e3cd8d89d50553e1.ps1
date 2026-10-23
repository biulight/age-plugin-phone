. (Join-Path $PSScriptRoot 'common.ps1')
$d=Join-Path $env:TEMP 'phone-beta2-p1-20261023'
$r=[ordered]@{case='wifi-interface-cycle';started_utc=[DateTime]::UtcNow.ToString('o');result='incomplete';provenance=(Get-P1Provenance $PSCommandPath)}
$restore=$false
try {
    $devices=@((Invoke-P1Adb @('devices')) -split '\r?\n' | Where-Object {$_ -match '^\S+\s+device$'})
    if($devices.Count -ne 1){throw 'device precondition'}
    $before=Get-P1WifiState
    if(-not $before.enabled -or -not $before.ipv4_present){throw 'Wi-Fi precondition'}
    $restore=$true
    $null=Invoke-P1Adb @('shell','cmd','wifi','set-wifi-enabled','disabled')
    $r.disabled_utc=[DateTime]::UtcNow.ToString('o')
    $removed=$false
    for($i=0;$i -lt 10;$i++){
        Start-Sleep -Milliseconds 500
        $state=Get-P1WifiState
        if(-not $state.enabled -and -not $state.ipv4_present){$removed=$true;break}
    }
    if(-not $removed){throw 'interface removal not verified'}
    $r.disabled_and_ipv4_removed=$true
    Start-Sleep -Seconds 5
} catch {$r.failure_category='interface-cycle-check-failed'}
finally {
    $restored=$false
    if($restore){
        try {
            $null=Invoke-P1Adb @('shell','cmd','wifi','set-wifi-enabled','enabled')
            for($i=0;$i -lt 20;$i++){
                Start-Sleep -Milliseconds 500
                $state=Get-P1WifiState
                if($state.enabled -and $state.ipv4_present){$restored=$true;break}
            }
        } catch { $r.restore_failure='wifi_restore_check_failed' }
    }
    $r.wifi_ipv4_restored=$restored
    $r.finished_utc=[DateTime]::UtcNow.ToString('o')
    if($r.Contains('disabled_and_ipv4_removed') -and $r.disabled_and_ipv4_removed -and $restored -and -not $r.Contains('failure_category')){$r.result='passed'}else{$r.result='failed'}
    $r | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $d ('wifi-interface-cycle-'+[Guid]::NewGuid().ToString('N')+'.json'))
}
$r | ConvertTo-Json -Depth 5
if($r.result -ne 'passed'){exit 1}
