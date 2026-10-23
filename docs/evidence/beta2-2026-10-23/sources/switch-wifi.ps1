$ErrorActionPreference='Stop'
$d=Join-Path $env:TEMP 'phone-beta2-p1-20261023'
$r=[ordered]@{case='wifi-interface-cycle';started_utc=[DateTime]::UtcNow.ToString('o');result='incomplete'}
try {
    $devices=@(& adb devices | Where-Object {$_ -match '^\S+\s+device$'})
    if($devices.Count -ne 1){throw 'device precondition'}
    if((& adb shell settings get global wifi_on).Trim() -ne '1'){throw 'Wi-Fi must start enabled'}
    $before=(& adb shell ip -4 addr show dev wlan0) -join ' '
    if($before -notmatch '\binet '){throw 'Wi-Fi address required'}
    & adb shell cmd wifi set-wifi-enabled disabled | Out-Null
    if($LASTEXITCODE -ne 0){throw 'disable failed'}
    $r.disabled_utc=[DateTime]::UtcNow.ToString('o')
    $removed=$false
    for($i=0;$i -lt 10;$i++){
        Start-Sleep -Milliseconds 500
        $state=(& adb shell settings get global wifi_on) -join ''
        $addr=(& adb shell ip -4 addr show dev wlan0 2>$null) -join ' '
        if($state.Trim() -eq '0' -and $addr -notmatch '\binet '){$removed=$true;break}
    }
    if(-not $removed){throw 'interface removal not verified'}
    $r.disabled_and_ipv4_removed=$true
    Start-Sleep -Seconds 5
} catch {$r.failure_category='interface-cycle-check-failed'}
finally {
    & adb shell cmd wifi set-wifi-enabled enabled | Out-Null
    $restored=$false
    for($i=0;$i -lt 20;$i++){
        Start-Sleep -Milliseconds 500
        $addr=(& adb shell ip -4 addr show dev wlan0 2>$null) -join ' '
        if($addr -match '\binet '){$restored=$true;break}
    }
    $r.wifi_ipv4_restored=$restored
    $r.finished_utc=[DateTime]::UtcNow.ToString('o')
    if($r.disabled_and_ipv4_removed -and $restored -and -not $r.failure_category){$r.result='passed'}else{$r.result='failed'}
    $r | ConvertTo-Json | Set-Content (Join-Path $d ('wifi-interface-cycle-'+[Guid]::NewGuid().ToString('N')+'.json'))
}
$r | ConvertTo-Json
if($r.result -ne 'passed'){exit 1}
