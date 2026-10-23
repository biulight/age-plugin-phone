$ErrorActionPreference='Stop'
$d=Join-Path $env:TEMP 'phone-beta2-p1-20261023'
$op=Get-Content (Join-Path $d 'disconnect-operation.json') -Raw | ConvertFrom-Json -DateKind String
$driver=Get-Process -Id $op.pid
if($driver.StartTime.ToUniversalTime().ToString('o') -cne $op.started){throw 'Operation identity changed'}
$children=@(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($driver.Id)" | Where-Object Name -eq 'age.exe')
if($children.Count -ne 1){throw 'Expected one test age process'}
$plugins=@(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($children[0].ProcessId)" | Where-Object {$_.ExecutablePath -eq ([IO.Path]::GetFullPath((Join-Path $d 'package/age-plugin-phone.exe')))})
if($plugins.Count -ne 1){throw 'Expected one exact-package test plugin process'}
$plugin=Get-Process -Id $plugins[0].ProcessId
if($plugin.Path -ne ([IO.Path]::GetFullPath((Join-Path $d 'package/age-plugin-phone.exe')))){throw 'Plugin identity changed'}
$plugin.Kill()
$plugin.WaitForExit()
@{case='wifi-disconnect-action';action='terminated-current-test-plugin';completed_utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Tee-Object -FilePath (Join-Path $d 'disconnect-action.json')
