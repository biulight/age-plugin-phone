$ErrorActionPreference='Stop'
$env:JAVA_HOME=Join-Path $env:LOCALAPPDATA 'mise/installs/java/temurin-17.0.20+101'
if(-not (Test-Path (Join-Path $env:JAVA_HOME 'bin/java.exe'))){throw 'Expected Java unavailable'}
$originalTemp=$env:TEMP
$old=Join-Path $originalTemp 'phone-beta2-p1-20261023'
$campaign=Join-Path $originalTemp 'phone-maintenance-20261029'
$d=Join-Path $campaign 'phone-beta2-p1-20261023'
if(-not (Test-Path (Join-Path $d 'windows-preflight.json'))){throw 'Expected prior campaign preflight'}
$null=New-Item -ItemType Directory $d -Force
# Existing pinned package is reverified below.
foreach($name in @('age-plugin-phone-0.1.0-beta.2-windows-x64-beta-test-signed.zip','age-plugin-phone-0.1.0-beta.2-windows-signature-verification.txt','network-r2-signed.apk')){Copy-Item (Join-Path $old $name) $d}
Copy-Item (Join-Path $old 'verify-windows.ps1') $d
$env:TEMP=$campaign
& (Join-Path $d 'verify-windows.ps1')
if(-not (Get-Content (Join-Path $d 'windows-preflight.json') -Raw | ConvertFrom-Json).windows_supported){throw 'Windows unsupported'}
function Invoke-CheckedAdb([string[]]$Arguments){$out=& adb @Arguments 2>&1; if($LASTEXITCODE -ne 0){throw 'ADB command failed'}; return ($out -join "`n")}
$devices=Invoke-CheckedAdb @('devices')
if(@($devices -split '\r?\n' | Where-Object {$_ -match '^\S+\s+device$'}).Count -ne 1){throw 'Expected one phone'}
if((Invoke-CheckedAdb @('reverse','--list')).Trim()){throw 'Reverse residue'}
$package='io.github.biulight.age_plugin_phone'
$location=(Invoke-CheckedAdb @('shell','pm','path',$package)).Trim()
if($location -notmatch '^package:(/[^\r\n]+/base.apk)$'){throw 'Unexpected package path'}
$null=Invoke-CheckedAdb @('pull',$Matches[1],(Join-Path $d 'installed-preflight.apk'))
$hash=(Get-FileHash (Join-Path $d 'installed-preflight.apk')).Hash.ToLowerInvariant()
if($hash -cne 'cd28c3a7a19e1a4a92910c151551cec853169fa5e653815421c6386d825ee37a'){throw 'Installed APK mismatch'}
$bt=Join-Path $env:LOCALAPPDATA 'Android/Sdk/build-tools/35.0.0'
$output=& (Join-Path $bt 'apksigner.bat') verify --verbose --print-certs (Join-Path $d 'installed-preflight.apk') 2>&1
if($LASTEXITCODE -ne 0){throw 'APK signature failed'}
$signer=[regex]::Match(($output -join "`n"),'Signer #1 certificate SHA-256 digest: ([0-9a-f]+)').Groups[1].Value
if($signer -cne '9a3e5a00a0a363ca58bbe0abfa1bbc0e36cbdce58e314c0c0dbfa94baff1d58b'){throw 'APK signer mismatch'}
$badging=& (Join-Path $bt 'aapt.exe') dump badging (Join-Path $d 'installed-preflight.apk') 2>&1
if($LASTEXITCODE -ne 0){throw 'APK version query failed'}
$m=[regex]::Match(($badging -join "`n"),"package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'")
if(-not $m.Success -or $m.Groups[1].Value -cne $package -or $m.Groups[2].Value -cne '1000' -or $m.Groups[3].Value -cne '0.1.0-beta.2'){throw 'APK version mismatch'}
[ordered]@{case='candidate-preflight';result='passed';checked_utc=[DateTime]::UtcNow.ToString('o');installed_apk_sha256=$hash;signer_sha256=$signer;signature_verified=$true;package=$package;version_code='1000';version='0.1.0-beta.2';adb_reverse_count=0;installation_changed=$false;driver_sha256=(Get-FileHash $PSCommandPath).Hash.ToLowerInvariant()} | ConvertTo-Json | Tee-Object -FilePath (Join-Path $d 'android-preflight.json')
