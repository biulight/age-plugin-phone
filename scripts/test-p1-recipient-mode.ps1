#requires -Version 7.2
$ErrorActionPreference='Stop'
Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility
function Test-Mode([string]$Requested,[string]$Prepared,[bool]$Legacy,[bool]$Pass, [bool]$Tamper=$false) {
    . (Join-Path $PSScriptRoot 'p1/common.ps1')
    $saved=$env:TEMP
    $savedLocal=$env:LOCALAPPDATA
    $env:TEMP=Join-Path ([IO.Path]::GetTempPath()) ('phone-mode-'+[guid]::NewGuid().ToString('N'))
    $env:LOCALAPPDATA=$env:TEMP
    $d=Join-Path $env:TEMP 'phone-beta2-p1-20261023'
    $null=New-Item -ItemType Directory (Join-Path $d 'package') -Force
    $null=New-Item -ItemType Directory (Join-Path $d 'synthetic') -Force
    $cipher=Join-Path $d 'synthetic/synthetic.age'
    [IO.File]::WriteAllText($cipher,'synthetic ciphertext')
    $inputSet=@{matching='matching';nonmatching='nonmatching';digest=('0'*64);cipher_sha256=(Get-FileHash $cipher).Hash}
    if($Tamper){[IO.File]::WriteAllText($cipher,'replaced ciphertext')}
    if(-not $Legacy){$inputSet.recipient_mode=$Prepared}
    $inputSet | ConvertTo-Json | Set-Content (Join-Path $d 'local-inputs.json')
    $state=@{calls=0}
    function Invoke-P1Adb { param($Arguments) return "fixture-device`tdevice" }
    function Assert-P1NoReverse {}
    function Get-Command {param($Name,$CommandType) return @{Source=('fixture-'+$Name)}}
    function Get-FileHash {param([Alias('LiteralPath')]$Path,$Algorithm) if($Path.EndsWith('age-plugin-phone.exe')){return @{Hash='62d8f3836598dd1ab287c3b2ac432539870bfb0cbe7bdfd547d08cf3be373e2b'}}; Microsoft.PowerShell.Utility\Get-FileHash $Path}
    function Invoke-AcceptanceProcess {
        param($File,$Arguments)
        $state.calls++
        if($File -ne 'fixture-age' -or $Arguments[0] -ne '-d' -or $Arguments[2] -ne 'nonmatching'){throw 'Unexpected process invocation'}
        return [pscustomobject]@{ExitCode=1;Output='';DiagnosticCategory='identity-miss'}
    }
    $driver=Join-Path $PSScriptRoot 'p1/step-regression.ps1'
    $source=Get-Content $driver -Raw
    $source=$source.Replace(". (Join-Path `$PSScriptRoot 'common.ps1')",'')
    $source=$source.Replace('$PSCommandPath',"'"+$driver.Replace("'","''")+"'")
    $source=$source.Replace("if(`$record.result -eq 'failed'){exit 1}","if(`$record.result -eq 'failed'){throw 'driver_failed'}")
    $failed=$false
    try {
        try {$null=& ([scriptblock]::Create($source)) -Case nonmatch-only -AcceptanceRecipientMode $Requested}
        catch {if($_.Exception.Message -notin @('Prepared recipient mode mismatch','Prepared ciphertext binding mismatch')){throw};$failed=$true}
        if($failed -eq $Pass){throw 'Mode admission result mismatch'}
        if($Pass){
            if($state.calls -ne 1){throw 'Expected exactly one synthetic age call'}
            $reports=@(Get-ChildItem $d -Filter 'nonmatch-only-*.json')
            if($reports.Count -ne 1){throw 'Expected one report'}
            $r=Get-Content $reports[0].FullName -Raw | ConvertFrom-Json
            if($r.recipient_mode -cne $Requested -or $r.result -ne 'automated-checks-passed-awaiting-observation' -or $r.route_mode -ne 'explicit-adb'){throw 'Mode or transport misreported'}
        } elseif($state.calls -ne 0){throw 'Mismatched mode contacted age'}
    } finally {Remove-Item $env:TEMP -Recurse -Force;$env:TEMP=$saved;$env:LOCALAPPDATA=$savedLocal}
}
Test-Mode phone phone $false $true
Test-Mode tag tag $false $true
Test-Mode phone tag $false $false
Test-Mode tag phone $false $false
Test-Mode phone phone $true $false
Test-Mode tag phone $true $false
Test-Mode phone phone $false $false $true
Test-Mode tag tag $false $false $true

function Test-Preparation([string]$Mode,[bool]$WrongExport) {
    . (Join-Path $PSScriptRoot 'p1/common.ps1')
    $savedTemp=$env:TEMP;$savedLocal=$env:LOCALAPPDATA;$savedPath=$env:PATH
    $env:TEMP=Join-Path ([IO.Path]::GetTempPath()) ('phone-prepare-'+[guid]::NewGuid().ToString('N'))
    $env:LOCALAPPDATA=$env:TEMP
    $d=Join-Path $env:TEMP 'phone-beta2-p1-20261023'
    $stubs=Join-Path $env:LOCALAPPDATA 'age-plugin-phone'
    $null=New-Item -ItemType Directory (Join-Path $d 'package') -Force
    $null=New-Item -ItemType Directory $stubs -Force
    # Product parsing is mocked; these synthetic payloads exercise the runner's selection.
    function Write-Stub([string]$Name,[string]$Recipient) {
        $alphabet='qpzry9x8gf2tvdw0s3jn54khce6mua7l';$acc=0;$bits=0;$text=''
        foreach($b in [Text.Encoding]::ASCII.GetBytes($Recipient)){
            $acc=(($acc -band 65535) -shl 8) -bor $b;$bits+=8
            while($bits -ge 5){$bits-=5;$text+=$alphabet[($acc -shr $bits) -band 31]}
        }
        if($bits){$text+=$alphabet[($acc -shl (5-$bits)) -band 31]}
        [IO.File]::WriteAllText((Join-Path $stubs $Name),'fixture1'+$text+'qqqqqq')
    }
    Write-Stub 'identity-match.txt' 'age1phone1synthetic'
    Write-Stub 'identity-other.txt' 'age1phone1other'
    $state=@{exports=0;encryptions=0;recoveries=0;plain=$null;cipher=$null}
    function Invoke-P1Adb {param($Arguments) return "fixture-device`tdevice"}
    function Assert-P1NoReverse {}
    function Get-Command {param($Name,$CommandType) return @{Source=('fixture-'+$Name)}}
    function Get-FileHash {param([Alias('LiteralPath')]$Path,$Algorithm) if($Path.EndsWith('age-plugin-phone.exe')){return @{Hash='62d8f3836598dd1ab287c3b2ac432539870bfb0cbe7bdfd547d08cf3be373e2b'}}; Microsoft.PowerShell.Utility\Get-FileHash $Path}
    function Invoke-AcceptanceProcess {
        param($File,$Arguments)
        $r=[pscustomobject]@{ExitCode=0;Output='';DiagnosticCategory='none'}
        if($Arguments[0] -eq 'recipients'){
            if($Arguments[3] -ne '--recipient-type' -or $Arguments[4] -cne $Mode){throw 'Wrong export mode argument'}
            $state.exports++;$suffix=if($Arguments[2].EndsWith('identity-match.txt')){'match'}else{'other'}
            $exportMode=if($WrongExport){if($Mode -eq 'tag'){'phone'}else{'tag'}}else{$Mode}
            $r.Output="age1${exportMode}1${suffix}";return $r
        }
        if($File -eq 'fixture-age-keygen'){
            if($Arguments[0] -eq '-o'){[IO.File]::WriteAllText($Arguments[1],'synthetic recovery')}
            elseif($Arguments[0] -eq '-y'){$r.Output='age1recovery'}else{throw 'Unexpected keygen invocation'}
            return $r
        }
        if($File -ne 'fixture-age'){throw 'Unexpected program'}
        if($Arguments[0] -eq '-e'){
            if($Arguments[1] -ne '-r' -or $Arguments[2] -cne "age1${Mode}1match" -or $Arguments[4] -ne 'age1recovery'){throw 'Wrong encryption recipients'}
            $state.encryptions++;$state.plain=$Arguments[-1];$state.cipher=$Arguments[6]
            [IO.File]::WriteAllText($state.cipher,"synthetic ciphertext for $Mode");return $r
        }
        if($Arguments[0] -eq '-d'){
            if(-not $Arguments[2].EndsWith('recovery.txt') -or $Arguments[-1] -cne $state.cipher){throw 'Unexpected phone contact during prepare'}
            $state.recoveries++;[IO.File]::WriteAllBytes($Arguments[4],[IO.File]::ReadAllBytes($state.plain));return $r
        }
        throw 'Unexpected age invocation'
    }
    $driver=Join-Path $PSScriptRoot 'p1/step-regression.ps1'
    $source=(Get-Content $driver -Raw).Replace(". (Join-Path `$PSScriptRoot 'common.ps1')",'')
    $source=$source.Replace('$PSCommandPath',"'"+$driver.Replace("'","''")+"'")
    $source=$source.Replace('    exit', '    return')
    $rejected=$false
    try {
        try {$null=& ([scriptblock]::Create($source)) -Case prepare -AcceptanceRecipientMode $Mode -PhonePublicRecipient 'age1phone1synthetic'}
        catch {if($_.Exception.Message -ne 'Exported recipient mode mismatch'){throw};$rejected=$true}
        if($rejected -ne $WrongExport){throw 'Unexpected preparation outcome'}
        if($WrongExport){if($state.encryptions -ne 0 -or (Test-Path (Join-Path $d 'local-inputs.json'))){throw 'Invalid mode created prepared inputs'}}
        else {
            $inputs=Get-Content (Join-Path $d 'local-inputs.json') -Raw | ConvertFrom-Json
            if($state.exports -ne 2 -or $state.encryptions -ne 1 -or $state.recoveries -ne 1 -or $inputs.recipient_mode -cne $Mode -or $inputs.cipher_sha256 -cne (Get-FileHash $state.cipher).Hash){throw 'Prepared mode or ciphertext binding failed'}
        }
    } finally {Remove-Item $env:TEMP -Recurse -Force;$env:TEMP=$savedTemp;$env:LOCALAPPDATA=$savedLocal;$env:PATH=$savedPath}
}
Test-Preparation phone $false
Test-Preparation tag $false
Test-Preparation phone $true
Test-Preparation tag $true
Write-Host 'P1 recipient-mode binding and preparation fixtures passed (12 scenarios).'
