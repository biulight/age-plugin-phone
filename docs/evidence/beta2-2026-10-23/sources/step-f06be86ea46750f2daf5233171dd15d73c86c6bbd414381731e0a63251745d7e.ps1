param([ValidateSet('prepare','nonmatch-only','malformed','unavailable-state','approve-1','approve-2','cancel','after-cancel','wifi-approve','wifi-repeat','wifi-cancel','wifi-after-cancel','wifi-background','wifi-after-background','wifi-paused','wifi-timeout','wifi-after-timeout')][string]$Case,
    [string]$PhonePublicRecipient)
$ErrorActionPreference='Stop'
$d=Join-Path $env:TEMP 'phone-beta2-p1-20261023'
. (Join-Path $d 'windows-minimal-acceptance.ps1')
# Additional negative cases classify only fixed product diagnostics, never record raw stderr.
$baseDiagnostic = (Get-Item Function:Get-AcceptanceDiagnostic).ScriptBlock
function Get-AcceptanceDiagnostic {
    param([string]$Diagnostic)
    if ($Case -eq 'malformed' -and $Diagnostic -cmatch 'malformed phone stanza') { return 'malformed-phone-stanza' }
    if ($Case -eq 'unavailable-state' -and $Diagnostic -cmatch 'paired desktop state is unavailable') { return 'paired-state-unavailable' }
    & $baseDiagnostic $Diagnostic
}
# Dot-sourcing initializes harness parameters, so use this runner's distinct names below.
$product=Join-Path $d 'package/age-plugin-phone.exe'
$root=Join-Path $env:LOCALAPPDATA 'age-plugin-phone'
$age=(Get-Command age -CommandType Application | Select-Object -First 1).Source
$keygen=(Get-Command age-keygen -CommandType Application | Select-Object -First 1).Source
$env:PATH="$(Split-Path $product);$env:PATH"
$env:AGE_PLUGIN_PHONE_CONFIG_DIR=$root
$env:AGE_PLUGIN_PHONE_TRANSPORT=if($Case.StartsWith('wifi-')){'wifi'}else{'adb'}
Remove-Item Env:AGE_PLUGIN_PHONE_MESSAGES,Env:AGE_PLUGIN_PHONE_WIFI_ADDRESS -ErrorAction SilentlyContinue
$devices=@(& adb devices | Where-Object {$_ -match '^\S+\s+device$'})
if ($devices.Count -ne 1) { throw 'Expected one authorized USB phone' }
if($Case.StartsWith('wifi-')) { Remove-Item Env:AGE_PLUGIN_PHONE_ADB_SERIAL -ErrorAction SilentlyContinue }
else { $env:AGE_PLUGIN_PHONE_ADB_SERIAL=($devices[0] -split '\s+')[0] }
if (@(& adb reverse --list | Where-Object {$_}).Count -ne 0) { throw 'Existing ADB reverse rule; no changes made' }
if ((Get-FileHash $product).Hash.ToLowerInvariant() -cne '62d8f3836598dd1ab287c3b2ac432539870bfb0cbe7bdfd547d08cf3be373e2b') { throw 'Product hash mismatch' }
$work=Join-Path $d 'synthetic'
$localInputs=Join-Path $d 'local-inputs.json'
if ($Case -eq 'prepare') {
    if (Test-Path $localInputs) { throw 'Prepared inputs already exist; do not overwrite' }
    if ($PhonePublicRecipient -cnotmatch '^age1phone1[0-9a-z]+$') { throw 'Expected phone public recipient' }
    $alphabet='qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    $candidates=@()
    foreach($stub in @(Get-ChildItem $root -Filter 'identity-*.txt' -File | Sort-Object LastWriteTime -Descending)) {
        $r=Invoke-AcceptanceProcess $product @('recipients','--identity',$stub.FullName,'--recipient-type','phone')
        if ($r.ExitCode -ne 0) { continue }
        $line=@([IO.File]::ReadAllLines($stub.FullName) | ForEach-Object {$_.Trim()} | Where-Object {$_ -and -not $_.StartsWith('#')})[0].ToLowerInvariant()
        $data=$line.Substring($line.LastIndexOf('1')+1); $data=$data.Substring(0,$data.Length-6)
        $bytes=[Collections.Generic.List[byte]]::new(); $acc=0; $bits=0
        foreach($char in $data.ToCharArray()) {
            $v=$alphabet.IndexOf($char); if ($v -lt 0) { throw 'Invalid validated stub encoding' }
            $acc=(($acc -band 255) -shl 5) -bor $v; $bits+=5
            if ($bits -ge 8) { $bits-=8; $bytes.Add([byte](($acc -shr $bits) -band 255)) }
        }
        $legacy=[regex]::Match([Text.Encoding]::ASCII.GetString($bytes.ToArray()),'age1phone1[0-9a-z]+').Value
        $candidates+=@{path=$stub.FullName; recipient=$r.Output.Trim(); legacy=$legacy}
    }
    $matching=@($candidates | Where-Object {$_.legacy -ceq $PhonePublicRecipient})
    if ($matching.Count -eq 0) { throw 'No existing Windows pairing for current phone' }
    $selected=$matching[0]
    $others=@($candidates | Where-Object {$_.recipient -cne $selected.recipient})
    if ($others.Count -eq 0) { throw 'No different valid phone recipient' }
    New-Item -ItemType Directory $work | Out-Null
    $plain=Join-Path $work 'synthetic.bin'; $cipher=Join-Path $work 'synthetic.age'; $recovery=Join-Path $work 'recovery.txt'
    [IO.File]::WriteAllBytes($plain,[Security.Cryptography.RandomNumberGenerator]::GetBytes(128))
    $r=Invoke-AcceptanceProcess $keygen @('-o',$recovery); if($r.ExitCode -ne 0){throw 'Recovery creation failed'}
    $r=Invoke-AcceptanceProcess $keygen @('-y',$recovery); if($r.ExitCode -ne 0){throw 'Recovery recipient failed'}
    $r=Invoke-AcceptanceProcess $age @('-e','-r',$selected.recipient,'-r',$r.Output.Trim(),'-o',$cipher,$plain)
    if($r.ExitCode -ne 0){throw 'Synthetic encryption failed'}
    $digest=(Get-FileHash $plain).Hash
    $out=Join-Path $work 'recovered.bin'
    $r=Invoke-AcceptanceProcess $age @('-d','-i',$recovery,'-o',$out,$cipher)
    Assert-AcceptanceOutput $r.ExitCode $out $digest $true $r.Output $r.DiagnosticCategory
    # Operational inputs stay on the test host, outside shareable evidence.
    @{matching=$selected.path; nonmatching=$others[0].path; digest=$digest} | ConvertTo-Json | Set-Content $localInputs
    @{case='independent-recovery';result='passed';phone_contact_required=$false;synthetic_bytes=128} | ConvertTo-Json | Set-Content (Join-Path $d 'independent-recovery.json')
    Write-Output 'Prepared synthetic ciphertext; independent recovery passed. No phone authorization requested.'
    exit
}
$inputSet=Get-Content $localInputs -Raw | ConvertFrom-Json
$cipher=Join-Path $work 'synthetic.age'
$out=Join-Path $work ($Case+'-'+[Guid]::NewGuid().ToString('N')+'.bin')
$ids=@('-i',$inputSet.matching)
if($Case -eq 'nonmatch-only'){$ids=@('-i',$inputSet.nonmatching)}
if($Case -in @('approve-1','approve-2','cancel','after-cancel')){$ids=@('-i',$inputSet.nonmatching,'-i',$inputSet.matching)}
if($Case -eq 'unavailable-state'){$env:AGE_PLUGIN_PHONE_CONFIG_DIR=Join-Path $work 'never-created-private-state'}
if($Case -eq 'malformed'){
    $raw=[IO.File]::ReadAllBytes($cipher)
    $text=[Text.Encoding]::Latin1.GetString($raw)
    $modified=[regex]::new('(?m)^(-> phone-p256-v2 [^\r\n]+)$').Replace($text,'$1 invalid',1)
    if($modified -ceq $text){throw 'Supported stanza not found'}
    $cipher=Join-Path $work ('malformed-'+[Guid]::NewGuid().ToString('N')+'.age')
    [IO.File]::WriteAllBytes($cipher,[Text.Encoding]::Latin1.GetBytes($modified))
}
$success=$Case -in @('approve-1','approve-2','after-cancel','wifi-approve','wifi-repeat','wifi-after-cancel','wifi-after-background','wifi-after-timeout')
$record=[ordered]@{case=$Case;result='incomplete';transport=$env:AGE_PLUGIN_PHONE_TRANSPORT;phone_observation='pending';started_utc=[DateTime]::UtcNow.ToString('o');driver_sha256=(Get-FileHash (Join-Path $d 'step-regression.ps1')).Hash.ToLowerInvariant()}
$report=Join-Path $d ($Case+'-'+[Guid]::NewGuid().ToString('N')+'.json')
try {
    $r=Invoke-AcceptanceProcess $age (@('-d')+$ids+@('-o',$out,$cipher))
    $record.exit_code=$r.ExitCode; $record.diagnostic_category=$r.DiagnosticCategory
    Assert-AcceptanceOutput $r.ExitCode $out $inputSet.digest $success $r.Output $r.DiagnosticCategory ($Case -eq 'nonmatch-only')
    if ($Case -eq 'malformed' -and $r.DiagnosticCategory -cne 'malformed-phone-stanza') { throw 'Unexpected malformed-stanza failure' }
    if ($Case -eq 'unavailable-state' -and $r.DiagnosticCategory -cne 'paired-state-unavailable') { throw 'Unexpected unavailable-state failure' }
    if(@(& adb reverse --list | Where-Object {$_}).Count -ne 0){throw 'ADB reverse residue'}
    $record.result='automated-checks-passed-awaiting-observation'
    $record.output_check=if($success){'byte-identical'}else{'no-output'}
    $record.adb_reverse_count=0
} catch {
    $record.result='failed'; $record.failure_category='operation-or-assertion-failed'
} finally {
    $record.finished_utc=[DateTime]::UtcNow.ToString('o')
    $record|ConvertTo-Json|Set-Content $report
}
$record|ConvertTo-Json
if($record.result -eq 'failed'){exit 1}
