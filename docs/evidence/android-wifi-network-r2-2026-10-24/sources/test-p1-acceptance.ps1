#requires -Version 7.2
$ErrorActionPreference='Stop'
$suiteRoot=$PSScriptRoot
function Test-Scenario([string]$Mode) {
    . (Join-Path $suiteRoot 'p1/common.ps1')
    $savedTemp=$env:TEMP
    $env:TEMP=Join-Path ([IO.Path]::GetTempPath()) ('p1-fixture-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory (Join-Path $env:TEMP 'phone-beta2-p1-20261023') -Force
    $fixtureState=@{enabled=$true;disabledOnce=$false;restoreCalls=0}
    function Start-Sleep {}
    function Get-Command { param($Name,$CommandType) return @{Source='synthetic-adb'} }
    function Invoke-AcceptanceProcess {
        param($File,$Arguments,$TimeoutSeconds)
        $command=$Arguments -join ' '
        $r=[pscustomobject]@{ExitCode=0;Output='';DiagnosticCategory='none'}
        switch ($command) {
            'devices' { $r.Output="synthetic-device`tdevice" }
            'reverse --list' {
                if($Mode -eq 'reverse-error'){$r.ExitCode=1}
                if($Mode -eq 'reverse-residue'){$r.Output='synthetic residue'}
            }
            'shell settings get global wifi_on' {
                $r.Output=if($fixtureState.enabled){'1'}else{'0'}
                if($Mode -eq 'preflight-error'){$r.ExitCode=1;$r.Output=''}
            }
            'shell ip -o -4 addr show' {
                if($fixtureState.enabled){$r.Output='7: wlan0 inet 192.168.1.2/24 scope global wlan0'}
                elseif($Mode -eq 'address-error'){$r.ExitCode=1}
                elseif($Mode -eq 'address-timeout'){throw 'harness_timeout'}
                elseif($Mode -eq 'address-still-present'){$r.Output='7: wlan0 inet 192.168.1.2/24 scope global wlan0'}
            }
            'shell cmd wifi set-wifi-enabled disabled' {$fixtureState.enabled=$false;$fixtureState.disabledOnce=$true}
            'shell cmd wifi set-wifi-enabled enabled' {
                $fixtureState.restoreCalls++
                if($Mode -eq 'restore-error'){$r.ExitCode=1}else{$fixtureState.enabled=$true}
            }
            default { throw 'Unexpected fixture command' }
        }
        return $r
    }
    try {
        if($Mode.StartsWith('reverse-')) {
            $rejected=$false
            try { Assert-P1NoReverse } catch {$rejected=$true}
            if(-not $rejected){throw 'Reverse query failure/residue was accepted'}
            return
        }
        # Execute the production control flow with mocked IO; substitute only import and process exit.
        $source=Get-Content (Join-Path $suiteRoot 'p1/switch-wifi.ps1') -Raw
        $source=$source -replace '^\. \(Join-Path \$PSScriptRoot ''common.ps1''\)\r?\n',''
        $source=$source.Replace('$PSCommandPath', "'" + (Join-Path $suiteRoot 'p1/switch-wifi.ps1').Replace("'","''") + "'")
        $source=$source.Replace("if(`$r.result -ne 'passed'){exit 1}","if(`$r.result -ne 'passed'){throw 'expected_failed_result'}")
        try { $null=& ([scriptblock]::Create($source)) } catch { if($_.Exception.Message -ne 'expected_failed_result'){throw} }
        $files=@(Get-ChildItem (Join-Path $env:TEMP 'phone-beta2-p1-20261023') -Filter '*.json')
        if($files.Count -ne 1){throw 'Missing report'}
        $r=Get-Content $files[0] -Raw | ConvertFrom-Json
        $expected=if($Mode -eq 'passed'){'passed'}else{'failed'}
        if($r.result -ne $expected){throw "False result for $Mode"}
        if($Mode -eq 'preflight-error' -and $fixtureState.restoreCalls -ne 0){throw 'Preflight failure mutated Wi-Fi'}
        if($fixtureState.disabledOnce -and $fixtureState.restoreCalls -ne 1){throw 'Restoration was not attempted exactly once'}
        if($r.provenance.common_sha256.Length -ne 64){throw 'Missing provenance'}
    } finally {
        Remove-Item -LiteralPath $env:TEMP -Recurse -Force
        $env:TEMP=$savedTemp
    }
}
foreach($mode in @('passed','address-error','address-timeout','address-still-present','restore-error','preflight-error','reverse-error','reverse-residue')){Test-Scenario $mode}
& {
    . (Join-Path $suiteRoot 'p1/common.ps1')
    if((Get-AcceptanceDiagnostic 'private-path no matching foreground Wi-Fi listener was discovered secret') -ne 'wifi-discovery-no-match'){throw 'Discovery classification failed'}
    if((Get-AcceptanceDiagnostic 'phone Wi-Fi connection unavailable after discovery') -ne 'wifi-connect-failed'){throw 'Connect classification failed'}
    if((Get-AcceptanceDiagnostic 'unrecognized private diagnostic') -ne 'other-error'){throw 'Unknown diagnostic leaked'}
}
Write-Host 'P1 checked ADB, interface loss, restoration, reverse failure and diagnostic fixtures passed.'
