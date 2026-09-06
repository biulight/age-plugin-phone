#requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/windows-minimal-acceptance.ps1"

function Expect-Failure {
    param([scriptblock]$Action, [string]$Category)
    try { & $Action } catch {
        if ($_.Exception.Message -notlike "*$Category*") { throw 'Wrong failure category in fixture.' }
        return
    }
    throw "Fixture should have failed: $Category"
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('age-phone-minimal-fixtures-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
try {
    $original = Join-Path $testRoot 'original.bin'
    $output = Join-Path $testRoot 'output.bin'
    [IO.File]::WriteAllBytes($original, [byte[]](0, 1, 2, 255))
    $digest = (Get-FileHash -LiteralPath $original).Hash
    Copy-Item -LiteralPath $original -Destination $output
    Assert-AcceptanceOutput 0 $output $digest $true
    Expect-Failure { Assert-AcceptanceOutput 1 $output $digest $true } 'decrypt_failed'
    Expect-Failure { Assert-AcceptanceOutput 1 $output $digest $false } 'negative_case_released_output'
    [IO.File]::WriteAllBytes($output, [byte[]](0, 1, 2, 254))
    Expect-Failure { Assert-AcceptanceOutput 0 $output $digest $true } 'digest_mismatch'
    [IO.File]::WriteAllBytes($output, [byte[]]@())
    Assert-AcceptanceOutput 1 $output $digest $false
    Expect-Failure { Assert-AcceptanceOutput 0 $output $digest $false } 'negative_case_released_output'
    Remove-Item -LiteralPath $output
    Assert-AcceptanceOutput 1 $output $digest $false
    Expect-Failure { Assert-AcceptanceOutput 0 $output $digest $true } 'decrypt_failed'

    # Real subprocess boundaries: separate stderr, nonzero propagation, argument fidelity,
    # closed stdin, and a harness timeout that must not masquerade as a product negative.
    $pwsh = (Get-Process -Id $PID).Path
    $result = Invoke-AcceptanceProcess $pwsh @('-NoProfile', '-Command', '[Console]::Out.Write("public-fixture"); [Console]::Error.Write("discard-fixture"); exit 7')
    if ($result.ExitCode -ne 7 -or $result.Output -cne 'public-fixture') { throw 'Process output isolation failed.' }
    $child = Join-Path $testRoot 'argument fixture.ps1'
    Set-Content -LiteralPath $child -Value 'param([string]$Value); [Console]::Out.Write($Value)'
    $argument = 'spaces " quotes $dollar ; literal'
    $result = Invoke-AcceptanceProcess $pwsh @('-NoProfile', '-File', $child, $argument)
    if ($result.ExitCode -ne 0 -or $result.Output -cne $argument) { throw 'Argument fidelity failed.' }
    $result = Invoke-AcceptanceProcess $pwsh @('-NoProfile', '-Command', 'if ([Console]::ReadLine() -ne $null) { exit 9 }')
    if ($result.ExitCode -ne 0) { throw 'Child stdin was not closed.' }
    Expect-Failure { Invoke-AcceptanceProcess $pwsh @('-NoProfile', '-Command', 'Start-Sleep -Seconds 10') 1 } 'harness_timeout'

    function Read-Host { return 'not-observed' }
    Expect-Failure { Confirm-AcceptanceObservation 'fixture' } 'observation_not_confirmed'
    function Read-Host { return 'OBSERVED' }
    Confirm-AcceptanceObservation 'fixture'

    function Test-Orchestration {
        param([string]$FailureMode)
        # Simulate the host and external tools; no fixture is physical acceptance evidence.
        Set-Variable -Name IsWindows -Value $true -Force -Scope Local
        $PluginExe = Join-Path $testRoot 'age-plugin-phone.exe'
        $Apk = Join-Path $testRoot 'candidate.apk'
        $IdentityStub = Join-Path $testRoot 'public-stub.txt'
        foreach ($path in @($PluginExe, $Apk, $IdentityStub)) { Set-Content -LiteralPath $path -Value 'fixture-only' }
        $ExpectedExeSha256 = (Get-FileHash -LiteralPath $PluginExe).Hash.ToLowerInvariant()
        $ExpectedApkSha256 = (Get-FileHash -LiteralPath $Apk).Hash.ToLowerInvariant()
        $Commit = 'a' * 40
        $WorkflowRun = '123'
        $WorkflowAttempt = '1'
        $Version = '0.1.0-alpha.4'
        $PhoneRecipient = 'age1phonefixture'
        $ConfigRoot = $testRoot
        $AdbSerial = 'fixture-private-serial'
        $AgeExe = Join-Path $testRoot 'age.exe'
        $AgeKeygenExe = Join-Path $testRoot 'age-keygen.exe'
        $AdbExe = Join-Path $testRoot 'adb.exe'
        $ReportPath = Join-Path $testRoot "$FailureMode.json"
        $state = @{ Probe = ''; Unwraps = 0; FixtureDirectory = '' }
        $before = @{}
        $names = @('PATH', 'AGE_PLUGIN_PHONE_CONFIG_DIR', 'AGE_PLUGIN_PHONE_TRANSPORT',
            'AGE_PLUGIN_PHONE_ADB_SERIAL', 'AGE_PLUGIN_PHONE_WIFI_ADDRESS', 'AGE_PLUGIN_PHONE_MESSAGES')
        foreach ($name in $names) { $before[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
        function Get-Command {
            param([string]$Name, [string]$CommandType, [string]$ErrorAction)
            if ($Name -eq 'adb.exe') { return [pscustomobject]@{ Source = $AdbExe } }
            return [pscustomobject]@{ Source = $Name }
        }
        function Read-Host {
            param([string]$Prompt)
            if ($Prompt -like '*READY*') { return 'READY' }
            return 'OBSERVED'
        }
        function Invoke-AcceptanceProcess {
            param([string]$File, [string[]]$Arguments, [int]$TimeoutSeconds = 120)
            $response = [pscustomobject]@{ ExitCode = 0; Output = '' }
            if ($File -eq $PluginExe) {
                if ($Arguments[0] -eq '--version') { $response.Output = "age-plugin-phone $Version" }
                else { $response.Output = 'windows_alpha_support: supported' }
            } elseif ($File -eq $AdbExe) {
                if ($Arguments -contains 'get-state') { $response.Output = 'device' }
                elseif ($FailureMode -eq 'residue' -and $state.Unwraps -gt 0) { $response.Output = 'private-reverse-fixture' }
            } elseif ($File -eq $AgeKeygenExe) {
                if ($Arguments[0] -eq '-y') { $response.Output = 'age1fixture' }
                else { Set-Content -LiteralPath $Arguments[1] -Value 'private-recovery-fixture' }
            } elseif ($File -eq $AgeExe) {
                $outputFile = $Arguments[[Array]::IndexOf($Arguments, '-o') + 1]
                if ($Arguments[0] -eq '-e') {
                    $state.Probe = $Arguments[-1]
                    $state.FixtureDirectory = Split-Path -Parent $state.Probe
                    Set-Content -LiteralPath $outputFile -Value 'ciphertext-fixture'
                } else {
                    $caseName = [IO.Path]::GetFileNameWithoutExtension($outputFile)
                    if ($caseName -ne 'recovery') { $state.Unwraps++ }
                    if ($FailureMode -eq 'timeout' -and $state.Unwraps -eq 2) { throw 'harness_timeout' }
                    if ($caseName -in @('usb-cancel', 'wifi-background', 'wifi-paused')) { $response.ExitCode = 1 }
                    else { Copy-Item -LiteralPath $state.Probe -Destination $outputFile }
                }
            } else { throw 'Unexpected fixture executable.' }
            return $response
        }
        if ($FailureMode -eq 'passed') { Invoke-MinimalAcceptance }
        elseif ($FailureMode -eq 'timeout') { Expect-Failure { Invoke-MinimalAcceptance } 'harness_timeout' }
        else { Expect-Failure { Invoke-MinimalAcceptance } 'adb_reverse_residue' }
        $raw = Get-Content -LiteralPath $ReportPath -Raw
        $report = $raw | ConvertFrom-Json
        if ($FailureMode -eq 'passed') {
            if ($report.status -ne 'passed-minimal-unwrap-only' -or $report.rows.Count -ne 11 -or $state.Unwraps -ne 8) {
                throw 'Successful orchestration missed required rows.'
            }
        } elseif ($report.status -ne 'failed' -or $state.Unwraps -gt 2) { throw 'Failed run retried or lost its failure report.' }
        if (-not $report.synthetic_files_removed -or (Test-Path -LiteralPath $state.FixtureDirectory)) { throw 'Fixture directory not removed.' }
        foreach ($name in $names) {
            if ([Environment]::GetEnvironmentVariable($name, 'Process') -cne $before[$name]) { throw "Environment was not restored: $name" }
        }
        foreach ($private in @($testRoot, $IdentityStub, $AdbSerial, $PhoneRecipient, 'private-recovery-fixture', 'private-reverse-fixture')) {
            if ($raw.Contains($private)) { throw 'Private fixture data leaked into report.' }
        }
        try { Invoke-MinimalAcceptance; throw 'Existing report was overwritten.' }
        catch [IO.IOException] { } # CreateNew must retain the prior failed or successful report.
        if ((Get-Content -LiteralPath $ReportPath -Raw) -cne $raw) { throw 'Prior evidence changed.' }
    }
    Test-Orchestration 'passed'
    Test-Orchestration 'timeout'
    Test-Orchestration 'residue'
    Write-Host 'Minimum acceptance output, process, timeout, observation, report and restoration fixtures passed.'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
