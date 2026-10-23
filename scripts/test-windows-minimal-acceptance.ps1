#requires -Version 7.2
param([switch]$NativeClients)
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

function Assert-NoPrivateEvidence {
    param($Value, [string[]]$PrivateValues)
    if ($Value -is [string]) {
        foreach ($private in $PrivateValues) {
            if ($private -and $Value.Contains($private)) { throw 'Private fixture data leaked into report.' }
        }
    } elseif ($Value -is [Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            Assert-NoPrivateEvidence $key $PrivateValues
            Assert-NoPrivateEvidence $Value[$key] $PrivateValues
        }
    } elseif ($Value -is [Collections.IEnumerable]) {
        foreach ($item in $Value) { Assert-NoPrivateEvidence $item $PrivateValues }
    }
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('age-phone-minimal-fixtures-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
try {
    if ($IsWindows) {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        foreach ($typeName in @('System.Windows.MessageBox', 'System.Windows.MessageBoxButton',
            'System.Windows.MessageBoxImage', 'System.Windows.MessageBoxResult')) {
            if ($null -eq ($typeName -as [type])) { throw "Native owner dialog type is unavailable: $typeName" }
        }
    }
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
    Expect-Failure { Assert-AcceptanceOutput 1 $output $digest $false 'synthetic stdout' } 'unexpected_stdout'
    Expect-Failure { Assert-AcceptanceOutput 1 $output $digest $false '' 'other-error' $true } 'unexpected_identity_failure'
    Assert-AcceptanceOutput 1 $output $digest $false '' 'identity-miss' $true
    Expect-Failure { Assert-AcceptanceOutput 7 $output $digest $false } 'unexpected_exit_code'
    Expect-Failure { Assert-AcceptanceOutput 0 $output $digest $false } 'negative_case_released_output'
    Remove-Item -LiteralPath $output
    Assert-AcceptanceOutput 1 $output $digest $false
    Expect-Failure { Assert-AcceptanceOutput 0 $output $digest $true } 'decrypt_failed'
    Copy-Item -LiteralPath $original -Destination $output
    Expect-Failure { Assert-AcceptanceOutput 0 $output $digest $true 'synthetic stdout' } 'unexpected_stdout'

    $miss = "age: error: no identity matched any of the recipients`nage: report unexpected or unhelpful errors at https://filippo.io/age/report`n"
    foreach ($text in @($miss, $miss.Replace("`n", "`r`n"))) {
        if ((Get-AcceptanceDiagnostic $text) -cne 'identity-miss') { throw 'Ordinary miss classification failed.' }
    }
    foreach ($text in @('', 'malformed identity', 'paired desktop state is unavailable',
        ($miss + 'unexpected extra diagnostic'), ('prefix' + $miss))) {
        if ((Get-AcceptanceDiagnostic $text) -ceq 'identity-miss') { throw 'Unrelated failure classified as miss.' }
    }
    # Test decoded values, including JSON-escaped Windows paths, nested arrays and keys.
    $privateWindowsPath = 'C:\Users\fixture\private\identity.txt'
    foreach ($injected in @(@{ rows = @(@{ extra = $privateWindowsPath }) }, @{ $privateWindowsPath = 'value' })) {
        $decoded = ($injected | ConvertTo-Json -Depth 6) | ConvertFrom-Json -AsHashtable
        Expect-Failure { Assert-NoPrivateEvidence $decoded @($privateWindowsPath) } 'Private fixture data leaked'
    }
    Assert-NoPrivateEvidence (@{ rows = @(@{ result = 'passed' }) }) @($privateWindowsPath)

    # Real subprocess boundaries: separate stderr, nonzero propagation, argument fidelity,
    # closed stdin, and a harness timeout that must not masquerade as a product negative.
    $pwsh = (Get-Process -Id $PID).Path
    $result = Invoke-AcceptanceProcess $pwsh @('-NoProfile', '-Command', '[Console]::Out.Write("public-fixture"); [Console]::Error.Write("discard-fixture"); exit 7')
    if ($result.ExitCode -ne 7 -or $result.Output -cne 'public-fixture' -or $result.DiagnosticCategory -cne 'other-error' -or
        ($result | ConvertTo-Json).Contains('discard-fixture')) { throw 'Process output isolation failed.' }
    $child = Join-Path $testRoot 'argument fixture.ps1'
    Set-Content -LiteralPath $child -Value 'param([string]$Value); [Console]::Out.Write($Value)'
    $argument = 'spaces " quotes $dollar ; literal'
    $result = Invoke-AcceptanceProcess $pwsh @('-NoProfile', '-File', $child, $argument)
    if ($result.ExitCode -ne 0 -or $result.Output -cne $argument) { throw 'Argument fidelity failed.' }
    $result = Invoke-AcceptanceProcess $pwsh @('-NoProfile', '-Command', 'if ([Console]::ReadLine() -ne $null) { exit 9 }')
    if ($result.ExitCode -ne 0) { throw 'Child stdin was not closed.' }
    Expect-Failure { Invoke-AcceptanceProcess $pwsh @('-NoProfile', '-Command', 'Start-Sleep -Seconds 10') 1 } 'harness_timeout'

    if ($NativeClients) {
        # Public fixture parsing and disposable software age identities only: no phone/private state.
        $PluginExe = (Get-Command age-plugin-phone -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
        $nativeAge = (Get-Command age -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
        $nativeKeygen = (Get-Command age-keygen -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
        $publicStub = Join-Path $PSScriptRoot 'fixtures/acceptance-public-stub.txt'
        foreach ($RecipientMode in @('phone', 'tag')) {
            $parsed = Invoke-AcceptanceProcess $PluginExe @('recipients', '--identity', $publicStub, '--recipient-type', $RecipientMode)
            if ($parsed.ExitCode -ne 0) { throw 'Native public fixture could not be parsed.' }
            Assert-AcceptanceIdentity $publicStub $parsed.Output.Trim() $true
            Expect-Failure { Assert-AcceptanceIdentity $publicStub $parsed.Output.Trim() $false } 'identity_recipient_mismatch'
            Expect-Failure { Assert-AcceptanceIdentity $publicStub 'age1wrong' $true } 'identity_recipient_mismatch'
        }
        $RecipientMode = 'phone'
        $stubText = [IO.File]::ReadAllText($publicStub)
        $stubLine = @($stubText -split '\r?\n' | Where-Object { $_ -and -not $_.StartsWith('#') })[0]
        $badStub = Join-Path $testRoot 'invalid-public-stub.txt'
        $last = if ($stubLine[-1] -ceq 'Q') { 'P' } else { 'Q' }
        foreach ($text in @('', '# comment only', 'not-an-identity',
            ($stubLine + "`n" + $stubLine), ($stubLine.Substring(0, $stubLine.Length - 1) + $last),
            $stubLine.Replace('PHONE', 'OTHER'))) {
            [IO.File]::WriteAllText($badStub, $text)
            Expect-Failure { Assert-AcceptanceIdentity $badStub 'age1wrong' $false } 'invalid_identity_stub'
        }
        $nativeKey = Join-Path $testRoot 'native-key.txt'
        $otherKey = Join-Path $testRoot 'other-native-key.txt'
        foreach ($key in @($nativeKey, $otherKey)) {
            $r = Invoke-AcceptanceProcess $nativeKeygen @('-o', $key)
            if ($r.ExitCode -ne 0) { throw 'Disposable native key generation failed.' }
        }
        Expect-Failure { Assert-AcceptanceIdentity $otherKey 'age1wrong' $false } 'invalid_identity_stub'
        $recipient = Invoke-AcceptanceProcess $nativeKeygen @('-y', $nativeKey)
        if ($recipient.ExitCode -ne 0) { throw 'Disposable native recipient derivation failed.' }
        $cipher = Join-Path $testRoot 'native.age'
        $r = Invoke-AcceptanceProcess $nativeAge @('-e', '-r', $recipient.Output.Trim(), '-o', $cipher, $original)
        if ($r.ExitCode -ne 0) { throw 'Native fixture encryption failed.' }
        $nativeOutput = Join-Path $testRoot 'native-output.bin'
        $r = Invoke-AcceptanceProcess $nativeAge @('-d', '-i', $otherKey, '-o', $nativeOutput, $cipher)
        Assert-AcceptanceOutput $r.ExitCode $nativeOutput '' $false $r.Output $r.DiagnosticCategory $true
        [IO.File]::WriteAllText($badStub, 'malformed identity')
        $r = Invoke-AcceptanceProcess $nativeAge @('-d', '-i', $badStub, '-o', $nativeOutput, $cipher)
        Expect-Failure { Assert-AcceptanceOutput $r.ExitCode $nativeOutput '' $false $r.Output $r.DiagnosticCategory $true } 'unexpected_identity_failure'
        $r = Invoke-AcceptanceProcess $nativeAge @('-d', '-i', $nativeKey, '-o', $nativeOutput, $cipher)
        Assert-AcceptanceOutput $r.ExitCode $nativeOutput $digest $true $r.Output $r.DiagnosticCategory
        Write-Host 'Native plugin stub validation and real age miss/error/success regressions passed (no hardware acceptance).'
    }

    function Request-AcceptanceConfirmation { return $false }
    Expect-Failure { Confirm-AcceptanceObservation 'fixture' } 'observation_not_confirmed'
    function Request-AcceptanceConfirmation { return $true }
    Confirm-AcceptanceObservation 'fixture'

    function Test-Orchestration {
        param([string]$FailureMode, [string]$Version = '0.1.0-beta.2',
            [string]$RecipientMode = 'phone', [bool]$WithNonmatch = $true,
            [string]$PreflightError = '')
        # Simulate the host and external tools; no fixture is physical acceptance evidence.
        Set-Variable -Name IsWindows -Value $true -Force -Scope Local
        $PluginExe = Join-Path $testRoot 'age-plugin-phone.exe'
        $Apk = Join-Path $testRoot 'candidate.apk'
        $IdentityStub = Join-Path $testRoot 'public-stub.txt'
        $NonmatchingIdentityStub = if ($WithNonmatch) { Join-Path $testRoot 'nonmatching-stub.txt' } else { '' }
        foreach ($path in @($PluginExe, $Apk, $IdentityStub, $NonmatchingIdentityStub)) {
            if ($path) { Set-Content -LiteralPath $path -Value 'fixture-only' }
        }
        $ExpectedExeSha256 = (Get-FileHash -LiteralPath $PluginExe).Hash.ToLowerInvariant()
        $ExpectedApkSha256 = (Get-FileHash -LiteralPath $Apk).Hash.ToLowerInvariant()
        if ($FailureMode -eq 'wrong-hash') { $ExpectedApkSha256 = '0' * 64 }
        if ($FailureMode -eq 'missing-stub') { Remove-Item -LiteralPath $NonmatchingIdentityStub }
        $Commit = 'a' * 40
        $WorkflowRun = '123'
        $WorkflowAttempt = '1'
        $PhoneRecipient = "age1${RecipientMode}fixture"
        if ($FailureMode -eq 'mode-mismatch') { $PhoneRecipient = 'age1tagfixture' }
        if ($FailureMode -eq 'same-stub') { $NonmatchingIdentityStub = $IdentityStub }
        $ConfigRoot = $testRoot
        $AdbSerial = 'fixture-private-serial'
        $AgeExe = Join-Path $testRoot 'age.exe'
        $AgeKeygenExe = Join-Path $testRoot 'age-keygen.exe'
        $AdbExe = Join-Path $testRoot 'adb.exe'
        $ReportPath = Join-Path $testRoot ([Guid]::NewGuid().ToString('N') + '.json')
        $state = @{ Probe = ''; Unwraps = 0; FixtureDirectory = ''; Calls = 0 }
        $before = @{}
        $names = @('PATH', 'AGE_PLUGIN_PHONE_CONFIG_DIR', 'AGE_PLUGIN_PHONE_TRANSPORT',
            'AGE_PLUGIN_PHONE_ADB_SERIAL', 'AGE_PLUGIN_PHONE_WIFI_ADDRESS', 'AGE_PLUGIN_PHONE_MESSAGES')
        foreach ($name in $names) { $before[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
        function Get-Command {
            param([string]$Name, [string]$CommandType, [string]$ErrorAction)
            if ($Name -eq 'adb.exe') { return [pscustomobject]@{ Source = $AdbExe } }
            return [pscustomobject]@{ Source = $Name }
        }
        function Request-AcceptanceConfirmation {
            param([string]$Instruction, [string]$Confirmation)
            if ($FailureMode -eq 'preflight-unobserved') { return $false }
            if ($FailureMode -eq 'unobserved' -and $state.Unwraps -eq 1 -and $Confirmation -eq 'OBSERVED') { return $false }
            if ($FailureMode -eq 'stopped' -and $Confirmation -eq 'READY') { return $false }
            return $true
        }
        function Invoke-AcceptanceProcess {
            param([string]$File, [string[]]$Arguments, [int]$TimeoutSeconds = 120)
            $state.Calls++
            $response = [pscustomobject]@{ ExitCode = 0; Output = ''; DiagnosticCategory = 'none' }
            if ($File -eq $PluginExe) {
                if ($Arguments[0] -eq '--version') {
                    $response.Output = if ($FailureMode -eq 'wrong-version') { 'age-plugin-phone 0.1.0-beta.1' } else { "age-plugin-phone $Version" }
                }
                elseif ($Arguments[0] -eq 'recipients') {
                    if ($Arguments[1] -cne '--identity' -or $Arguments[3] -cne '--recipient-type' -or $Arguments[4] -cne $RecipientMode) {
                        throw 'Wrong public-stub validation invocation.'
                    }
                    $response.Output = if ($Arguments[2] -ceq $IdentityStub) { $PhoneRecipient } else { "age1${RecipientMode}different" }
                    if ($FailureMode -eq 'invalid-stub') { $response.ExitCode = 1; $response.DiagnosticCategory = 'other-error' }
                    if ($FailureMode -eq 'wrong-matching-recipient' -and $Arguments[2] -ceq $IdentityStub) { $response.Output = "age1${RecipientMode}different" }
                    if ($FailureMode -eq 'same-recipient') { $response.Output = $PhoneRecipient }
                } else { $response.Output = 'windows_alpha_support: supported' }
            } elseif ($File -eq $AdbExe) {
                if ($Arguments -contains 'get-state') { $response.Output = 'device' }
                elseif ($FailureMode -eq 'residue' -and $state.Unwraps -gt 0) { $response.Output = 'private-reverse-fixture' }
            } elseif ($File -eq $AgeKeygenExe) {
                if ($Arguments[0] -eq '-y') { $response.Output = 'age1fixture' }
                else { Set-Content -LiteralPath $Arguments[1] -Value 'private-recovery-fixture' }
            } elseif ($File -eq $AgeExe) {
                $outputFile = $Arguments[[Array]::IndexOf($Arguments, '-o') + 1]
                if ($Arguments[0] -eq '-e') {
                    if ($Arguments[2] -cne $PhoneRecipient) { throw 'Wrong encryption recipient.' }
                    $state.Probe = $Arguments[-1]
                    $state.FixtureDirectory = Split-Path -Parent $state.Probe
                    Set-Content -LiteralPath $outputFile -Value 'ciphertext-fixture'
                } else {
                    $caseName = [IO.Path]::GetFileNameWithoutExtension($outputFile)
                    if ($caseName -ne 'recovery') { $state.Unwraps++ }
                    if ($FailureMode -eq 'timeout' -and $state.Unwraps -eq 2) { throw 'harness_timeout' }
                    if ($FailureMode -eq 'launch' -and $state.Unwraps -eq 1) { throw 'process_start_failed' }
                    if ($caseName -in @('nonmatch-then-match', 'nonmatch-then-cancel')) {
                        if (($Arguments[1..4] -join '|') -cne (@('-i', $NonmatchingIdentityStub, '-i', $IdentityStub) -join '|')) {
                            throw 'Nonmatch must precede matching identity without recovery identity.'
                        }
                    } elseif ($caseName -eq 'nonmatch-only') {
                        if ($Arguments[2] -cne $NonmatchingIdentityStub -or @($Arguments | Where-Object { $_ -eq '-i' }).Count -ne 1) {
                            throw 'Nonmatch isolation failed.'
                        }
                    } elseif ($caseName -ne 'recovery' -and $Arguments[2] -cne $IdentityStub) { throw 'Wrong matching identity.' }
                    if ($caseName -in @('nonmatch-only', 'nonmatch-then-cancel', 'usb-cancel', 'wifi-background', 'wifi-paused')) { $response.ExitCode = 1 }
                    else { Copy-Item -LiteralPath $state.Probe -Destination $outputFile }
                    if ($caseName -eq 'nonmatch-only') { $response.DiagnosticCategory = 'identity-miss' }
                    if ($FailureMode -eq 'wrong-negative-reason' -and $caseName -eq 'nonmatch-only') { $response.DiagnosticCategory = 'other-error' }
                    if (($FailureMode -eq 'negative-stdout' -and $caseName -eq 'nonmatch-only') -or
                        ($FailureMode -eq 'positive-stdout' -and $caseName -eq 'nonmatch-then-match') -or
                        ($FailureMode -eq 'recovery-stdout' -and $caseName -eq 'recovery')) { $response.Output = 'synthetic-unexpected-stdout' }
                    if ($FailureMode -eq 'negative-output' -and $caseName -eq 'nonmatch-only') { Copy-Item -LiteralPath $state.Probe -Destination $outputFile }
                    if ($FailureMode -eq 'crash' -and $caseName -eq 'nonmatch-only') { $response.ExitCode = 7 }
                }
            } else { throw 'Unexpected fixture executable.' }
            return $response
        }
        if ($PreflightError) {
            Expect-Failure { Invoke-MinimalAcceptance } $PreflightError
            if ($state.Calls -ne 0 -or (Test-Path -LiteralPath $ReportPath)) { throw 'Invalid inputs reached execution.' }
            return
        }
        $failureCategories = @{
            timeout = 'harness_timeout'; residue = 'adb_reverse_residue'; launch = 'process_start_failed'
            unobserved = 'observation_not_confirmed'; stopped = 'operator_stopped'
            'negative-output' = 'negative_case_released_output'; crash = 'unexpected_exit_code'
            'preflight-unobserved' = 'observation_not_confirmed'; 'wrong-version' = 'wrong_plugin_version'
            'invalid-stub' = 'invalid_identity_stub'; 'same-recipient' = 'identity_recipient_mismatch'
            'wrong-matching-recipient' = 'identity_recipient_mismatch'; 'wrong-negative-reason' = 'unexpected_identity_failure'
            'negative-stdout' = 'unexpected_stdout'; 'positive-stdout' = 'unexpected_stdout'; 'recovery-stdout' = 'unexpected_stdout'
        }
        if ($FailureMode -eq 'passed') { Invoke-MinimalAcceptance }
        else { Expect-Failure { Invoke-MinimalAcceptance } $failureCategories[$FailureMode] }
        $raw = Get-Content -LiteralPath $ReportPath -Raw
        $report = $raw | ConvertFrom-Json
        if ($FailureMode -eq 'passed') {
            $expectedUnwraps = if ($WithNonmatch) { 11 } else { 8 }
            $expectedNotRun = if ($WithNonmatch) { 0 } else { 3 }
            if ($report.status -ne 'passed-minimal-unwrap-only' -or $report.rows.Count -ne 15 -or $state.Unwraps -ne $expectedUnwraps -or
                @($report.rows | Where-Object result -eq 'not-run').Count -ne $expectedNotRun) {
                throw 'Successful orchestration missed required rows.'
            }
        } elseif ($report.status -ne 'failed' -or $state.Unwraps -gt 2) { throw 'Failed run retried or lost its failure report.' }
        if ($report.schema_version -ne 2 -or $report.recipient_mode -cne $RecipientMode -or $report.multi_identity -ne $WithNonmatch) {
            throw 'Report scope mismatch.'
        }
        if ($FailureMode -ne 'passed' -and (@($report.rows | Where-Object result -eq 'not-run').Count -eq 0 -or
            @($report.rows | Where-Object result -eq 'failed-or-unobserved').Count -ne 1)) { throw 'Incomplete run reported as complete.' }
        if (-not $report.synthetic_files_removed -or ($state.FixtureDirectory -and (Test-Path -LiteralPath $state.FixtureDirectory))) { throw 'Fixture directory not removed.' }
        foreach ($name in $names) {
            if ([Environment]::GetEnvironmentVariable($name, 'Process') -cne $before[$name]) { throw "Environment was not restored: $name" }
        }
        Assert-NoPrivateEvidence ($raw | ConvertFrom-Json -AsHashtable) @(
            $testRoot, $IdentityStub, $NonmatchingIdentityStub, $AdbSerial, $PhoneRecipient,
            'private-recovery-fixture', 'private-reverse-fixture', 'synthetic-unexpected-stdout')
        try { Invoke-MinimalAcceptance; throw 'Existing report was overwritten.' }
        catch [IO.IOException] { } # CreateNew must retain the prior failed or successful report.
        if ((Get-Content -LiteralPath $ReportPath -Raw) -cne $raw) { throw 'Prior evidence changed.' }
    }
    Test-Orchestration 'passed'
    Test-Orchestration 'passed' '0.1.0-beta.2' 'tag'
    # Synthetic version tests parameter handling, not compatibility with an old binary.
    Test-Orchestration 'passed' '0.1.0-alpha.99' 'phone' $false
    foreach ($failure in @('timeout', 'residue', 'launch', 'unobserved', 'stopped', 'negative-output', 'crash', 'preflight-unobserved', 'wrong-version',
        'invalid-stub', 'same-recipient', 'wrong-matching-recipient', 'wrong-negative-reason', 'negative-stdout', 'positive-stdout', 'recovery-stdout')) {
        Test-Orchestration $failure
    }
    foreach ($version in @('0.1.0', '0.1.0-rc.1', '0.1.0-beta.0', '0.1.0-beta.2-extra', '0.1.0-BETA.2')) {
        Test-Orchestration 'passed' $version 'phone' $true 'invalid candidate provenance'
    }
    Test-Orchestration 'passed' '0.1.0-beta.2' 'phone' $false 'requires a nonmatching'
    Test-Orchestration 'same-stub' '0.1.0-beta.2' 'phone' $true 'must be distinct'
    Test-Orchestration 'mode-mismatch' '0.1.0-beta.2' 'phone' $true 'recipient mode'
    Test-Orchestration 'wrong-hash' '0.1.0-beta.2' 'phone' $true 'digest mismatch'
    Test-Orchestration 'missing-stub' '0.1.0-beta.2' 'phone' $true 'absolute existing files'
    Write-Host 'Minimum acceptance output, process, timeout, observation, report and restoration fixtures passed.'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
