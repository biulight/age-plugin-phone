#requires -Version 7.2
<#
.SYNOPSIS
Owner-assisted synthetic-data regression for one verified Windows/Android candidate pair.
.DESCRIPTION
Run after independent signature verification and fresh, full-fingerprint managed setup.
Never run under Start-Transcript. Only the JSON report is intended for shared evidence.
The script never confirms pairing, performs phone authentication, edits replay state,
installs an APK, changes firewall rules, or deletes a pairing. See the alpha.4 checklist.
#>
[CmdletBinding()]
param(
    [string]$PluginExe,
    [string]$Apk,
    [string]$ExpectedExeSha256,
    [string]$ExpectedApkSha256,
    [string]$Commit,
    [string]$WorkflowRun,
    [string]$WorkflowAttempt,
    [string]$Version,
    [string]$IdentityStub,
    [string]$PhoneRecipient,
    [string]$ReportPath,
    [string]$ConfigRoot,
    [string]$AdbSerial,
    [string]$AgeExe = 'age.exe',
    [string]$AgeKeygenExe = 'age-keygen.exe',
    [string]$AdbExe = 'adb.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-AcceptanceProcess {
    param([string]$File, [string[]]$Arguments, [int]$TimeoutSeconds = 120)
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'process_start_failed' }
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw 'harness_timeout' # Never count a killed process as an expected negative.
        }
        $output = $stdout.GetAwaiter().GetResult()
        $null = $stderr.GetAwaiter().GetResult() # Do not print or save native diagnostics.
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $output }
    } finally {
        $process.Dispose()
    }
}

function Assert-AcceptanceOutput {
    param([int]$ExitCode, [string]$OutputPath, [string]$Digest, [bool]$ExpectSuccess)
    $exists = Test-Path -LiteralPath $OutputPath -PathType Leaf
    if ($ExpectSuccess) {
        if ($ExitCode -ne 0 -or -not $exists) { throw 'decrypt_failed' }
        if ((Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash -ne $Digest) {
            throw 'digest_mismatch'
        }
    } elseif ($ExitCode -eq 0 -or ($exists -and (Get-Item -LiteralPath $OutputPath).Length -ne 0)) {
        throw 'negative_case_released_output'
    }
}

function Confirm-AcceptanceObservation {
    param([string]$Instruction)
    if ((Read-Host "$Instruction Type OBSERVED only if personally observed") -cne 'OBSERVED') {
        throw 'observation_not_confirmed'
    }
}

function Invoke-MinimalAcceptance {
    # Parameters are script-scoped so dot-sourcing exposes only helpers for fixture tests.
    if (-not $IsWindows) { throw 'This physical regression requires Windows and PowerShell 7.' }
    foreach ($hash in @($ExpectedExeSha256, $ExpectedApkSha256)) {
        if ($hash -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid expected artifact SHA-256.' }
    }
    if ($Commit -cnotmatch '^[0-9a-f]{40}$' -or $WorkflowRun -notmatch '^[1-9][0-9]*$' -or
        $WorkflowAttempt -notmatch '^[1-9][0-9]*$' -or $Version -notmatch '^\d+\.\d+\.\d+-alpha\.\d+$') {
        throw 'Missing or invalid candidate provenance.'
    }
    foreach ($path in @($PluginExe, $Apk, $IdentityStub)) {
        if (-not [IO.Path]::IsPathFullyQualified($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'Candidate and public stub paths must be absolute existing files.'
        }
    }
    if ([IO.Path]::GetFileName($PluginExe) -cne 'age-plugin-phone.exe' -or
        $PhoneRecipient -cnotmatch '^age1phone[0-9a-z]+$') { throw 'Invalid plugin name or phone recipient.' }
    if ((Get-FileHash -LiteralPath $PluginExe).Hash.ToLowerInvariant() -cne $ExpectedExeSha256 -or
        (Get-FileHash -LiteralPath $Apk).Hash.ToLowerInvariant() -cne $ExpectedApkSha256) {
        throw 'Candidate artifact digest mismatch.'
    }
    if (-not [IO.Path]::IsPathFullyQualified($ReportPath)) { throw 'Report path must be absolute.' }
    if ($ConfigRoot -and -not [IO.Path]::IsPathFullyQualified($ConfigRoot)) {
        throw 'Configuration root must be absolute and match the fresh setup.'
    }
    foreach ($name in @('AgeExe', 'AgeKeygenExe', 'AdbExe')) {
        $resolved = (Get-Command (Get-Variable $name -ValueOnly) -CommandType Application -ErrorAction Stop).Source
        Set-Variable $name $resolved
    }
    if ([IO.Path]::GetFileName($AdbExe) -ine 'adb.exe') { throw 'ADB must retain its executable name.' }

    # Reserve a new report before creating synthetic files or invoking any phone operation.
    $reportStream = [IO.File]::Open($ReportPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    $report = [ordered]@{
        schema_version = 1; scope = 'owner-only-minimal-unwrap'; status = 'incomplete'
        version = $Version; commit = $Commit; workflow_run = $WorkflowRun; workflow_attempt = $WorkflowAttempt
        exe_sha256 = $ExpectedExeSha256; apk_sha256 = $ExpectedApkSha256
        started_utc = [DateTime]::UtcNow.ToString('o'); rows = [Collections.Generic.List[object]]::new()
    }
    $environmentNames = @('PATH', 'AGE_PLUGIN_PHONE_CONFIG_DIR', 'AGE_PLUGIN_PHONE_TRANSPORT',
        'AGE_PLUGIN_PHONE_ADB_SERIAL', 'AGE_PLUGIN_PHONE_WIFI_ADDRESS', 'AGE_PLUGIN_PHONE_MESSAGES')
    $savedEnvironment = @{}
    foreach ($name in $environmentNames) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    $fixture = $null
    $stage = 'preflight'
    try {
        $env:PATH = "$(Split-Path -Parent $PluginExe);$(Split-Path -Parent $AdbExe);$env:PATH"
        # A current-directory executable can precede PATH on Windows.
        $shadow = Join-Path (Get-Location).Path 'age-plugin-phone.exe'
        if ((Test-Path -LiteralPath $shadow) -and
            [IO.Path]::GetFullPath($shadow) -ne [IO.Path]::GetFullPath($PluginExe)) { throw 'shadowed_plugin' }
        $shadowAdb = Join-Path (Get-Location).Path 'adb.exe'
        if ((Test-Path -LiteralPath $shadowAdb) -and
            [IO.Path]::GetFullPath($shadowAdb) -ne [IO.Path]::GetFullPath($AdbExe)) { throw 'shadowed_adb' }
        if ((Get-Command adb.exe -CommandType Application).Source -ne $AdbExe) { throw 'shadowed_adb' }
        $env:AGE_PLUGIN_PHONE_CONFIG_DIR = $ConfigRoot
        $env:AGE_PLUGIN_PHONE_ADB_SERIAL = $AdbSerial
        $env:AGE_PLUGIN_PHONE_WIFI_ADDRESS = $null
        $env:AGE_PLUGIN_PHONE_MESSAGES = $null
        $env:AGE_PLUGIN_PHONE_TRANSPORT = 'adb'
        $result = Invoke-AcceptanceProcess $PluginExe @('--version')
        if ($result.ExitCode -ne 0 -or $result.Output.Trim() -cne "age-plugin-phone $Version") { throw 'wrong_plugin_version' }
        $result = Invoke-AcceptanceProcess $PluginExe @('status')
        if ($result.ExitCode -ne 0 -or $result.Output -notmatch '(?m)^windows_alpha_support: supported\r?$') {
            throw 'capability_probe_failed'
        }
        $adbSelection = @()
        if ($AdbSerial) { $adbSelection = @('-s', $AdbSerial) }
        $result = Invoke-AcceptanceProcess $AdbExe ($adbSelection + @('get-state'))
        if ($result.ExitCode -ne 0 -or $result.Output.Trim() -cne 'device') { throw 'adb_selection_failed' }

        function Assert-NoReverseRules {
            $reverse = Invoke-AcceptanceProcess $AdbExe ($adbSelection + @('reverse', '--list'))
            if ($reverse.ExitCode -ne 0 -or $reverse.Output.Trim().Length -ne 0) { throw 'adb_reverse_residue' }
        }
        Assert-NoReverseRules
        Confirm-AcceptanceObservation 'Verified signatures/provenance; this exact normal APK is installed; status supports TPM/StrongBox; fresh setup compared the complete fingerprint on both endpoints.'
        $report.rows.Add(@{ case = 'preflight'; result = 'passed'; observer = $true })
        $fixture = Join-Path ([IO.Path]::GetTempPath()) ('age-phone-minimal-' + [Guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $fixture
        $probe = Join-Path $fixture 'synthetic.bin'
        $ciphertext = Join-Path $fixture 'synthetic.age'
        $recovery = Join-Path $fixture 'disposable-recovery.txt'
        [IO.File]::WriteAllBytes($probe, [Text.Encoding]::UTF8.GetBytes('synthetic age-plugin-phone minimum regression'))
        $digest = (Get-FileHash -LiteralPath $probe).Hash
        $stage = 'encrypt'
        $result = Invoke-AcceptanceProcess $AgeKeygenExe @('-o', $recovery)
        if ($result.ExitCode -ne 0) { throw 'recovery_generation_failed' }
        $result = Invoke-AcceptanceProcess $AgeKeygenExe @('-y', $recovery)
        if ($result.ExitCode -ne 0 -or $result.Output.Trim() -cnotmatch '^age1[0-9a-z]+$') { throw 'recovery_recipient_failed' }
        $result = Invoke-AcceptanceProcess $AgeExe @('-e', '-r', $PhoneRecipient, '-r', $result.Output.Trim(), '-o', $ciphertext, $probe)
        if ($result.ExitCode -ne 0) { throw 'encryption_failed' }
        $stage = 'independent-recovery'
        $output = Join-Path $fixture 'recovery.bin'
        $result = Invoke-AcceptanceProcess $AgeExe @('-d', '-i', $recovery, '-o', $output, $ciphertext)
        Assert-AcceptanceOutput $result.ExitCode $output $digest $true
        $report.rows.Add(@{ case = $stage; result = 'passed'; output_sha256 = $digest.ToLowerInvariant() })

        $cases = @(
            @('usb-approve-1', 'adb', $true, 'Approve on the phone using fresh biometrics.'),
            @('usb-approve-2', 'adb', $true, 'Approve again; a NEW biometric operation is required.'),
            @('usb-cancel', 'adb', $false, 'Wait for the native authorization prompt, then Cancel it.'),
            @('usb-after-cancel', 'adb', $true, 'Approve this fresh request without restarting the phone app.'),
            @('wifi-approve', 'wifi', $true, 'Enable Wi-Fi auto-listen and keep the phone visible; approve with fresh biometrics.'),
            @('wifi-background', 'wifi', $false, 'Wait for the native authorization prompt, then press HOME and hold the launcher for two seconds.'),
            @('wifi-after-background', 'wifi', $true, 'Return to foreground; wait for listening; approve this fresh request without restarting.'),
            @('wifi-paused', 'wifi', $false, 'Pause Wi-Fi auto-listen; keep it paused. Expect no phone prompt and no USB fallback.')
        )
        foreach ($case in $cases) {
            $stage = $case[0]
            Write-Host "$stage`: $($case[3])"
            if ((Read-Host 'Type READY to start this single attempt') -cne 'READY') { throw 'operator_stopped' }
            $env:AGE_PLUGIN_PHONE_TRANSPORT = $case[1]
            $output = Join-Path $fixture "$stage.bin"
            $timer = [Diagnostics.Stopwatch]::StartNew()
            $result = Invoke-AcceptanceProcess $AgeExe @('-d', '-i', $IdentityStub, '-o', $output, $ciphertext)
            $timer.Stop()
            Assert-AcceptanceOutput $result.ExitCode $output $digest $case[2]
            Assert-NoReverseRules
            Confirm-AcceptanceObservation "$($case[3]) Observed the intended event and recovery to usable phone UI."
            $report.rows.Add(@{ case = $stage; result = 'passed'; exit_code = $result.ExitCode
                elapsed_ms = $timer.ElapsedMilliseconds; observer = $true; adb_reverse_count = 0 })
        }
        $stage = 'final-audit'
        Assert-NoReverseRules
        Confirm-AcceptanceObservation 'Wi-Fi auto-listen is paused and phone controls are enabled.'
        $report.rows.Add(@{ case = $stage; result = 'passed'; observer = $true; adb_reverse_count = 0 })
        $report.status = 'passed-minimal-unwrap-only'
    } catch {
        $category = 'harness_error'
        $allowed = @('process_start_failed', 'harness_timeout', 'decrypt_failed', 'digest_mismatch',
            'negative_case_released_output', 'observation_not_confirmed', 'shadowed_plugin', 'shadowed_adb',
            'wrong_plugin_version', 'capability_probe_failed', 'adb_selection_failed', 'adb_reverse_residue',
            'recovery_generation_failed', 'recovery_recipient_failed', 'encryption_failed', 'operator_stopped')
        if ($_.Exception.Message -cin $allowed) { $category = $_.Exception.Message }
        $report.rows.Add(@{ case = $stage; result = 'failed-or-unobserved'; category = $category })
        $report.status = 'failed'
        # Original exceptions/command arguments may contain private paths; never put them in evidence.
        throw "Minimal acceptance stopped at $stage ($category). Preserve this failed report; follow the checklist for diagnosis and a fresh run."
    } finally {
        foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
        try {
            if ($fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
            $report.synthetic_files_removed = $true
        } catch {
            $report.synthetic_files_removed = $false
            $report.status = 'failed'
        }
        $report.finished_utc = [DateTime]::UtcNow.ToString('o')
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes(($report | ConvertTo-Json -Depth 6))
            $reportStream.Write($bytes, 0, $bytes.Length)
        } finally { $reportStream.Dispose() }
    }
    if ($report.status -ne 'passed-minimal-unwrap-only') { throw 'Synthetic-file cleanup failed; see local report.' }
    Write-Host 'Minimal unwrap checks passed. Pairing UI, upgrade, signature, and official cleanup checklist rows remain separate gates.'
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-MinimalAcceptance }
