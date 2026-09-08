#requires -Version 7.2
# Synthetic files only. Never use Start-Transcript or print process output/key files.
param([ValidateSet('prepare','baseline','candidate','cancel','after-cancel')][string]$Stage)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = 'D:\Github\Biulight\age-phone-hardware-20260908'
$fixture = "$root-fixture"
$baseline = 'D:\Github\Biulight\age-phone-baseline-20260908\target\debug\age-plugin-phone.exe'
$candidate = 'D:\Github\Biulight\age-phone-registry-final-20260908\install\bin\age-plugin-phone.exe'
$probe = 'D:\Github\Biulight\age-phone-refactor-20260908\target\debug\phone-refactor-hardware-probe.exe'
function Run-CheckedProcess([string]$File, [string[]]$Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.WorkingDirectory = $fixture
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($arg in $Arguments) { $info.ArgumentList.Add($arg) }
    $p = [Diagnostics.Process]::new()
    $p.StartInfo = $info
    try {
        if (-not $p.Start()) { throw 'process_start_failed' }
        $p.StandardInput.Close()
        $out = $p.StandardOutput.ReadToEndAsync()
        $err = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(120000)) { $p.Kill($true); $p.WaitForExit(); throw 'harness_timeout' }
        $text = $out.GetAwaiter().GetResult()
        $null = $err.GetAwaiter().GetResult()
        return [pscustomobject]@{ Code = $p.ExitCode; Text = $text }
    } finally { $p.Dispose() }
}
function Require-Zero($result) { if ($result.Code -ne 0) { throw 'child_failed' } }
function Bindings {
    $map = @{}
    Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Name -notlike 'replay-*' -and $_.Name -notlike '*.lock' } | ForEach-Object {
        $map[$_.Name] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    }
    return $map
}
try {
    if ((Get-FileHash $baseline).Hash -ne 'E832B98C1F41EC7D784A6BE1F73FAD75D38989A822739CFE27EDA3D3E2C6F6BF') { throw 'baseline_digest_failed' }
    if ((Get-FileHash $candidate).Hash -ne '3681F58271E279FB016B6AC597773FBF9DC9105711BF75B8D38F5FD13AB53A78') { throw 'candidate_digest_failed' }
    $setup = Get-Content -LiteralPath "$root-public.json" -Raw | ConvertFrom-Json
    if ($setup.schema_version -ne 1 -or -not (Test-Path -LiteralPath $setup.identity_path)) { throw 'setup_missing' }
    if (-not ([IO.Path]::GetFullPath($setup.identity_path).StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase))) { throw 'wrong_test_root' }
    $env:AGE_PLUGIN_PHONE_CONFIG_DIR = $root
    $env:AGE_PLUGIN_PHONE_TRANSPORT = 'adb'
    $env:AGE_PLUGIN_PHONE_MESSAGES = $null
    $env:AGE_PLUGIN_PHONE_WIFI_ADDRESS = $null
    $env:AGE_PLUGIN_PHONE_ADB_SERIAL = $null
    $exe = if ($Stage -in @('prepare','baseline')) { $baseline } else { $candidate }
    $env:PATH = "$(Split-Path -Parent $exe);$env:PATH"
    $age = (Get-Command age.exe).Source
    $keygen = (Get-Command age-keygen.exe).Source
    if ($Stage -eq 'prepare') {
        if (Test-Path -LiteralPath $fixture) { throw 'fixture_already_exists' }
        $null = New-Item -ItemType Directory -Path $fixture
        [IO.File]::WriteAllBytes("$fixture\synthetic.bin", [Security.Cryptography.RandomNumberGenerator]::GetBytes(64))
        Require-Zero (Run-CheckedProcess $keygen @('-o', "$fixture\recovery.txt"))
        $recovery = Run-CheckedProcess $keygen @('-y', "$fixture\recovery.txt")
        Require-Zero $recovery
        Require-Zero (Run-CheckedProcess $age @('-e','-r',$setup.recipient,'-r',$recovery.Text.Trim(),'-o',"$fixture\synthetic.age","$fixture\synthetic.bin"))
        Require-Zero (Run-CheckedProcess $age @('-d','-i',"$fixture\recovery.txt",'-o',"$fixture\recovered.bin","$fixture\synthetic.age"))
        if ((Get-FileHash "$fixture\synthetic.bin").Hash -ne (Get-FileHash "$fixture\recovered.bin").Hash) { throw 'recovery_mismatch' }
        Bindings | ConvertTo-Json | Set-Content "$fixture\bindings.json"
        Write-Output 'synthetic_encryption=PASS independent_recovery=PASS'
        exit 0
    }
    $original = Get-Content "$fixture\bindings.json" -Raw | ConvertFrom-Json -AsHashtable
    $current = Bindings
    if ($current.Count -ne $original.Count) { throw 'binding_count_changed' }
    foreach ($name in $original.Keys) { if ($current[$name] -ne $original[$name]) { throw 'binding_bytes_changed' } }
    $output = "$fixture\$Stage.bin"
    if (Test-Path -LiteralPath $output) { throw 'stage_output_exists' }
    $result = Run-CheckedProcess $age @('-d','-i',$setup.identity_path,'-o',$output,"$fixture\synthetic.age")
    if ($Stage -eq 'cancel') {
        if ($result.Code -eq 0 -or ((Test-Path $output) -and (Get-Item $output).Length -ne 0)) { throw 'negative_released_output' }
        Write-Output 'cancel_no_output=PASS owner_native_cancellation_observation_required=true'
    } else {
        Require-Zero $result
        if ((Get-FileHash "$fixture\synthetic.bin").Hash -ne (Get-FileHash $output).Hash) { throw 'decrypt_mismatch' }
        Write-Output "$Stage`_decrypt=PASS"
        if ($Stage -eq 'baseline') {
            $replay = Run-CheckedProcess $probe @('stored-response',$root,$setup.identity_path)
            Require-Zero $replay
            if ($replay.Text.Trim() -ne 'stored_response_replay=PASS clock_rollback=PASS state_unchanged=PASS existing_key_binding=PASS') { throw 'probe_report_invalid' }
            Write-Output $replay.Text.Trim()
        }
    }
    $current = Bindings
    foreach ($name in $original.Keys) { if ($current[$name] -ne $original[$name]) { throw 'binding_bytes_changed' } }
    Write-Output 'stub_locator_tpm_metadata_unchanged=PASS'
} catch {
    Write-Output "stage_failed=$Stage"
    exit 1
}
