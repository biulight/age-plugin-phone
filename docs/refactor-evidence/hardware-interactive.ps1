#requires -Version 7.2
param([ValidateSet('approve-replay','cancel-replay','cleanup')][string]$Action)
$ErrorActionPreference = 'Stop'
$root = 'D:\Github\Biulight\age-phone-hardware-20260908'
$setup = Get-Content -LiteralPath "$root-public.json" -Raw | ConvertFrom-Json
if (-not ([IO.Path]::GetFullPath($setup.identity_path).StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase))) { throw 'wrong_test_root' }
Set-Location "$root-fixture"
$env:AGE_PLUGIN_PHONE_CONFIG_DIR = $root
if ($Action -eq 'cleanup') {
    & 'D:\Github\Biulight\age-phone-registry-final-20260908\install\bin\age-plugin-phone.exe' remove-desktop-state --identity-stub $setup.identity_path
} else {
    & 'D:\Github\Biulight\age-phone-refactor-20260908\target\debug\phone-refactor-hardware-probe.exe' $Action $root $setup.identity_path
}
exit $LASTEXITCODE
