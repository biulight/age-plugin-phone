# alpha.4 release candidate and acceptance checklist

Status: **owner-only physical acceptance passed; published 2026-09-07**. Version: `0.1.0-alpha.4`.
Accepted commit: `5da4b0bc8f3ca6f16f9be1b7430e923baad402b9`.
See the [acceptance and publication record](windows-acceptance-2026-09-07.md) for exact hashes,
original evidence, preserved failures and scope limitations. This checklist was synchronized after
publication; the signed ZIP retains its original pre-acceptance checklist. Published assets are unchanged.

This is the minimum owner-only developer-prerelease gate, not the complete public-Alpha matrix.
The [owner-preview scope](owner-only-preview.md) defines deferred gates. Preserve failed and
unobserved attempts; a later pass gets a new record and never erases the earlier result.

## Accepted candidate provenance

| Field | Required value |
| --- | --- |
| Candidate commit | `5da4b0bc8f3ca6f16f9be1b7430e923baad402b9` |
| CI | [34110138123](https://github.com/biulight/age-plugin-phone/actions/runs/34110138123), exact SHA, passed |
| Signing | [34110640981](https://github.com/biulight/age-plugin-phone/actions/runs/34110640981), attempt 1, both platforms passed |
| Windows ZIP / EXE, Android normal APK | Exact SHA-256 values in the [acceptance record](windows-acceptance-2026-09-07.md) |
| Signers | Registered certificate SHA-256 values in the original evidence linked from that record |
| Physical environment | Windows 11 build 22631 x64 / TPM 2.0; Android 16 / StrongBox; age 1.3.1, ADB 1.0.41 |
| Physical result | Passed 2026-09-07; zero unresolved required rows; full public-Alpha matrix deferred |

- [x] Version manifests and Cargo.lock agree on alpha.4; release notes and changelog reviewed.
- [x] `cargo fmt --all --check`, strict locked workspace Clippy, and locked workspace tests pass locally.
- [x] Frozen Bun install and frontend build, Android native negative tests, Swift vectors and iOS
  compile jobs pass in CI. iOS compilation does not establish hardware acceptance.
- [x] Release validator/staging fixtures, minimum-script fixtures, workflow lint and
  `git diff --check` pass locally.
- [x] Candidate working tree is clean and exact-SHA CI is green before signing dispatch.
  Push the candidate on `codex/alpha.4-rc`; CI runs directly on `codex/alpha.*` pushes so its
  tested SHA is the candidate itself, not a temporary pull-request merge commit.
- [x] Dispatch the existing Alpha workflow with the full `expected_commit`; both signing jobs
  succeed. Keep `alpha-release-publish` waiting until the physical gate below is complete.
- [x] Independently verify the six same-run assets and certificate identities using the
  [signing runbook](release-signing.md). Confirm ZIP root includes the EXE, quickstart, Wi-Fi guide,
  firewall helper, `windows-minimal-acceptance.ps1`, and this checklist. Never install the test root.

## Historical preparation and superseded attempts

The following records describe earlier states, not the final release status above.

Local preparation on 2026-09-06: local Rust, release-validator, script-fixture, workflow-lint
and diff checks plus frozen Bun install/TypeScript/Vite build passed. PowerShell 7.4.6 on macOS exercised subprocess/output/timeout helpers and simulated
full-run success, failure reporting, no retry, report preservation, environment restoration and
evidence redaction. The simulated host/tool responses are harness tests, not Windows/phone
acceptance. Windows harness CI and the unchanged Android/iOS jobs still need the final candidate
SHA run. No alpha.4 package has been signed or physically tested by this preparation.

Candidate CI `34022371647` at `5695709` exposed a Windows harness environment-restoration
failure: an originally absent variable became an empty variable through .NET string binding.
The follow-up explicitly removes originally absent variables and preserves existing values;
the replacement candidate must pass a new complete CI run before signing.

Signed candidate `dd5ad4350fe333822a66714374dc9aac9f2cbcf9`, workflow run `34022913877`
attempt 1, passed exact-SHA CI and signing but failed physical harness acceptance on Windows 11:
PowerShell `Read-Host` returned end-of-input at the first owner checkpoint. Two scoped preflight
reports retain the failure as `harness_error`; no unwrap request ran and disposable files were
removed. External console adapters are diagnostic history and do not qualify the signed script.
This candidate is superseded and must never be published. Its successful alpha.3-to-alpha.4
in-place upgrade and fresh managed pairing remain physical evidence bound only to that candidate.
The replacement candidate must include native owner dialogs, pass new exact-SHA CI and signing,
and repeat the minimum unwrap and remaining manual gates with its same-run artifacts.

## Exact-package preparation and upgrade

- [x] Use synthetic data and an independent recovery recipient. Record the normal APK's identity
  and pairing state locally before upgrading; keep the separate `.wifipoc` app out of this evidence.
- [x] Verify the installed normal alpha.3 APK and the downloaded alpha.4 APK signers agree. Install
  alpha.4 in place without uninstalling, clearing data, deleting identity or resetting replay state.
  Check version and retained public identity/pairings; perform a fresh biometric decrypt of an
  existing synthetic ciphertext using the alpha.4 EXE and independent recovery of that ciphertext.
  If no alpha.3 installation/pairing exists, mark this row unexecuted and arrange a scoped upgrade
  run; a fresh installation does not count as an upgrade pass.
- [x] Read-only `status` supports Windows 11 x64, TPM 2.0 and Platform Crypto Provider; the installed
  normal APK reports StrongBox availability. One explicit ADB device, zero initial reverse rules.
- [x] Create a fresh alpha.4 managed USB pairing with `setup --json` in a dedicated configuration
  root. Start the desktop command first; while it is waiting, choose **Pair · USB** on the phone.
  Choosing the phone action before the desktop has armed its ADB reverse rule immediately fails with
  `usb_transport_failed`. Owner compares the complete fingerprint on both screens and supplies the
  desktop input. Capture stdout into a local variable only; schema 1, existing public stub, no
  pending setup journal. This fresh pairing is the input to the script below. Never pipe a generated
  confirmation to setup.

## Run the minimum unwrap regression

Use an interactive PowerShell 7.2+ terminal with standard age, age-keygen and ADB installed. Close
other test harnesses/ADB controllers. Disable terminal transcription; only the allowlisted JSON
report is shareable. Match the configuration root used for setup. Hash inputs come from the
independently verified signing evidence, not values invented by the script.

```powershell
$pluginExe = '<absolute verified alpha.4 age-plugin-phone.exe>'
$pluginConfig = '<absolute dedicated configuration root>'
$env:AGE_PLUGIN_PHONE_CONFIG_DIR = $pluginConfig
# Start this command first. While it waits, tap Pair via Developer USB on the phone,
# then compare and enter the FULL fingerprint yourself.
$setupText = & $pluginExe setup --label 'Alpha minimum' --transport adb --json
if ($LASTEXITCODE -ne 0) { throw 'setup failed; follow official resume/cleanup instructions' }
$setup = ($setupText -join "`n") | ConvertFrom-Json
if ($setup.schema_version -ne 1 -or -not (Test-Path -LiteralPath $setup.identity_path)) { throw 'invalid setup result' }
$parameters = @{
    PluginExe = $pluginExe
    Apk = '<absolute verified normal alpha.4 APK>'
    ExpectedExeSha256 = '<64 lowercase hex from verified evidence>'
    ExpectedApkSha256 = '<64 lowercase hex from verified evidence>'
    Commit = '<40-character candidate SHA>'
    WorkflowRun = '<signing run ID>'
    WorkflowAttempt = '<signing attempt>'
    Version = '0.1.0-alpha.4'
    IdentityStub = $setup.identity_path
    PhoneRecipient = $setup.recipient
    ConfigRoot = $pluginConfig
    ReportPath = '<absolute NEW local JSON report path>'
}
# If multiple devices exist, also select the SAME serial during setup and here:
# $parameters.AdbSerial = $adbSerial
& .\scripts\windows-minimal-acceptance.ps1 @parameters
```

From the extracted Windows ZIP, use `.\windows-minimal-acceptance.ps1`. Setup is performed once;
if the fresh pairing above already exists, reuse its local `$setup` values. Select the exact age,
age-keygen or ADB executable with `AgeExe`, `AgeKeygenExe` or `AdbExe` if PATH is ambiguous.
The script pins the candidate plugin directory and each transport, clears inherited Wi-Fi address
and message overrides, and restores its process environment on completion. It does not install or
verify the running phone APK automatically: installation and identity observations are manual gates.

| Script row | Required outcome |
| --- | --- |
| Independent recovery | Same synthetic ciphertext decrypts byte-for-byte with disposable independent identity |
| USB approve 1 and 2 | Two successful digest matches, owner observes a new biometric operation each time |
| USB cancel | Native prompt observed and cancelled; nonzero exit, absent/empty output |
| USB after cancel | Fresh request succeeds without app restart or replay repair |
| Wi-Fi approve | Foreground auto-listen; explicit Wi-Fi succeeds with new biometric authorization |
| Wi-Fi background | Observe native prompt first, HOME for two seconds; nonzero exit, absent/empty output |
| Wi-Fi after background | Return, ready listener, new request succeeds without app restart |
| Wi-Fi paused | Pause listener; explicit Wi-Fi fails without phone prompt or USB fallback |
| Final audit | Listener paused, controls enabled, zero reverse rules, disposable files removed |

Each unwrap row checks output and zero ADB reverse rules and requires an explicit owner observation.
The Windows script uses fail-closed native Yes/No dialogs for READY and OBSERVED checkpoints; it
does not depend on terminal stdin or `Read-Host`. Select **Yes** only after reading the complete
instruction and personally satisfying that checkpoint.
The script waits at most 120 seconds per native process. A harness timeout is a failure, never a
successful product timeout test. There is no automatic retry. A failed/unattended observation
stops the run; keep the report, diagnose with [the Wi-Fi guide](windows-wifi.md), then use a new
report filename for a fresh run. The script removes only its disposable fixture directory and
restores environment variables. It retains all pairing/replay state and never removes ADB rules.
After failure, independently audit processes, reverse rules and phone state before continuing.

## Manual alpha.4 regression — required owner-only rows passed

Use fresh temporary pairings for interruption rows. Observe the launcher for at least two seconds
when backgrounding; an immediate HOME/return sequence is insufficient evidence of Activity stop.

| Row | Acceptance |
| --- | --- |
| USB pairing success/loading | Start desktop setup first, then tap Pair USB; spinner and disabled control while pending, full-fingerprint success, controls enabled |
| USB native Cancel | Pending native comparison dismissed; controls enabled; unconfirmed desktop state rolled back |
| USB comparison background | HOME while native comparison is open; returning shows enabled controls and cancelled operation, no stale confirmation |
| USB fresh operation | New pairing succeeds after interruption without app restart |
| Wi-Fi pairing success/loading | Tap one-shot Pair Wi-Fi first, then start desktop setup; full comparison, success and usable UI |
| Wi-Fi listener timeout | Observed timeout clears loading; a new click opens a fresh listener without restart |
| Wi-Fi native Cancel/background | Exercise both separately while native comparison is open; dismiss confirmation, enable controls, rollback unconfirmed state |
| Wi-Fi fresh operation | New pairing succeeds after interruptions; auto-listen becomes ready |
| Discovery transitions | At most three `wifi-doctor --identity-stub` windows after pairing, decrypt and return to foreground; record delay, elapsed time, result and rule state |
| Firewall helper | Inspect and WhatIf; any authorized change restricted to exact EXE/interface; restore original state. Absent-rule success is not a clean-VM pass |

Record each manual row as passed, failed, or unexecuted, with artifact binding and coarse timing.
Retain timeouts, late confirmations and unattended attempts with their real classification. A
phone-confirmed/desktop-expired pairing may leave a phone orphan requiring explicit native
revocation; never promote that attempt to success. Do not lengthen production discovery or reset
replay state to obtain a pass. A historical unexplained discovery failure remains historical;
record any new failure and resolve its release impact before promotion.

## Cleanup and promotion

- [x] Verify recovery for all retained synthetic ciphertexts before retiring test pairings.
- [x] Owner revokes only test pairings/orphans through native confirmation, identified by full
  transcript fingerprint. Use official `remove-desktop-state --identity-stub` and enter the full
  fingerprint for each local pairing. Pending setup follows documented `setup --resume`/`--cleanup`
  semantics; do not manually delete replay files, private locators or CNG keys.
- [x] Final audit: no test stubs or non-lock test state, no candidate processes or reverse rules,
  no temporary firewall rules, Wi-Fi paused, enabled phone controls. Preserve unrelated pairings
  and the phone identity; identity deletion/uninstall is not minimum-regression cleanup.
- [x] Attach sanitized manual results and script report to the candidate evidence. Record only
  versions, hashes, dates, coarse states/errors/timings and counts; omit plaintext, keys, QR or
  protocol contents, labels, serials, recipients, private paths and aliases.
- [x] Resolve all required failed/unexecuted rows. A `passed-minimal-unwrap-only` script report
  does not pass manual UI/upgrade/cleanup gates or the full public-Alpha matrix.
- [x] Reviewer approves `alpha-release-publish` only for the same verified SHA/run/attempt after
  physical acceptance. The existing workflow owns the tag, six assets and public prerelease.
  Never create/move a final tag or upload replacement assets manually.

Historical references: [alpha.3 package acceptance](windows-acceptance-2026-09-05.md) and
[debug UI/Wi-Fi acceptance](windows-ui-wifi-acceptance-2026-09-05.md). Neither transfers to alpha.4.
