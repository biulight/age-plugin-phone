# Windows Alpha quick start

This guide validates one exact signed Windows/Android developer-prerelease pair with synthetic data
before using the phone identity for retained data. It does not close the full Alpha matrix and is
not approval to protect real secrets. The independent source review is complete, but protocol v2
remains unfrozen and the remaining QR/replay, lifecycle/invalidation, multi-phone, public-signing,
and technical-user gates are still open. Historical results from another commit or artifact pair
do not transfer; this guide remains reusable for each new exact artifact pair.

The present use is the owner-only technical preview in
[`owner-only-preview.md`](owner-only-preview.md). This guide may exercise the recorded single-device
Developer USB path with synthetic data; it does not waive the deferred UVC, second-phone,
public-signing, or external-user gates.

Use one exact RC artifact set throughout the guide. Do not mix a desktop executable, Android APK,
or evidence file from another commit or workflow attempt.

## 1. Verify and install the artifacts

Download both artifact groups and their `SHA256SUMS.txt` and `signature-verification.txt` evidence.
Confirm that the hashes, immutable commit, workflow run and attempt, and certificate fingerprints
agree with the approved release record. The Windows ZIP is intentionally named and recorded as
private-root test-signed; an ordinary Windows installation does not trust that root.

Do not install the private test root system-wide merely to suppress an untrusted-publisher warning.
The test signature proves artifact identity only when checked against the separately approved test
root and evidence. It is not public publisher trust.

### Runtime prerequisites

Extract `age-plugin-phone.exe` without renaming it and place its directory on the current user's
`PATH`. Install the APK from the same RC set on the test phone. The normal Shine path uses the
standard `age` CLI, `age-plugin-phone`, ADB, and the Android application; it does not require
`rage`. The guided phone-identity shortcut in section 2 requires Shine 2.0.0-rc.1 or later.

### Alpha interoperability validation tool

`rage` is an alternative age-compatible client, not a runtime dependency of `age-plugin-phone` or
Shine. It is optional outside this validation, but the pinned release is required to complete this
guide's cross-client Alpha checks in section 3. Open a new PowerShell 7 session and install it into
a versioned per-user directory. The digest below is the SHA-256 published for the upstream v0.12.1
Windows x64 asset:

```powershell
$rageVersion = "0.12.1"
$rageArchive = Join-Path $env:TEMP "rage-v$rageVersion-x86_64-windows.zip"
$rageRoot = Join-Path $env:LOCALAPPDATA "Programs\rage-$rageVersion"
Invoke-WebRequest -Uri "https://github.com/str4d/rage/releases/download/v$rageVersion/rage-v$rageVersion-x86_64-windows.zip" -OutFile $rageArchive
if ((Get-FileHash $rageArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne "da5b8111c8f097c7822df505ad504696e4891ff8adec06a39171f8d717590b2c") { Remove-Item -LiteralPath $rageArchive -Force; throw "rage archive digest mismatch" }
New-Item -ItemType Directory -Force -Path $rageRoot | Out-Null
Expand-Archive -LiteralPath $rageArchive -DestinationPath $rageRoot -Force
Remove-Item -LiteralPath $rageArchive -Force
$env:PATH = "$(Join-Path $rageRoot 'rage');$env:PATH"
```

Keep that exact directory on `PATH` for the candidate session, then run:

```powershell
age-plugin-phone status
age --version
rage --version
adb version
adb devices
```

The desktop status must report a supported Windows 11 x64 client, TPM 2.0, and Microsoft Platform
Crypto Provider. Use exactly one authorized online Android device, or select it explicitly as shown
below. On the phone, confirm that the application reports an available StrongBox identity and strong
biometric authentication. ADB authorization and device identity are transport prerequisites, not
cryptographic authentication.

## 2. Set up the Windows desktop and phone

Choose one setup entry point. For the normal Shine validation path, use its guided shortcut:

```powershell
shine env secret identity init --phone --label "NUC WiFi Pair" --transport auto
```

This invokes the plugin's transactional managed setup and leaves the pairing interaction in the
terminal. It does not move TPM, replay, locator, interruption, or cleanup state into Shine. After a
successful setup, Shine validates the plugin's versioned public result and appends only the public
identity-stub path to the current user's global `age_identities` list. It does not change
`secret_backend` or add an encryption recipient.

For Wi-Fi pairing, keep the phone application in the foreground and choose **Pair · Wi-Fi** before
running the command. With `auto`, the desktop first performs one bounded pairing discovery. Exactly
one responding foreground listener selects Wi-Fi. If no listener responds, Windows selects
Developer USB/ADB before creating the pairing offer; choose **Pair · USB** on the phone. Ambiguous
discovery or a local discovery error fails closed, and an attempt never switches transport after
protocol work begins.

Compare the complete fingerprint on both endpoints, then type the full fingerprint into the desktop
prompt. Do not approve a partial or visually similar fingerprint. Success prints the public
identity-stub path, the `age1phone...` recipient, and the global Shine configuration path.

For standard-age validation without the Shine handoff, run the plugin directly instead:

```powershell
age-plugin-phone setup --label "Windows Alpha" --transport auto
```

The direct command creates the same plugin-owned pairing state and prints the same public identity
path and recipient, but it does not edit Shine configuration. Section 4 shows the current manual
configuration form for this path.

Shine consumes the plugin's `setup --json` handoff internally. Other automation may use that option
directly, but the interactive pairing and full-fingerprint confirmation remain visible on stderr;
stdout is reserved for one versioned object containing only the public identity path and recipient.
Do not treat this output mode as non-interactive setup or as permission to skip the phone
comparison.

Copy the printed public identity-stub path into the variable used by the remaining steps:

```powershell
$pluginConfig = Join-Path $env:LOCALAPPDATA "age-plugin-phone"
$identityStub = "<printed-public-identity-stub-path>"
```

The identity stub contains public pairing material, not the phone's long-term private key. The
desktop state refers to distinct non-exportable TPM signing and stanza-selection keys. The durable
replay state and private locator remain under `%LOCALAPPDATA%\age-plugin-phone`.

When more than one ADB device is online, pin Developer USB during setup and retain the selection for
later standard-age invocations:

```powershell
$adbSerial = "<selected-adb-serial>"
shine env secret identity init --phone --label "Windows Alpha" --transport adb --adb-serial $adbSerial
$env:AGE_PLUGIN_PHONE_ADB_SERIAL = $adbSerial
```

For the direct plugin path, replace the Shine command above with
`age-plugin-phone setup --label "Windows Alpha" --transport adb --adb-serial $adbSerial`.

Treat device serials and the desktop label only as untrusted routing and display hints. They never
replace fingerprint comparison, protocol verification, or the fresh phone biometric operation.

If setup is interrupted, rerunning either setup entry point fails closed while the plugin's
protected journal exists. Use `age-plugin-phone setup --resume` only when the desktop had already
accepted the complete fingerprint; otherwise use `age-plugin-phone setup --cleanup`, then revoke
any matching fingerprint retained on the phone. These modes never infer targets or claim phone-side
revocation. If pairing succeeds but Shine cannot save its global configuration, do not start a new
pairing; add the TOML-safe `age_identities` entry printed by Shine. The explicit `pair` command with
user-supplied paths remains available only for advanced diagnostics.

## 3. Prove a reference-age round trip

Copy the printed phone recipient into a PowerShell variable without adding whitespace:

```powershell
$phoneRecipient = "age1phone..."
```

Generate a disposable recovery identity for this synthetic test. Do not reuse it for real data:

```powershell
age-keygen -o .\recovery-test-identity.txt
$recoveryRecipient = age-keygen -y .\recovery-test-identity.txt
```

Create a non-sensitive probe, encrypt it to both recipients, and decrypt it through the phone
identity stub. Each command below is deliberately one line:

```powershell
Set-Content -NoNewline -Encoding utf8 .\probe.txt "synthetic age-plugin-phone Alpha probe"
age -e -r $phoneRecipient -r $recoveryRecipient -o .\probe.txt.age .\probe.txt
age -d -i $identityStub -o .\probe.phone.txt .\probe.txt.age
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.phone.txt -Algorithm SHA256).Hash) { throw "phone round-trip digest mismatch" }
```

The decrypt command must cause a new approval request and fresh strong biometric operation on the
paired phone. A saved `auto` preference first performs authenticated discovery for that exact
pairing. Exactly one matching foreground **Wi-Fi auto-listen** endpoint selects Wi-Fi; no matching
response selects Developer USB/ADB on Windows before the signed unwrap request is created.
Ambiguity or a local discovery error fails closed. Once a route is selected, the attempt never
races, switches, or silently retries another transport.

For the Wi-Fi path, enable **Wi-Fi auto-listen** and keep the phone application in the foreground.
For Developer USB, the desktop creates its exact reverse rule and opens the Android application
automatically; there is no separate **Approve USB** button. Only the fixed, payload-free wake action
crosses the ADB command line, and the signed request is still verified and durably consumed before
the biometric prompt. Developer USB and Wi-Fi age unwraps do not emit a `message` callback by
default, so a successful command can reserve stdout for plaintext. Set
`$env:AGE_PLUGIN_PHONE_MESSAGES = "1"` before the age command to opt into payload-free desktop
guidance. Explicit QR always renders its one-time request in the terminal. Approval details remain
on the phone, while errors still fail the age command. Cancellation, timeout, cable or network
failure, an unauthorized device, or a wrong paired phone must fail without plaintext or partial
output. Retrying after any interruption must create a new request and require another biometric
operation.

Now prove that the independent recovery path decrypts the same ciphertext without the phone:

```powershell
age -d -i .\recovery-test-identity.txt -o .\probe.recovery.txt .\probe.txt.age
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.recovery.txt -Algorithm SHA256).Hash) { throw "recovery round-trip digest mismatch" }
```

Do not proceed to Shine secret sealing or runtime decryption until both digest comparisons pass.
Record only non-sensitive versions, artifact digests, scenario results, and recovered-output
digests as described by
[`alpha-matrix.md`](alpha-matrix.md). Never record plaintext, private state paths, device serials,
raw protocol messages, QR contents, stanza bodies, file keys, or key aliases.

Use the same synthetic input to prove both cross-client directions. Each phone-path decryption must
trigger its own fresh biometric operation:

```powershell
rage -d -i $identityStub -o .\probe.rage-phone.txt .\probe.txt.age
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.rage-phone.txt -Algorithm SHA256).Hash) { throw "rage phone digest mismatch" }
rage -e -r $phoneRecipient -r $recoveryRecipient -o .\probe.rage.age .\probe.txt
age -d -i $identityStub -o .\probe.age-from-rage.txt .\probe.rage.age
age -d -i .\recovery-test-identity.txt -o .\probe.recovery-from-rage.txt .\probe.rage.age
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.age-from-rage.txt -Algorithm SHA256).Hash) { throw "age-from-rage phone digest mismatch" }
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.recovery-from-rage.txt -Algorithm SHA256).Hash) { throw "rage recovery digest mismatch" }
```

## 4. Use Shine's managed identity configuration

Shine invokes the standard `age` CLI. This repository adds no Shine-specific protocol, RPC, URI, or
ciphertext format.

If section 2 used `shine env secret identity init --phone`, the public stub is already present in
the current user's global `age_identities`. Confirm that Shine can enumerate the configured public
stub without printing its contents:

```powershell
shine env secret identity list
```

If section 2 used `age-plugin-phone setup` directly, append the printed public stub path to the
global `~/.shine/config.toml` instead:

```toml
age_identities = ["C:/Users/<user>/AppData/Local/age-plugin-phone/identity-....txt"]
```

The singular `age_identity` setting remains a legacy compatibility field. Shine merges it before
the ordered `age_identities` list, so preserve an existing entry when it is still needed for
recovery or historical ciphertext; use `age_identities` for new phone stubs. A project that
explicitly sets either identity field replaces the global identity set. For that reason, the guided
phone command stops before pairing when the active project has such an override instead of creating
a pairing that the project would ignore.

The guided command intentionally leaves the existing secret backend unchanged. The workspace
configuration below selects `age` explicitly for this test.

Put the public phone and independent recovery recipients in the project's commit-ready
`shine.workspace.toml`:

```toml
[env.encryption]
backend = "age"
age_recipients = [
  "age1phone...",
  "age1...",
]
```

Use only synthetic workspace values for this Alpha check. For example, add this value to one source
listed by the test workspace, such as `shine.env.toml`:

```toml
version = 1

[secret]
AGE_PLUGIN_PHONE_ALPHA_PROBE = "synthetic Shine Alpha probe"
```

Seal it and verify its presence without printing the value:

```powershell
shine env secret seal
shine env run --mode development -- pwsh -NoProfile -Command 'if ($env:AGE_PLUGIN_PHONE_ALPHA_PROBE -ne "synthetic Shine Alpha probe") { throw "synthetic Shine probe mismatch" }'
```

Sealing uses public recipients and does not need phone authorization. Decrypting during `env run`
must invoke `age-plugin-phone.exe` and cause a fresh phone biometric operation. With the saved
`auto` preference, keep **Wi-Fi auto-listen** enabled in the foreground to use Wi-Fi; otherwise
Windows selects Developer USB before creating the request. Independently decrypt or reseal through
the recovery identity before treating the recovery portion of the matrix as passed. Never make the
phone the only recipient for important data.

## 5. Revoke and remove one test pairing

This step is destructive and belongs at the end of a disposable pairing's test run. First verify
that the independent recovery identity can decrypt every retained synthetic ciphertext. In the
phone application's **Paired desktops** section, select the pairing by its transcript fingerprint,
not its untrusted label, and revoke it. Confirm that a new request from the revoked desktop produces
no plaintext and no biometric prompt.

Then remove the exact local Windows state:

```powershell
age-plugin-phone remove-desktop-state --identity-stub $identityStub
```

The command prints the full transcript fingerprint and requires it to be typed exactly. It removes
only that pairing's response replay state, TPM metadata, locator, two exact CNG keys, replay lock,
and public identity stub. An interrupted cleanup remains fail-closed and the same command resumes
only the journaled target. Do not delete individual files or CNG keys manually.

If the phone has been lost, the command may still remove local state after the same confirmation,
but local success is not evidence of phone-side revocation. Old version 2 ciphertext remains bound
to the removed pairing and must be recovered and re-encrypted; cleanup never migrates it.

Use the stub-based command whenever the public stub is available. If a failed or older pairing left
a private locator after its public stub was lost, enumerate locators without printing their contents
and proceed only when exactly one intended orphan is present:

```powershell
$locatorCandidates = @(Get-ChildItem -LiteralPath $pluginConfig -File -Filter "*.cbor" | Where-Object { $_.BaseName -match '^[0-9a-f]{32,128}(-[0-9a-f]{32,128})?$' })
if ($locatorCandidates.Count -ne 1) { throw "expected exactly one orphan locator; stop and identify the intended pairing" }
$orphanLocator = $locatorCandidates[0].FullName
age-plugin-phone remove-orphaned-desktop-state --locator $orphanLocator
```

Compare the displayed full transcript fingerprint with the pairing being retired and type it
exactly. This recovery-only command accepts only the locator's canonical protected path, validates
its desktop ID and existing response-replay scope, and uses the same crash-safe cleanup journal. It
removes the bound replay state, exact CNG keys, TPM metadata, locator, and replay lock. It does not
find or delete public identity stubs and does not revoke the phone pairing. If multiple locator
candidates exist, do not pass a wildcard or choose by a caller-supplied label; restore the matching
public stub when possible or identify the intended pairing by its full fingerprint.

## Troubleshooting

- If PowerShell reports that `-o` is a command or that an age flag needs an argument, a pasted line
  continuation or empty variable is the likely cause. Re-run the documented single-line command and
  check `$phoneRecipient.Length`, `$recoveryRecipient.Length`, and `Test-Path $identityStub` without
  printing identity contents.
- If age cannot find the plugin, confirm that the executable is still named
  `age-plugin-phone.exe`, its directory is on the current user's `PATH`, and the PowerShell session
  was opened after the `PATH` change.
- If several devices appear in `adb devices`, pass `--transport adb --adb-serial SERIAL` during
  direct plugin pairing, or use the equivalent Shine `--phone --transport adb --adb-serial SERIAL`
  form, and set `AGE_PLUGIN_PHONE_ADB_SERIAL` for later standard-age invocations.
- If the Shine shortcut reports that the active project overrides age identities, remove or update
  that intentional project override before pairing. Do not rerun from another directory merely to
  bypass a project policy you still expect the project to use.
- If `auto` does not select Wi-Fi, confirm that the phone application is in the foreground and that
  the correct one-shot **Pair · Wi-Fi** action or persistent **Wi-Fi auto-listen** mode is active for
  the operation. No response selects Developer USB on Windows; ambiguity or discovery failure is an
  error, and there is no in-flight fallback.
- Pairing uses create-new semantics and does not overwrite an existing identity stub or replay
  state. Use the documented lifecycle and recovery process instead of deleting or replacing only
  one state file.
- Use `AGE_PLUGIN_PHONE_TRANSPORT=qr` only for the camera fallback. QR changes transport, not the
  pairing, authorization, replay, or response-binding requirements.
