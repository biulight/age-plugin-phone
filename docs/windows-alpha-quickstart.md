# Windows Alpha quick start

This guide validates one signed Windows/Android RC pair with synthetic data before using the phone
identity through Shine. It does not close the full Alpha matrix and is not approval to protect real
secrets. The independent source review is complete, but protocol v2 remains unfrozen and the
remaining QR/replay, lifecycle/invalidation, multi-phone, public-signing, and
technical-user gates are still open. The recorded candidate has completed the primary one-phone
Developer USB and age/rage/Shine interoperability paths only on the previous `18a94c8` physical
baseline. Active candidate `35bbb60` has verified packages but no physical results yet; this guide
remains reusable for later exact artifact pairs and does not transfer evidence between them.

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

Extract `age-plugin-phone.exe` without renaming it and place its directory on the current user's
`PATH`. Install the APK from the same RC set on the test phone. Then open a new PowerShell 7 session
and install the pinned Windows rage release into a versioned per-user directory. The digest below
is the SHA-256 published for the upstream v0.12.1 Windows x64 asset:

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

## 2. Pair the Windows desktop and phone

Create the default private configuration directory and define the three output paths:

```powershell
$pluginConfig = Join-Path $env:LOCALAPPDATA "age-plugin-phone"
New-Item -ItemType Directory -Force -Path $pluginConfig | Out-Null
$desktopState = Join-Path $pluginConfig "desktop.state"
$identityStub = Join-Path $pluginConfig "identity.txt"
$replayState = Join-Path $pluginConfig "replay.state"
```

Start pairing as one PowerShell command. Avoid backtick line continuations when copying commands
between terminals:

```powershell
age-plugin-phone pair --label "Windows Alpha" --desktop-state $desktopState --identity-output $identityStub --replay-state $replayState --transport adb
```

On the phone, choose **Pair via Developer USB**. Compare the complete fingerprint on both endpoints,
then type the full fingerprint into the desktop prompt. Do not approve a partial or visually similar
fingerprint. Success prints the public identity-stub path and a `Recipient: age1phone...` value.

The identity stub contains public pairing material, not the phone's long-term private key. The
desktop state refers to distinct non-exportable TPM signing and stanza-selection keys. The durable
replay state and private locator remain under `%LOCALAPPDATA%\age-plugin-phone`.

When more than one ADB device is online, use this form instead of the preceding pairing command and
retain the selection for later age invocations:

```powershell
$adbSerial = "<selected-adb-serial>"
age-plugin-phone pair --label "Windows Alpha" --desktop-state $desktopState --identity-output $identityStub --replay-state $replayState --transport adb --adb-serial $adbSerial
$env:AGE_PLUGIN_PHONE_ADB_SERIAL = $adbSerial
```

Treat device serials and the desktop label only as untrusted routing and display hints. They never
replace fingerprint comparison, protocol verification, or the fresh phone biometric operation.

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
paired phone. Developer USB creates its exact reverse rule and then opens the Android application
automatically; there is no separate **Approve USB** button. Only the fixed, payload-free wake action
crosses the ADB command line, and the signed request is still verified and durably consumed before
the biometric prompt. Cancellation, timeout, cable failure, an unauthorized device, or a wrong
paired phone must fail without plaintext or partial output. Retrying after any interruption must
create a new request and require another biometric operation.

Now prove that the independent recovery path decrypts the same ciphertext without the phone:

```powershell
age -d -i .\recovery-test-identity.txt -o .\probe.recovery.txt .\probe.txt.age
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.recovery.txt -Algorithm SHA256).Hash) { throw "recovery round-trip digest mismatch" }
```

Do not proceed to Shine until both digest comparisons pass. Record only non-sensitive versions,
artifact digests, scenario results, and recovered-output digests as described by
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

## 4. Use the existing Shine boundary

Shine invokes the standard `age` CLI. This repository adds no Shine-specific protocol, RPC, URI, or
ciphertext format. Configure the public phone identity stub as the current Windows user's decryption
identity in `~/.shine/config.toml`:

```toml
secret_backend = "age"
age_identity = "C:/Users/<user>/AppData/Local/age-plugin-phone/identity.txt"
```

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
must invoke `age-plugin-phone.exe` and cause a fresh phone biometric operation. Independently decrypt
or reseal through the recovery identity before treating the recovery portion of the matrix as
passed. Never make the phone the only recipient for important data.

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
  pairing and set `AGE_PLUGIN_PHONE_ADB_SERIAL` for standard age invocations.
- Pairing uses create-new semantics and does not overwrite an existing identity stub or replay
  state. Use the documented lifecycle and recovery process instead of deleting or replacing only
  one state file.
- Use `AGE_PLUGIN_PHONE_TRANSPORT=qr` only for the camera fallback. QR changes transport, not the
  pairing, authorization, replay, or response-binding requirements.
