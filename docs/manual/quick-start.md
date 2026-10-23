---
title: "Your first round trip"
sidebar_position: 4
---

# Your first round trip

Pair one Android phone and desktop over Developer USB, encrypt disposable text, and verify both phone and independent recovery decryption. Finish [installation](support.md) first. Use a new empty test directory so output files do not replace existing work.

## 1. Pair the phone

Connect the authorized Android device. Start this command on the desktop **before** choosing **Pair · USB** on the phone:

```sh
age-plugin-phone setup --label "Test laptop" --transport adb
```

When several ADB devices are connected, add `--adb-serial SERIAL`, replacing `SERIAL` with the intended device's serial. Compare the **entire fingerprint** on both devices and enter it at the desktop prompt only if it matches. Labels are untrusted hints. Complete the phone's native confirmation yourself.

Save the printed public identity-stub path and recipient. Setup succeeds only after confirmation; for an interrupted attempt, use the [recovery guide](guides/recovery.md).

If several ADB devices are connected, set `AGE_PLUGIN_PHONE_ADB_SERIAL` in the shell used for decryption as described in the [environment reference](reference/commands.md) before continuing.

## 2. Encrypt and verify on Windows

In PowerShell, replace the two placeholders with setup's output. The recovery key below is a disposable test identity; keep it separate from plugin state.

```powershell
$identityStub = "<printed-public-identity-stub-path>"
$phoneRecipient = "<printed-recipient>"
age-keygen -o .\recovery-test-identity.txt
$recoveryRecipient = age-keygen -y .\recovery-test-identity.txt
Set-Content -NoNewline -Encoding utf8 .\probe.txt "synthetic beta probe"
age -e -r $phoneRecipient -r $recoveryRecipient -o .\probe.txt.age .\probe.txt
age -d -i $identityStub -o .\probe.phone.txt .\probe.txt.age
age -d -i .\recovery-test-identity.txt -o .\probe.recovery.txt .\probe.txt.age
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.phone.txt -Algorithm SHA256).Hash) { throw "phone digest mismatch" }
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.recovery.txt -Algorithm SHA256).Hash) { throw "recovery digest mismatch" }
```

## 3. Or verify on macOS

Use this block instead of the Windows block. Replace the same two placeholders:

```sh
identityStub='<printed-public-identity-stub-path>'
phoneRecipient='<printed-recipient>'
age-keygen -o recovery-test-identity.txt
recoveryRecipient=$(age-keygen -y recovery-test-identity.txt)
printf '%s' 'synthetic beta probe' > probe.txt
age -e -r "$phoneRecipient" -r "$recoveryRecipient" -o probe.txt.age probe.txt
age -d -i "$identityStub" -o probe.phone.txt probe.txt.age
age -d -i recovery-test-identity.txt -o probe.recovery.txt probe.txt.age
cmp probe.txt probe.phone.txt
cmp probe.txt probe.recovery.txt
```

## Confirm success

Encryption needs no phone approval. Phone decryption must prompt for fresh native verification. Recovery decryption must work without the phone. Both comparisons must succeed; `cmp` exits successfully without output for equal files. Stop at any failed command instead of using later output as evidence of success.

Decrypt once more to a new output file and confirm another fresh phone prompt. Cancel a separate attempt: it must fail without usable plaintext. A retry requires a new request and new approval. If using several ADB devices, set the [ADB serial environment variable](reference/commands.md) before age decryption as well.

Do not put this disposable recovery private key in a repository, evidence log, or plugin state. Keeping another phone paired only to this desktop does not cover losing the desktop. Read [recovery](guides/recovery.md) before deleting any identity, then explore [connection choices](guides/transports.md) or [application integration](guides/applications.md).
