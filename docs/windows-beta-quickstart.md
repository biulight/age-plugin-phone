# Windows Beta quick start

This guide covers the proposed `0.1.0-beta.2` Windows 11 x64 source-install
path with an Android StrongBox phone. The beta is still experimental: use only
synthetic or disposable data, always add and test an independent recovery
recipient, and confirm every full pairing fingerprint and phone verification
yourself. See the [closeout checklist](beta-readiness.md) before treating a
candidate as published or accepted.

## Prerequisites

- Windows 11 x64 with TPM 2.0 and Microsoft Platform Crypto Provider.
- Rust 1.88 or later using the MSVC toolchain.
- Visual Studio C++ Build Tools and a current Windows SDK.
- age 1.3 or later. rage is optional and useful for interoperability testing.
- Android with live StrongBox P-256 support and strong biometric authentication.
- Android platform-tools when using Developer USB. USB debugging and ADB
  authorization are transport prerequisites, never protocol authorization.

After the version is published on crates.io, install the four locked packages
from source through the CLI package:

```powershell
rustup default stable-x86_64-pc-windows-msvc
cargo install age-plugin-phone --version 0.1.0-beta.2 --locked
age-plugin-phone status
```

`status` must report a supported Windows client, TPM 2.0 and Microsoft Platform
Crypto Provider before setup. Source installation does not require the private
Windows test-signing root. An optional prebuilt ZIP remains explicitly
test-signed; verify its checksums and signing evidence and do not install its
private root into a system trust store.

Install the signed Android APK from the same accepted beta candidate. Do not mix
desktop and phone artifacts from different commits or workflow attempts.

## Pair

Keep important data outside this exercise. For foreground Wi-Fi, enable the
phone listener before running setup. For Developer USB, start desktop setup first
and then choose the phone's USB pairing action after the reverse route is armed.

```powershell
age-plugin-phone setup --label "Windows Beta" --transport auto
```

Compare the entire fingerprint on both devices, then enter the full fingerprint
at the desktop prompt. Save the printed public identity-stub path and recipient:

```powershell
$identityStub = "<printed-public-identity-stub-path>"
$phoneRecipient = "<printed-age1phone-recipient>"
```

The public stub contains no phone private identity. Windows keeps separate TPM
signing and selection keys; the phone performs every long-term identity operation
after fresh native verification. If setup is interrupted, use `setup --resume`
only after the desktop durably accepted the full fingerprint. Otherwise use
`setup --cleanup` and revoke any corresponding phone record.

## Verify phone and recovery decryption

Create a disposable recovery identity, encrypt synthetic input to both recipients,
and require both paths to reproduce the same digest:

```powershell
age-keygen -o .\recovery-test-identity.txt
$recoveryRecipient = age-keygen -y .\recovery-test-identity.txt
Set-Content -NoNewline -Encoding utf8 .\probe.txt "synthetic beta probe"
age -e -r $phoneRecipient -r $recoveryRecipient -o .\probe.txt.age .\probe.txt
age -d -i $identityStub -o .\probe.phone.txt .\probe.txt.age
age -d -i .\recovery-test-identity.txt -o .\probe.recovery.txt .\probe.txt.age
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.phone.txt -Algorithm SHA256).Hash) { throw "phone digest mismatch" }
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.recovery.txt -Algorithm SHA256).Hash) { throw "recovery digest mismatch" }
```

The phone path must display a fresh system verification for this request.
Cancellation, timeout, disconnect and a wrong phone must produce no plaintext.
A retry creates a new request and must prompt again.

## Opt in to the native tagged recipient

The default remains the private-selection `age1phone` recipient. After updating
the phone app, export the optional standard tagged recipient from the same public
identity stub:

```powershell
$tagRecipient = age-plugin-phone recipients -i $identityStub --recipient-type tag
age -e -r $tagRecipient -r $recoveryRecipient -o .\probe.tag.age .\probe.txt
age -d -i $identityStub -o .\probe.tag-phone.txt .\probe.tag.age
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.tag-phone.txt -Algorithm SHA256).Hash) { throw "tag digest mismatch" }
```

age encrypts to `age1tag` natively, so encryption does not need the phone plugin.
The four-byte selector is publicly testable and never authorizes decryption; the
phone still authenticates the complete request and requires fresh verification.
Old phone apps reject this stanza. There is no automatic conversion or fallback.

For managed Shine setup, cleanup, multi-client validation and detailed failure
recovery, consult the historical [Windows Alpha guide](windows-alpha-quickstart.md)
while applying this beta's version, scope and release evidence. Shine uses the
ordinary age plugin boundary and introduces no separate ciphertext format.

Never record private keys, file keys, plaintext, raw protocol payloads, QR contents,
device serials or private state paths in acceptance evidence.
