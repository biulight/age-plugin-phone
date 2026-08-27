# age-plugin-phone

`age-plugin-phone` is an experimental, standalone [age] identity plugin that will keep long-term
decryption keys on a phone and authorize individual file-key unwrap operations over a fully offline
QR, BLE, or USB channel.

It is intended to work with any compatible age client. It does not depend on Shine, understand
Shine environments, or define a Shine-specific ciphertext format.

> [!WARNING]
> This repository is an experimental prototype. Reference age recipient and identity state machines
> are connected to the one-shot QR flow with native desktop camera capture, but the protocol and
> camera path have not received independent review. Do not use it to protect real secrets.

## Intended boundary

```text
age-compatible application
          |
          v
       age/rage
          |
          v
 age-plugin-phone  <---- QR / BLE / USB ---->  phone app
                                                   |
                                                   v
                                      hardware-backed private key
```

The phone should release only the file key for the single age recipient stanza approved by the
user. It must never export the long-term private key to the desktop.

## Repository layout

- `crates/desktop`: the `age-plugin-phone` desktop binary and age plugin entry point.
- `crates/protocol`: transport-independent pairing and unwrap message types.
- `crates/recipient-p256`: experimental, transport-independent P-256 tagged-recipient reference.
- `crates/transport`: bounded, one-shot opaque request/response session boundary.
- `apps/mobile`: Tauri 2 mobile application with a deliberately non-sensitive TypeScript UI.
- `docs`: architecture, protocol, threat model, and roadmap.

## Current commands

```console
cargo run -p age-plugin-phone -- status
cargo run -p age-plugin-phone -- pair --help
cargo run -p age-plugin-phone -- unwrap --help
cargo run -p age-plugin-phone -- qr-capture-probe
cargo test --workspace

cd apps/mobile
bun install
bun run tauri android init
bun run tauri ios init
```

On Windows, `status` performs a read-only Alpha capability probe. It reports the actual Windows
version, client/server edition, x64 architecture, TPM 2.0 availability, and Microsoft Platform
Crypto Provider availability without creating or opening persisted keys.

The Android development build's **Pair this phone** action scans the desktop offer, signs and
renders the phone response entirely in native UI, and shows the full transcript fingerprint. The
desktop `pair` command scans that response directly from camera index 0, verifies it, asks for the
same full fingerprint, and then creates the public stub. Camera frames and QR text remain in memory
and are never trusted without protocol verification.

The plugin implements standard age `recipient-v1` and `identity-v1`. New pairing output uses a
pairing-specific v2 `age1phone` recipient whose encrypted selector privately maps multi-phone
stanzas on the desktop; legacy v1 recipients remain supported for unambiguous files. Encryption is
public-only. During decryption, the age client displays a terminal request QR while
the desktop camera scans and reassembles the phone response. Pairing creates a private locator in
the platform configuration directory so the public identity stub contains no private-key path. Set
`AGE_PLUGIN_PHONE_CONFIG_DIR` to the same absolute directory for pairing and age invocations only
when an isolated non-default location is required.

On Windows, the configuration directory is `%LOCALAPPDATA%\age-plugin-phone`. Pairing requires the
`--desktop-state` and `--replay-state` paths to be direct children of that directory. The desktop
state contains only a TPM key locator ID: signing and private stanza selection use distinct,
non-exportable P-256 keys in Microsoft Platform Crypto Provider, with no software or DPAPI fallback.
Locator, metadata, replay, temporary, and lock files use protected current-user ACLs. Pairing,
explicit unwrap, and standard `identity-v1` operations fail before protocol work unless the host is
a Windows 11-or-later x64 client with an available TPM 2.0 and Platform Crypto Provider.

Windows now defaults to the Developer USB ADB Alpha for `pair`, `unwrap`, and standard age identity
operations. Start the desktop operation, then choose **Pair via Developer USB** or **Approve via
Developer USB** in the Android development build. Use `--adb-serial SERIAL` when multiple devices
are listed by ADB. `--transport qr` selects the camera fallback without changing the pairing.
For standard age invocations, set `AGE_PLUGIN_PHONE_TRANSPORT=qr` for that fallback or
`AGE_PLUGIN_PHONE_ADB_SERIAL=SERIAL` for explicit device selection.

> [!CAUTION]
> Developer USB requires Android USB debugging and ADB authorization. An ADB-authorized desktop has
> much broader access to the phone than this application needs. ADB identity, device state, and the
> cable are not trusted by the protocol and do not replace the fresh phone biometric operation.

## Design goals

- No server, account, cloud rendezvous, or online authorization dependency.
- Independent phone user verification for every private-key operation.
- Long-term private keys are non-exportable or wrapped by a hardware-backed phone key.
- The desktop receives only a request-bound file key, never the long-term identity.
- Replay, copied desktop state, cancellation, and transport failure all fail closed.
- Standard age plugin and recipient behavior remains the only application integration boundary.

Start with the [Android StrongBox PoC](docs/android-strongbox-poc.md), then read
[the architecture](docs/architecture.md), [experimental P-256 recipient ADR](docs/adr/0001-experimental-p256-recipient.md),
[offline-envelope ADR](docs/adr/0002-experimental-offline-envelope.md),
[persistent replay-state ADR](docs/adr/0003-persistent-replay-state.md),
[Android pairing-state ADR](docs/adr/0004-android-pairing-state.md),
[QR framing ADR](docs/adr/0005-qr-framing.md),
[native QR capture ADR](docs/adr/0006-native-qr-capture.md),
[Android production key-custody ADR](docs/adr/0007-android-production-key-custody.md),
[bidirectional pairing ADR](docs/adr/0008-bidirectional-pairing.md),
[one-shot unwrap ADR](docs/adr/0009-one-shot-qr-unwrap.md),
[reference age integration ADR](docs/adr/0010-reference-age-state-machines.md),
[desktop-native scanner ADR](docs/adr/0011-desktop-native-qr-scanner.md),
[private stanza selection ADR](docs/adr/0012-private-stanza-selection.md),
[Windows CNG boundary ADR](docs/adr/0013-windows-cng-key-boundaries.md),
[split desktop-key protocol ADR](docs/adr/0014-split-desktop-key-protocol-v2.md),
[Windows private storage ADR](docs/adr/0015-windows-private-storage.md),
[common transport and ADB Alpha ADR](docs/adr/0016-common-transport-and-adb-alpha.md),
[identity lifecycle and recovery ADR](docs/adr/0017-lifecycle-and-recovery.md),
[Windows and Android Alpha matrix](docs/alpha-matrix.md),
[independent security review package](docs/security-review-package.md),
[protocol draft](docs/protocol.md), and [threat model](docs/threat-model.md) before implementing a
transport or cryptographic backend.

## Why Tauri

Tauri 2 provides one mobile application shell while keeping protocol logic in Rust and allowing the
hardware-key boundary to be implemented as a small native Swift/Kotlin plugin. The WebView is UI
only: long-term keys, unwrapped file keys, raw signed requests, and hardware-key commands must not
cross into JavaScript. The generic Tauri biometric plugin is not a substitute for binding user
authentication to the actual Secure Enclave or Android Keystore private-key operation.

[age]: https://age-encryption.org/
