# age-plugin-phone

`age-plugin-phone` is an experimental, standalone [age] identity plugin that will keep long-term
decryption keys on a phone and authorize individual file-key unwrap operations over QR, BLE, USB,
or an experimental local Wi-Fi channel.

It is intended to work with any compatible age client. It does not depend on Shine, understand
Shine environments, or define a Shine-specific ciphertext format.

> [!WARNING]
> This repository is an experimental prototype. An independent source review has been completed
> and its actionable finding resolved, but protocol v2 remains unfrozen and native Windows,
> physical Android, signed-package, and interoperability gates remain open. Do not use it to
> protect real secrets.

The first installable snapshot is
[`v0.1.0-alpha.1`](docs/releases/v0.1.0-alpha.1.md), a test-signed developer prerelease for
synthetic or disposable data with a separately verified independent recovery recipient. Publishing
that snapshot does not constitute a public-Alpha, stable-protocol, or production-secret claim.

The current deployment posture is an
[owner-only technical preview](docs/owner-only-preview.md): one repository owner, one known
Windows/TPM desktop, one capability-qualified StrongBox phone, and Developer USB as the normal
route. An opt-in foreground Wi-Fi auto-listen PoC is available as an explicit owner experiment. UVC-camera
QR evidence, a second StrongBox family, multi-phone testing, public Windows
signing, and an external technical-user Alpha are recorded but deferred until broader use is
planned. Deferred means unverified, not passed.

## Intended boundary

```text
age-compatible application
          |
          v
age-compatible client
    (age or rage)
          |
          v
 age-plugin-phone  <--- QR / BLE / USB / Wi-Fi --->  phone app
                                                   |
                                                   v
                                      hardware-backed private key
```

`age` and `rage` are alternative compatible clients; an installation does not require both. The
Windows Alpha quick start installs a pinned `rage` release only to validate cross-client
interoperability. Shine uses the standard `age` CLI and does not require `rage` at runtime.

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

The Android build runs on Temurin JDK 17. Install the project JDK with [mise](https://mise.jdx.dev/)
from the repository root:

```console
mise install
mise exec -- java -version
```

With `mise activate` configured for your shell, entering the repository sets `JAVA_HOME`
automatically. For scripts and non-interactive shells, run commands through `mise exec --`.

```console
cargo run -p age-plugin-phone -- status
cargo run -p age-plugin-phone -- pair --help
cargo run -p age-plugin-phone -- unwrap --help
cargo run -p age-plugin-phone -- qr-capture-probe
cargo run -p age-plugin-phone -- remove-desktop-state --help
cargo run -p age-plugin-phone -- remove-orphaned-desktop-state --help
cargo test --workspace

cd apps/mobile
bun install
bun run tauri android init
bun run tauri ios init
```

On Windows, `status` performs a read-only Alpha capability probe. It reports the actual Windows
version, client/server edition, x64 architecture, TPM 2.0 availability, and Microsoft Platform
Crypto Provider availability without creating or opening persisted keys.

The Android Alpha UI shows the StrongBox identity status and public recipient, offers explicit
Developer USB or QR pairing, a QR approval fallback, and an owner-only foreground Wi-Fi
auto-listen toggle. It also lists paired desktops and provides native-confirmed revocation and identity
deletion. A normal Developer USB unwrap launches the app automatically and enters the same native
one-shot authorization controller. Revocation becomes
durable before its pairing record is removed; identity deletion is journaled before pairings and
StrongBox aliases are destroyed. Interrupted deletion remains unavailable and cannot recreate an
empty replay scope.

The Android build's **Pair · QR** action scans the desktop offer, signs and
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

After phone-side revocation, `remove-desktop-state` requires the full transcript fingerprint and
uses a private crash-safe journal to remove only that pairing's replay state, TPM metadata, locator,
two exact CNG keys, and public stub. A pending cleanup makes the target pairing unavailable and may
be resumed; it does not claim phone-side revocation or affect another pairing.

If the public stub is already unavailable but its private locator remains,
`remove-orphaned-desktop-state --locator PATH` is the recovery-only equivalent. It accepts only an
exact canonical locator directly under the protected Windows configuration root, revalidates its
desktop ID and response-replay scope, and requires the same full transcript fingerprint. It removes
only private state; public stubs and phone-side revocation remain separate operations. Prefer the
stub-based command whenever the public stub still exists.

The unified `auto` transport policy defaults to the Developer USB ADB Alpha on Windows and QR on
other desktop platforms for `pair`, `unwrap`, and standard age identity operations. It resolves one
route before creating the protocol session and never races, switches, or silently retries after
sending begins. Pairing over ADB still requires **Pair via Developer USB** on the phone. For unwrap,
the desktop creates the exact reverse rule and launches one fixed, payload-free Android action;
cold start and an existing `singleTask` instance both enter the native USB controller without a
manual pre-step.
Use `--adb-serial SERIAL` when multiple devices are listed by ADB. `--transport qr` selects the
camera fallback without changing the pairing. For standard age invocations, set
`AGE_PLUGIN_PHONE_TRANSPORT=qr` for that fallback or `AGE_PLUGIN_PHONE_ADB_SERIAL=SERIAL` for
explicit device selection. The accepted choices are `auto`, `adb`, `ble`, `wifi`, and `qr`; `ble`
is reserved and fails closed until its native proof of concept is reviewed and implemented.

For the owner-only foreground Wi-Fi unwrap PoC, enable **Wi-Fi auto-listen** once and keep the phone
App visible. The opt-in is stored in app-private non-backed-up state and defaults off. Then invoke
age with `AGE_PLUGIN_PHONE_TRANSPORT=wifi` and
`AGE_PLUGIN_PHONE_WIFI_ADDRESS=PHONE_PRIVATE_IPV4:47140`; unset
`AGE_PLUGIN_PHONE_ADB_SERIAL`. While enabled and foregrounded, the native listener automatically
re-arms after bounded timeouts, failures, cancellation, or completion. **Pause · Wi-Fi
auto-listen** closes the current listener, accepted socket, or pending biometric operation; it does
not restore an accepted request or retry it on another transport. With `auto`, an explicit Wi-Fi
address pins this one route; it does not create discovery or fallback. The experiment provides no
pairing, discovery, background wake, or production support claim.
The LAN route is untrusted and every accepted request still requires paired-desktop verification,
durable replay consumption, and a fresh StrongBox-backed biometric operation.
The toggle is available in every Android build. Build the side-by-side Android experiment with
`bun run android:build:wifi-poc`; its dedicated
build path uses a `.wifipoc` application-ID suffix and therefore has independent application
storage, StrongBox keys, and pairings. An ordinary debug APK retains the signed preview's package ID
and must not be installed over it.

> [!CAUTION]
> Developer USB requires Android USB debugging and ADB authorization. An ADB-authorized desktop has
> much broader access to the phone than this application needs. ADB identity, device state, and the
> cable are not trusted by the protocol and do not replace the fresh phone biometric operation.

Doctor diagnostics are visible only in debug builds and return non-sensitive reports. Release
builds keep the product identity plugin enabled but reject Doctor commands. Signed Alpha artifact
creation is defined in [the Milestone 6 Alpha release guide](docs/milestone-6-alpha.md), with
credential provisioning and RC0 dispatch in [the signing runbook](docs/release-signing.md). The
workflow intentionally fails when signing configuration is absent or does not match the registered
certificate identity.

For a synthetic-data walkthrough from signed package verification through pairing, reference-age
round trips, recovery, and the existing Shine configuration boundary, use the
[Windows Alpha quick start](docs/windows-alpha-quickstart.md).

CI also runs [`scripts/interoperability-smoke.sh`](scripts/interoperability-smoke.sh) against
checksum-pinned released age and rage binaries. It verifies that both clients invoke the production
recipient plugin for multiple phone recipients and files, preserve v1/v2 stanza counts, and recover
byte-for-byte through an independently generated recipient. This portable check does not replace a
fresh-biometric physical phone unwrap.

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
[owner-only technical preview scope](docs/owner-only-preview.md),
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
