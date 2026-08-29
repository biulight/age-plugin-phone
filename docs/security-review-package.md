# Independent security review package

Status: package prepared; independent review has not started.

This is the entry point for the Milestone 5 cryptographic and implementation review. The protocol
is experimental version 2 and is not suitable for production secrets. Preparing this package does
not approve the design or freeze compatibility.

## Review candidate and evidence handling

Review must target an immutable commit and the exact artifacts built from it, not a moving branch.
The preparation baseline was commit `c49f4da`; it is not the review candidate because this package
and the remaining device evidence follow it. Before review starts, create a dedicated review tag,
record the full commit and artifact SHA-256 digests here, and make every later finding resolution a
separate auditable change.

Device reports may contain versions, public capability results, synthetic-input digests, coarse
error categories, and pass/fail outcomes. They must not contain private keys, file keys, plaintext,
raw protocol payloads, QR contents, stanza bodies, key aliases, private paths, or unredacted device
serials and caller labels.

## Security claim under review

For a ciphertext addressed to a paired version 2 phone recipient, copying desktop files is
insufficient to decrypt it on another machine; the phone releases only one request-bound age file
key after a fresh StrongBox-backed user-verification operation; replay, wrong-device, malformed,
expired, cancelled, invalidated, or failed-transport paths release no file key and create no weaker
fallback.

The trusted computing base and adversary are defined in [the threat model](threat-model.md). In
particular, administrator/kernel compromise, phone OS or secure-hardware compromise, user approval
of a deceptive request, and plaintext compromise after a legitimate approval are out of scope.
Developer USB assumes the ADB-authorized desktop fully controls the stream and may use unrelated ADB
capabilities.

## Design and implementation map

| Review area | Normative design | Primary Rust implementation and tests | Primary Android implementation and tests |
| --- | --- | --- | --- |
| P-256 age recipient and file-key wrap | [ADR 0001](adr/0001-experimental-p256-recipient.md), [ADR 0012](adr/0012-private-stanza-selection.md) | `crates/recipient-p256/src/lib.rs`, `crates/recipient-p256/src/plugin.rs`, `docs/test-vectors/p256-recipient-v1.json`, `docs/test-vectors/p256-recipient-v2.json` | `TaggedRecipientCrypto.kt`, `TaggedRecipientCryptoTest.kt` |
| Canonical pairing transcript and fingerprints | [ADR 0002](adr/0002-experimental-offline-envelope.md), [ADR 0008](adr/0008-bidirectional-pairing.md), [ADR 0014](adr/0014-split-desktop-key-protocol-v2.md) | `crates/protocol/src/lib.rs`, `crates/desktop/src/pairing.rs`, `docs/test-vectors/pairing-transcript-v2.json` | `PairingConfirmationSession.kt`, `NativePairingResponseController.kt` and their tests |
| Long-term P-256 role separation | [ADR 0002](adr/0002-experimental-offline-envelope.md), [ADR 0013](adr/0013-windows-cng-key-boundaries.md), [ADR 0014](adr/0014-split-desktop-key-protocol-v2.md) | Transcript checks in `crates/protocol/src/lib.rs`, strict stub checks in `crates/desktop/src/pairing.rs`, and custody in `crates/windows-cng/src/windows.rs` | Transcript checks in `OfflineEnvelopeCrypto.kt`, state checks in `PairingStateStore.kt`, and custody in `PhoneIdentityKeyStore.kt` |
| Private stanza selection | [ADR 0012](adr/0012-private-stanza-selection.md) | `crates/recipient-p256/src/lib.rs`, `crates/desktop/src/age_identity.rs` | `TaggedRecipientCrypto.kt` structural and unwrap validation |
| Signed, encrypted response envelope | [ADR 0002](adr/0002-experimental-offline-envelope.md), [ADR 0009](adr/0009-one-shot-qr-unwrap.md) | `crates/protocol/src/lib.rs`, `crates/desktop/src/unwrap.rs`, `docs/test-vectors/offline-envelope-v2.json` | `OfflineEnvelopeCrypto.kt`, `NativeUnwrapResponseController.kt` and tests |
| Windows and Android replay storage | [ADR 0003](adr/0003-persistent-replay-state.md), [ADR 0004](adr/0004-android-pairing-state.md), [ADR 0015](adr/0015-windows-private-storage.md) | `crates/protocol/src/replay.rs`, `crates/windows-storage/src/windows.rs`, `crates/desktop/src/locator.rs` | `PairingStateStore.kt`, `PairingStateStoreTest.kt` |
| CNG/TPM custody and Windows private files | [ADR 0013](adr/0013-windows-cng-key-boundaries.md), [ADR 0015](adr/0015-windows-private-storage.md) | `crates/windows-cng`, `crates/windows-storage`, Windows paths in `crates/desktop` | Not applicable |
| Android StrongBox custody and per-use authorization | [ADR 0007](adr/0007-android-production-key-custody.md), [ADR 0009](adr/0009-one-shot-qr-unwrap.md), [StrongBox PoC](android-strongbox-poc.md) | Portable verifier and operation traits in `crates/protocol` and `crates/recipient-p256` | `PhoneIdentityKeyStore.kt`, `PhoneIdentityPlugin.kt`, `NativeUnwrapResponseController.kt` and tests |
| QR and common stream framing | [ADR 0005](adr/0005-qr-framing.md), [ADR 0006](adr/0006-native-qr-capture.md), [ADR 0011](adr/0011-desktop-native-qr-scanner.md), [ADR 0016](adr/0016-common-transport-and-adb-alpha.md) | `crates/protocol/src/qr.rs`, `crates/transport/src/lib.rs`, `crates/desktop/src/qr_scanner.rs` | `QrFraming.kt`, `QrScanSession.kt`, `NativeQrScannerController.kt`, `StreamTransport.kt` and tests |
| Developer USB ADB orchestration | [ADR 0016](adr/0016-common-transport-and-adb-alpha.md) | `crates/desktop/src/adb.rs`, transport selection in `crates/desktop/src/main.rs` and `age_identity.rs` | `MainActivity.kt`, `UsbUnwrapWakeCoordinator.kt`, `StreamTransport.kt`, and USB controllers in `PhoneIdentityPlugin.kt` |
| Standard age plugin state machines | [ADR 0010](adr/0010-reference-age-state-machines.md) | `crates/desktop/src/age_recipient.rs`, `crates/desktop/src/age_identity.rs` | Phone receives only the already selected, signed one-shot request |
| Lifecycle, revocation, invalidation, and recovery | [ADR 0017](adr/0017-lifecycle-and-recovery.md), [Alpha matrix](alpha-matrix.md) | Product implementation pending | Product implementation pending |

All Android filenames in the table are below
`plugins/tauri-plugin-phone-identity/android/src/main/java/io/github/biulight/phone_identity`; their
unit tests are in the parallel `src/test` tree.

## Cryptographic inventory

- P-256 ECDH unwrap key: non-exportable StrongBox, auth-per-use, `BIOMETRIC_STRONG`, invalidated by
  biometric enrollment change.
- P-256 ECDSA phone key: distinct non-exportable StrongBox key that signs pairing and already-
  authorized responses; it cannot unwrap an age stanza.
- P-256 ECDSA desktop key: distinct non-exportable Microsoft Platform Crypto Provider key that signs
  offers and requests.
- P-256 ECDH desktop selection key: distinct non-exportable Microsoft Platform Crypto Provider key
  that authenticates a private 16-byte identity selector and never decrypts a file key.
- P-256 one-time desktop and phone session keys: fresh per unwrap response envelope.
- HKDF-SHA256 with role- and version-specific domains; ChaCha20-Poly1305 for recipient and response
  encryption; SHA-256 for digests and fingerprints; fixed-width low-S P-256 ECDSA signatures.
- Canonical compressed SEC1 public points, canonical unpadded Base64 where required, and fixed-array
  canonical CBOR with unknown/extra fields rejected.

The reviewer should independently verify domain separation, zero-nonce safety assumptions, P-256
ECDH encoding and invalid-point handling, low-S normalization, transcript completeness, selector
privacy claims, response AAD/signature coverage, and whether any state-machine ordering permits a
file key or authorization to escape before durable replay consumption.

## State and trust-boundary checklist

The review should trace these boundaries end to end:

1. Untrusted age client inputs through strict recipient/stanza parsing and multi-identity selection.
2. Public desktop state through locator validation, TPM handle opening, signed request creation, and
   one-time session-key custody.
3. Opaque request bytes through QR or ADB framing without assigning transport trust.
4. Android pairing lookup by untrusted identifiers, signature/binding/expiry checks, durable request
   consumption, and creation of exactly one auth-per-use `KeyAgreement`.
5. StrongBox unwrap through immediate response encryption/signing and transient-buffer clearing.
6. Desktop response verification, AEAD authentication, durable response consumption, and the sole
   return of an `age_core::format::FileKey` to the age state machine.
7. Cancellation, timeout, restart, process death, storage failure, and hardware invalidation at each
   transition.

Special attention is requested for unsafe Windows FFI, ACL and reparse/hard-link validation,
write-through replacement semantics, cleanup-guardian process lifetime, Android Activity and
`BiometricPrompt` callbacks, Java/Kotlin byte-array copies, Rust zeroization boundaries, and all
error paths that cross the native/WebView boundary.

## Reproduction

From a clean checkout of the review commit with the locked dependencies. The Android build uses a
supported JDK 17 runtime; do not rely on the workstation's newest installed JDK:

```console
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

cd apps/mobile
bun install --frozen-lockfile
bun run build

cd src-tauri/gen/android
set JAVA_HOME=<path-to-jdk-17>
.\gradlew.bat :tauri-plugin-phone-identity:testDebugUnitTest
```

Windows CNG/storage tests and Android device tests must run in the native user/device contexts; a
restricted build sandbox may correctly report TPM or provider access as unavailable. The reviewer
must compare Rust/Kotlin results against the committed non-secret vectors and confirm that fixed
test scalars never enter a production Keystore.

The Kotlin pairing-state tests run the production state machine against a test-only
`DurableFileOperations` implementation. On POSIX hosts it exercises real owner-only modes and
symbolic links. On Windows JVM hosts, where those POSIX APIs and unprivileged symbolic-link creation
are unavailable, it explicitly simulates only the private/non-private and symbolic-link filesystem
decisions while retaining the same malformed-state, wrong-scope, replay, locking, durability,
poisoning, and confirmation transitions. This keeps the Windows review command reproducible but
does not replace Android on-device storage and lifecycle tests.

The physical procedure and required version metadata are defined in the
[Alpha matrix](alpha-matrix.md). Device evidence must include the two still-open Milestone 4 cases:
wrong paired physical device and injected response replay.

## Required reviewer outputs

The independent reviewer should provide:

- scope, reviewed commit/tag, artifact digests, environment, methods, and any excluded area;
- findings with severity, exploit preconditions, affected claim and code/design locations;
- a separate cryptographic assessment of both P-256 recipient versions, the v2 selector, pairing
  transcript, request/response envelope, key separation, and protocol domains;
- an implementation assessment of Rust, Windows CNG/storage, Kotlin/Android authorization and
  lifecycle, transports, and age state machines;
- validation or rejection of the stated security claim and threat-model assumptions; and
- explicit closure evidence for every resolved finding, including regression tests where possible.

Project maintainers record findings without rewriting their original meaning:

| ID | Severity | Area | Summary | Resolution commit | Reviewer verification | Status |
| --- | --- | --- | --- | --- | --- | --- |
| _none yet_ | | | Independent review not started | | | Open |

Accepted risks require a written rationale and cannot contradict the mandatory repository security
rules. Deferred findings that affect key custody, authorization freshness, message binding, replay,
strict parsing, or transport independence keep the Alpha gate closed.

## Known open items

- The wrong-paired-phone and injected-response-replay physical Windows cases remain incomplete.
- Automatic Developer USB cold/warm/background wake and malformed-wake behavior have portable
  coverage but still require packaged Windows/Android evidence.
- The rage, Shine, independent-recovery, second Android device family, and packaged-artifact rows in
  the Alpha matrix remain incomplete.
- Journaled paired-desktop revocation and phone identity deletion are implemented; their remaining
  packaged lifecycle and invalidation matrix is listed in the Alpha matrix.
- RC0 test-signed Windows and Android packaging and CI verification exist. A publicly trusted
  Windows signing program and the immutable final review candidate artifacts remain pending.
- No independent cryptographic or implementation review has been obtained.
- Protocol version 2 is deliberately unfrozen. Upgrade, downgrade-rejection, and compatibility
  policy will be decided only after findings are resolved.
