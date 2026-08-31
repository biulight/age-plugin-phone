# Architecture

## Product boundary

`age-plugin-phone` is an age plugin, not a Shine component. Applications integrate through an age
client and the standard age plugin protocol. The phone does not parse application configuration,
environment variables, or plaintext.

## Components

1. The desktop plugin receives recipient stanzas from an age client.
2. The transport builds an authenticated, request-bound QR, BLE, or USB exchange.
3. The phone validates the paired desktop, expiry, nonce, and request digest.
4. The phone displays the device and identity involved, then requires system user verification.
5. The hardware-backed phone identity unwraps one matching age file key.
6. The phone encrypts that file key to the desktop's one-time session public key.
7. The desktop plugin returns the file key to the age client and zeroizes its transient state.

The full age ciphertext and its plaintext remain on the desktop. The long-term identity remains on
the phone.

## Mobile application boundary

The mobile application uses Tauri 2 for navigation, rendering, lifecycle, and a small Rust core.
The WebView receives only non-sensitive presentation models such as paired-device labels, request
fingerprints, expiry, and success or cancellation state.

Hardware-key creation and file-key unwrap are implemented by a dedicated Tauri mobile plugin:

- Swift calls Secure Enclave and LocalAuthentication APIs on iOS.
- Kotlin calls Android Keystore/StrongBox and `BiometricPrompt` on Android.
- User verification is attached to the private-key operation by the native platform policy.
- Native code returns an already encrypted, request-bound response to Rust, never key bytes to
  JavaScript.

Android QR capture is owned by the native Kotlin plugin so raw frame strings and signed protocol
bytes never become Tauri command values. The generic biometric plugin alone is insufficient because
a separate authentication success boolean is not
cryptographically bound to the later private-key operation. BLE requires a reviewed native plugin
and is not part of the first milestone.

## Identity strategy

The Android production candidate is a hardware-native P-256 key compatible with age tagged
recipients. The StrongBox PoC passed on a Samsung `SM-F9660` running Android 16: the non-exportable
P-256 ECDH key was reported at the `STRONGBOX` security level, and every operation was bound to a
fresh `BiometricPrompt.CryptoObject(KeyAgreement)` authorization. This selects the P-256 tagged
recipient path for the next protocol PoC; it does not freeze the wire format.

The experimental construction, strict parsing rules, and cross-language vector are recorded in
[`ADR 0001`](adr/0001-experimental-p256-recipient.md). Its Rust reference implementation is kept
transport-independent so QR and pairing cannot silently define the recipient cryptography.

Canonical signed messages and the one-time desktop session response envelope are separately
recorded in [`ADR 0002`](adr/0002-experimental-offline-envelope.md). The protocol crate owns this
logic; transports carry opaque canonical bytes and do not redefine authentication or key binding.

Durable replay consumption is specified in
[`ADR 0003`](adr/0003-persistent-replay-state.md). The protocol crate provides scoped, bounded,
atomically replaced Unix and Windows file backends; the in-memory guard is test-only. Windows
locator, TPM metadata, ACL, locking, and replacement rules are specified by
[`ADR 0015`](adr/0015-windows-private-storage.md).

Android binds each public pairing record and its request-replay scope into one canonical state file
under `Context.noBackupFilesDir`, as specified in
[`ADR 0004`](adr/0004-android-pairing-state.md). Creation is explicit, opening missing state fails
closed, and native request verification returns only after the combined state replacement is
durable. A separate synthetic-data Doctor exercises create, consume, reopen, replay rejection,
wrong scope, deletion, and cleanup without exposing paths or protocol material to the WebView.

The native pairing-confirmation session accepts canonical signed offer/response bytes only from a
native transport controller. It verifies the complete transcript before producing a presentation
model containing just the untrusted desktop label and full transcript fingerprint. Confirmation is
one-shot: cancellation, a different or non-canonical fingerprint, duplicate confirmation, process
lifecycle loss, or failed persistence closes the session without retrying it. Raw QR and signed
protocol bytes are not Tauri command arguments and never enter JavaScript.

A wrapped native X25519 identity remains a separately reviewed fallback candidate for platforms
that cannot expose a suitable non-exportable operation. It is not enabled on the verified Android
path. Canonical pairing/request encoding and complete Rust/Kotlin protocol vectors now exist;
The native confirmation-to-persistence boundary now exists. Versioned canonical
framing and bounded animated-frame assembly are specified by
[`ADR 0005`](adr/0005-qr-framing.md) and implemented in Rust and Kotlin. Android native continuous
capture and desktop terminal animation are specified by
[`ADR 0006`](adr/0006-native-qr-capture.md). [`ADR 0008`](adr/0008-bidirectional-pairing.md)
connects the production StrongBox keys to phone response signing and native QR rendering. The
desktop verifies the response, compares the same full transcript fingerprint, and creates a
canonical public identity stub only after confirmation. The source-level independent review is
complete; the wire format remains experimental until compatibility policy and the remaining Alpha
evidence are complete.

[`ADR 0009`](adr/0009-one-shot-qr-unwrap.md) connects that pairing to one production-key Android
unwrap. Untrusted request identifiers route to candidate state only; the stored desktop key then
verifies the request and durable replay consumption precedes a new native biometric authorization.
The response remains encrypted and signed below the WebView boundary. The desktop uses a bounded
native camera worker to decode and reassemble response QR frames entirely in memory before passing
complete bytes to the same strict response verifier.

[`ADR 0010`](adr/0010-reference-age-state-machines.md) connects the public recipient and identity
stub to standard age `recipient-v1` and `identity-v1` state machines. A separate private,
transcript-bound locator resolves the desktop authentication and replay files; those paths are not
embedded in the public identity. Reference age can now create tagged stanzas and request a one-shot
phone unwrap without learning or storing a long-term age identity.

[`ADR 0012`](adr/0012-private-stanza-selection.md) adds pairing-specific v2 recipients. Each stanza
contains an authenticated identity selector encrypted to the paired desktop authentication key
under a domain separate from the phone file-key wrap. The desktop can therefore map anonymous
stanzas to the correct local pairing without a phone private operation or a public stable tag; the
desktop key still cannot decrypt the age file key.

[`ADR 0013`](adr/0013-windows-cng-key-boundaries.md) begins the Windows custody upgrade by
separating portable P-256 signing and key-agreement operations from concrete software scalars. A
dedicated CNG boundary provisions distinct non-exportable ECDSA and ECDH keys only through Microsoft
Platform Crypto Provider and fails closed on partial or exportable state. Its read-only support
probe requires a Windows 11-or-later x64 client, obtains the TPM version directly through Windows
TPM Base Services, requires TPM 2.0, and verifies that the Platform Crypto Provider opens. Pairing,
explicit unwrap, and the standard `identity-v1` state machine enforce this gate before protocol
work; no persisted key is created by the probe.

[`ADR 0014`](adr/0014-split-desktop-key-protocol-v2.md) upgrades the experimental protocol and all
pairing state to version 2. The signed offer, transcript fingerprint, public identity stub, and v2
paired recipient now bind distinct desktop signing and selection public keys. Version 1 messages,
stubs, desktop key files, locators, replay files, and Android pairing state are rejected rather than
migrated; users must pair again.

On Windows, production pairing and unwrap open the distinct CNG keys through operation traits;
software scalars are not compiled into that desktop state path. Private locator, public TPM-key
metadata, and response replay state live under `%LOCALAPPDATA%\age-plugin-phone` with protected
current-user ACLs. Missing or copied TPM keys, insecure files, concurrent replay owners, corrupt
state, failed replacement, or an unsupported Windows capability all fail closed.

The common one-request/one-response transport boundary and Developer USB ADB reverse Alpha are
specified by [`ADR 0016`](adr/0016-common-transport-and-adb-alpha.md). Stream framing binds a random
session ID, purpose, direction, and bounded body length but provides no authentication. Windows
defaults to ADB while QR remains a pairing-independent fallback. Android loopback stream bytes stay
inside the native Kotlin plugin and enter the same strict pairing and unwrap controllers as QR.
[`ADR 0018`](adr/0018-owner-only-foreground-wifi-poc.md) reuses that stream boundary for an opt-in
foreground-only Wi-Fi auto-listen experiment. Its private IPv4 route and foreground listener are
untrusted delivery hints and add no pairing, discovery, fallback, or authorization behavior.
[`ADR 0019`](adr/0019-unified-transport-policy.md) resolves `auto`, ADB, BLE, Wi-Fi, or QR into one
desktop route before a protocol session is created. Route hints pin one transport; an attempt never
races, switches, or silently retries after sending begins, and BLE remains unavailable until its
separately reviewed native proof of concept.

Identity replacement, paired-desktop revocation, deletion, application removal, and TPM/StrongBox
invalidation are specified by [`ADR 0017`](adr/0017-lifecycle-and-recovery.md). Version 2
ciphertexts bind both a phone identity and a paired desktop selection key, so replacing either
endpoint requires decrypting through a previously included independent recovery recipient and
encrypting anew. Pairing state and hardware private keys are never migrated or reconstructed.

## Transport strategy

QR is the first implementation target because it is observable, offline, and independent of radio
pairing behavior. BLE may follow after the application-layer protocol is stable. BLE pairing is
never the protocol's trust root; messages remain end-to-end authenticated and encrypted.

QR framing provides bounded corruption detection and assembly only. It never authenticates a peer.
The Android native scanner path owns raw frame strings, clears partial assemblies on failure or
cancellation, and passes only a complete digest-checked byte message to the native protocol parser.
Its Tauri result contains only a verified untrusted desktop label, offer digest, frame count, and
coarse error category. The desktop renderer writes QR modules and safe progress metadata, never the
frame text. The desktop scanner likewise keeps camera pixels, decoded frame text, partial chunks,
and complete responses in memory; only digest-checked complete bytes reach protocol verification.

ADB reverse is explicitly Developer USB mode. ADB device state and serials are untrusted endpoint
selection data only. The desktop uses an ephemeral loopback listener, passes no protocol bytes to
the ADB process, rejects an existing reverse rule, and removes only the exact rule it created.

The owner-only Wi-Fi PoC reverses the TCP role: after the user persistently opts in, Android keeps
one listener available only while the application is foregrounded and the desktop connects to a
numeric private IPv4 endpoint. The listener serializes requests and automatically re-arms with
bounded retry delays; leaving the foreground or pausing the mode closes its exact resources. It
carries only unwrap over the same bounded stream frame. LAN reachability, peer address, listener
availability, and connection success provide no authentication or approval, and the PoC has no
discovery, background wake, or fallback.

The unified desktop policy makes one deterministic choice before creating a pairing or unwrap
session. `auto` uses an explicit ADB or Wi-Fi route hint when present; otherwise it preserves ADB on
Windows and QR on other desktop platforms. This is not availability racing or fallback. A failed
attempt terminates, and a user retry creates a fresh signed protocol request.

## Integration invariant

No application-specific ciphertext, URI, environment variable, or RPC is allowed between Shine and
this project. A user who does not install Shine must be able to use the plugin with a compatible age
client.
