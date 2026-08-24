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

The official Tauri barcode scanner is a reasonable QR capture frontend. The generic biometric
plugin alone is insufficient because a separate authentication success boolean is not
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
[`ADR 0003`](adr/0003-persistent-replay-state.md). The protocol crate provides a scoped, bounded,
atomically replaced Unix file backend; the in-memory guard is test-only.

A wrapped native X25519 identity remains a separately reviewed fallback candidate for platforms
that cannot expose a suitable non-exportable operation. It is not enabled on the verified Android
path. Canonical pairing/request encoding and complete Rust/Kotlin protocol vectors now exist;
pairing/native-path integration of persistent replay state and independent review are still
required before the wire format is stabilized.

## Transport strategy

QR is the first implementation target because it is observable, offline, and independent of radio
pairing behavior. BLE may follow after the application-layer protocol is stable. BLE pairing is
never the protocol's trust root; messages remain end-to-end authenticated and encrypted.

## Integration invariant

No application-specific ciphertext, URI, environment variable, or RPC is allowed between Shine and
this project. A user who does not install Shine must be able to use the plugin with a compatible age
client.
