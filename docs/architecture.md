# Architecture

## Product boundary

Applications integrate with `age-plugin-phone` only through an age client and the standard age
plugin protocol. No Shine-specific ciphertext, URI, environment variable, or RPC is allowed between
Shine and this project. A user without Shine must be able to use it with a compatible age client.
The phone does not parse application configuration, environment variables, full age ciphertext,
or plaintext.

The protocol remains an experimental version 2 design. Source-level independent review is complete;
the wire format remains unfrozen pending compatibility policy and the remaining Alpha evidence.

## Unwrap flow

1. The desktop plugin receives recipient stanzas from an age client and selects a matching pairing.
2. It chooses one transport before creating a signed, request-bound unwrap session.
3. The phone verifies the paired desktop, expiry, nonce, and request digest, then durably consumes
   the request before prompting.
4. The phone displays the device and identity involved and requires fresh system user verification
   bound to the hardware identity operation.
5. The phone unwraps one matching age file key and signs a response encrypting it to the desktop's
   one-time session public key.
6. The desktop verifies the response and durably consumes it before returning the file key to the
   age client and zeroizing transient secrets.

The full age ciphertext and plaintext remain on the desktop; the long-term age identity stays on
the phone. Protocol authentication and key binding are independent of transport.

## Native mobile boundary

Tauri 2 provides navigation, rendering, lifecycle, and a small Rust core. Its WebView receives only
presentation models: untrusted paired-device labels, request fingerprints, expiry, and coarse
success, cancellation, or error state. Hardware-key operations, raw QR contents, protocol messages,
stanzas, and file keys stay inside the Kotlin or Swift native boundary, never Tauri command values
or JavaScript data. Native transports send already encrypted, request-bound responses directly.

Android uses Keystore/StrongBox and a fresh `BiometricPrompt.CryptoObject(KeyAgreement)` for each
identity unwrap. A separate authentication-success boolean is insufficient: authorization must bind
to that exact private-key operation. iOS 17+ uses Secure Enclave and a new `LAContext` for each
unwrap, with no authentication reuse. Lifecycle loss closes the native view, transport resources,
and authentication context without restoring consumed requests.

## Key custody and recipient cryptography

- The phone has distinct non-exportable P-256 ECDH identity and ECDSA signing keys. Only the identity
  key unwraps age file keys, with fresh user verification per use. The signing key authenticates
  messages without requiring or caching identity authorization. Android requires StrongBox with
  no TEE or software fallback ([ADR 0007](adr/0007-android-production-key-custody.md)); iOS requires
  Secure Enclave with no exportable or software-key fallback
  ([ADR 0022](adr/0022-ios-secure-enclave-key-custody.md)). Wrapped X25519 is an unimplemented
  historical candidate requiring separate review, not an enabled fallback on either platform.
- The desktop has distinct ECDSA request-signing and ECDH stanza-selection keys. Protocol version 2
  binds both public keys in the offer, transcript fingerprint, and public identity stub; the paired
  recipient uses the selection key. Version 1 protocol messages, stubs, desktop key files, locators,
  replay files, and Android pairing state are rejected rather than migrated; users must pair again
  ([ADR 0014](adr/0014-split-desktop-key-protocol-v2.md)).
- Windows pairing and unwrap require Windows 11+ x64 and TPM 2.0, checked through TPM Base Services
  and Microsoft Platform Crypto Provider. The support probe creates no persisted keys. CNG
  provisions distinct non-exportable keys and fails closed on partial, copied, missing, or
  exportable state; software scalars are excluded from this desktop state path
  ([ADR 0013](adr/0013-windows-cng-key-boundaries.md)).

The experimental P-256 recipient construction and cross-language vector are defined in
[ADR 0001](adr/0001-experimental-p256-recipient.md). Canonical signed messages and the encrypted
one-time response envelope belong to the protocol crate
([ADR 0002](adr/0002-experimental-offline-envelope.md)); neither pairing nor transports redefine
recipient cryptography.

## Pairing and replay state

Native pairing verifies both signed messages before returning the untrusted desktop label and full
transcript fingerprint for comparison. Both endpoints require exact full-fingerprint confirmation
before persisting a peer. Cancellation, mismatch, duplicate confirmation, lifecycle loss, or failed
persistence terminates the session; a retry requires a fresh exchange and complete verification.
The desktop rejects responses bound to another offer and creates only a public identity stub
([ADR 0008](adr/0008-bidirectional-pairing.md)). Existing state is never silently overwritten.

Replay state is scoped to a pairing and endpoint, bounded, and durably replaced. Missing, corrupt,
full, mismatched, or unavailable state fails closed instead of becoming an empty store; the
in-memory guard is test-only ([ADR 0003](adr/0003-persistent-replay-state.md)). Android atomically
stores the public pairing and request-replay scope under `Context.noBackupFilesDir`
([ADR 0004](adr/0004-android-pairing-state.md)). Its synthetic-data Doctor exercises persistence,
replay rejection, wrong scope, deletion, and cleanup without exposing paths or protocol material.
iOS uses protected, non-backed-up canonical state with exclusive locking and atomic replacement
([ADR 0023](adr/0023-ios-pairing-replay-lifecycle.md)).

Untrusted request identifiers only locate candidate state. Verification uses the stored desktop
signing key, and durable request consumption precedes each fresh biometric operation
([ADR 0009](adr/0009-one-shot-qr-unwrap.md)). Cancellation, authentication failure, backgrounding,
disconnect, or response loss never restores the consumed request. The desktop durably consumes an
authenticated response before releasing its file key.

Windows private locators, public TPM-key metadata, and response-replay state use protected
current-user ACLs under `%LOCALAPPDATA%\age-plugin-phone`. Insecure files, concurrent replay
owners, corrupt state, failed replacement, and unsupported capabilities fail closed
([ADR 0015](adr/0015-windows-private-storage.md)).

## Standard age integration

Public recipients and identity stubs connect to the standard `recipient-v1` and `identity-v1` state
machines. A separate private, transcript-bound locator resolves desktop key and replay state;
private keys and filesystem paths never enter the public stub
([ADR 0010](adr/0010-reference-age-state-machines.md)).

Each v2 stanza carries an authenticated identity selector encrypted to the paired desktop selection
key, in a domain separate from the phone file-key wrap. This selects the local pairing without a
phone private operation or public stable tag. The desktop selection key cannot decrypt the age
file key ([ADR 0012](adr/0012-private-stanza-selection.md), with key roles split by ADR 0014).

## Transport strategy

Transports carry opaque canonical protocol messages. Framing bounds allocation and detects
corruption or stream confusion; it does not authenticate peers or authorize unwrap.

QR framing and bounded assembly are defined by [ADR 0005](adr/0005-qr-framing.md). Android native
capture and desktop terminal animation follow [ADR 0006](adr/0006-native-qr-capture.md); iOS uses
AVFoundation and Core Image. Scanners keep pixels, raw frame text, partial chunks, and completed
responses in memory, clear assemblies on failure or cancellation, and pass only digest-checked
complete messages to strict protocol verification. Desktop rendering emits QR modules and safe
progress metadata, never raw frame text.

The one-request/one-response stream envelope binds a random session ID, purpose, direction, and
bounded length ([ADR 0016](adr/0016-common-transport-and-adb-alpha.md)). Android Developer USB
uses an ephemeral desktop loopback listener and ADB reverse. Device state and serials only select
an untrusted endpoint; no protocol bytes enter the ADB process. The desktop rejects existing reverse
rules and removes only the exact rule it created. iOS has no Developer USB UI and its native command
fails closed with `unsupported_transport`.

The owner-only foreground Wi-Fi experiment uses the same stream envelope
([ADR 0018](adr/0018-owner-only-foreground-wifi-poc.md)). After persistent user opt-in, Android
keeps one unwrap-only listener while foregrounded, serializes sessions, and re-arms with bounded
retry delays. Idle accept remains armed until its lifecycle owner closes it; leaving the foreground
or pausing closes its exact resources. iOS uses Network framework for foreground Wi-Fi. Listener
availability, private IPv4 routing, and TCP success provide no authentication or approval; there is
no Wi-Fi background wake.

Discovery and explicit Wi-Fi pairing follow [ADR 0021](adr/0021-wifi-discovery-and-pairing.md).
Bounded UDP queries target the limited broadcast address and, on multi-homed Windows hosts, each
eligible private IPv4 subnet broadcast. Existing-pairing responses must authenticate under the
paired phone-signing key and bind the exact query, including its nonce. Retransmits reuse only the
in-memory public signed response to that exact query, never identity authorization. The discovered
address remains an untrusted route hint. Pairing discovery is unauthenticated and requires the phone
user to open a separate one-shot foreground pairing listener; the signed exchange and complete
two-ended fingerprint comparison establish trust. The persistent unwrap listener never pairs.

The desktop resolves one route before creating a signed offer or unwrap request
([ADR 0019](adr/0019-unified-transport-policy.md), extended by ADR 0021). Explicit route hints pin
one route; a private per-pairing preference supplies the normal unwrap choice. Without a route hint,
`auto` tries bounded Wi-Fi discovery first: one matching source selects Wi-Fi; no response retains
ADB on Windows and QR elsewhere. Unwrap discovery requires authentication under the paired phone
key; pairing discovery requires one candidate in explicit phone pairing mode. Ambiguity or local
discovery failure is terminal. An attempt never races, switches, reconnects, or silently retries
once the signed session begins. Failure terminates it; user retries create fresh signed requests.
BLE remains unavailable pending a separately reviewed native implementation; OS-level BLE pairing
cannot become its trust root.

## Recovery and lifecycle

Identity replacement, paired-desktop revocation, deletion, application removal, and hardware
invalidation follow [ADR 0017](adr/0017-lifecycle-and-recovery.md). Version 2 ciphertext binds the
phone identity and paired desktop selection key. Replacing either endpoint requires decrypting
through an independent recovery recipient included at encryption time, then encrypting anew.
Pairing state and hardware private keys are never migrated or reconstructed.
