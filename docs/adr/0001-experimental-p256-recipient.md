# ADR 0001: Experimental StrongBox P-256 tagged recipient

- Status: experimental, accepted for interoperability testing
- Date: 2026-08-24
- Scope: age file-key wrapping only; not pairing or transport

## Context

The Android StrongBox PoC proved that the test device can hold a non-exportable P-256 ECDH key and
bind every private operation to a fresh `BiometricPrompt.CryptoObject(KeyAgreement)` authorization.
The next risk is the construction that maps that key to an age plugin recipient stanza.

This ADR deliberately does not stabilize a public wire format. Version 1 below is an experimental
domain used to create public test vectors and a Rust/Kotlin interoperability implementation. It
must receive independent cryptographic review before release compatibility is promised.

## Decision

### Key separation

The P-256 identity key is used only to unwrap age file keys. Pairing signatures, request signatures,
and desktop one-time response encryption use separate keys and domains. No key is reused between
these roles.

### Plugin recipient

The age plugin name is `phone`. The plugin-recipient payload is exactly 34 bytes:

```text
0x01 || recipient_public_key
```

`recipient_public_key` is the canonical 33-byte compressed SEC1 encoding of a valid P-256 point.
The resulting user-facing recipient uses the age plugin Bech32 HRP `age1phone`. Unknown versions,
wrong lengths, non-Bech32 encodings, non-canonical encodings, infinity, and points not on P-256 are
rejected.

The desktop identity stub is not specified by this ADR and never contains the P-256 private key.

### Recipient stanza

The stanza is exactly:

```text
tag  = "phone-p256-v1"
args = [base64-no-pad(ephemeral_public_key)]
body = ciphertext || authentication_tag
```

The ephemeral public key is a canonical 33-byte compressed SEC1 P-256 point. There must be exactly
one argument and the body must be exactly 32 bytes: a 16-byte encrypted age file key followed by a
16-byte Poly1305 tag. Unknown tags, extra arguments, padded or non-canonical Base64, invalid points,
and all other body lengths are rejected before a private-key operation is requested.

### Cryptographic construction

Encryption generates a fresh uniformly random P-256 ephemeral scalar for every stanza and computes:

```text
shared_secret = P-256-ECDH(ephemeral_private_key, recipient_public_key)
salt          = ephemeral_public_key || recipient_public_key
wrap_key      = HKDF-SHA256(shared_secret, salt,
                            "age-plugin-phone/recipient/p256/v1")
nonce         = 12 zero bytes
aad           = "phone-p256-v1" || 0x00 ||
                ephemeral_public_key || recipient_public_key
body          = ChaCha20-Poly1305(wrap_key, nonce, aad, file_key)
```

P-256 ECDH output is the 32-byte big-endian affine x-coordinate, including leading zero bytes.
The zero nonce is safe only because every stanza derives an independent key from a fresh ephemeral
key. Reusing an ephemeral scalar with the same recipient is prohibited.

Shared secrets, wrapping keys, and plaintext file keys are zeroized as soon as the operation ends.
They are never logged or returned to the WebView.

## Parsing and authorization order

All public structure is validated before showing the biometric prompt: exact tag, argument count,
canonical Base64, body length, and P-256 point validity. The authenticated StrongBox ECDH operation
then derives the wrapping key. Authentication failure, cancellation, AEAD failure, wrong identity,
or any malformed value fails closed without fallback.

## Test vectors

`docs/test-vectors/p256-recipient-v1.json` contains explicitly non-secret fixed scalar inputs and
public expected outputs for deterministic cross-language verification. In keeping with repository
logging rules, it does not record the derived shared secret or wrapping key. The fixed scalars are
test data and must never be imported into Android Keystore or used for real encryption.

## Consequences

- Rust and Kotlin can be tested before QR, BLE, pairing, or canonical CBOR exists.
- The stanza remains compatible with the age plugin mechanism without claiming compatibility with
  the built-in X25519 recipient.
- A future incompatible change uses a different payload version and stanza tag; it does not parse
  ambiguous optional fields.
- Production implementation remains blocked on protocol binding and independent cryptographic
  review.

## Interoperability evidence

2026-08-24 validation completed:

- the Rust reference and Kotlin native implementation consumed the same committed JSON vector and
  produced the same compressed public keys, stanza argument, ciphertext, and successful unwrap;
- malformed structure, non-canonical Base64, invalid points, wrong identity, and modified
  ciphertext failed closed in automated tests;
- a Samsung `SM-F9660` running Android 16 generated a disposable auth-per-use StrongBox identity,
  approved one `CryptoObject(KeyAgreement)` operation, and successfully unwrapped a randomly
  generated synthetic file key through this exact HKDF/AEAD construction;
- only `authenticated: true` and `agreementMatch: true` crossed into the WebView; the disposable
  key was then deleted and absence confirmed;
- a PID-scoped log scan found none of the prohibited key, alias, payload, or operation material.

Production use remains blocked on request-bound response encryption, canonical protocol encoding
and signatures, broader negative end-to-end tests, and independent cryptographic review.
