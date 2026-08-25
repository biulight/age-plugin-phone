# ADR 0002: Experimental canonical offline envelope

- Status: experimental, accepted for deterministic testing
- Date: 2026-08-24
- Scope: pairing transcript, unwrap request, and request-bound response envelope

## Context

The StrongBox P-256 tagged-recipient construction now interoperates between Rust, Kotlin, and a
live Android device. Transport must not define the signed bytes accidentally, and the phone must
never return a bare file key. The next boundary is therefore a canonical, transport-independent
request and encrypted response.

This ADR does not stabilize version 1. QR and BLE remain out of scope until deterministic vectors,
negative tests, and independent review are complete.

## Key separation

Three roles use independent keys:

1. the StrongBox P-256 age identity unwraps a matching recipient stanza after fresh authorization;
2. desktop and phone P-256 ECDSA keys authenticate pairing, requests, and responses;
3. a fresh desktop P-256 session key and fresh phone P-256 response key protect one returned file
   key.

No private key or authorization is reused across roles. Public keys use canonical compressed
33-byte SEC1 encoding. ECDSA signatures use fixed 64-byte `r || s` encoding and low-S form;
non-canonical high-S signatures are rejected.

## Canonical encoding

Every message is a canonical CBOR array with fixed length and positional fields. A signed message
is the two-element array:

```text
[canonical_payload : bstr, signature : bstr .size 64]
```

The signature input is:

```text
domain || 0x00 || canonical_payload
```

Decoders reject unknown versions, suites, message types, array lengths, trailing bytes,
non-minimal/non-canonical CBOR, wrong byte lengths, invalid UTF-8, and oversized display labels.
JSON is never signed.

Protocol version and suite are both `1` for the experimental vectors. Message types are:

- `1`: pairing offer;
- `2`: pairing response;
- `3`: unwrap request;
- `4`: unwrap response.

Identifiers are 16 random bytes. Nonces and request digests are 32 bytes. Display labels are
untrusted UTF-8 and limited to 64 encoded bytes.

## Pairing

The desktop signs a pairing offer containing its identifier, untrusted label, signing public key,
and nonce. The phone response contains the target identity identifier, canonical `age1phone`
recipient, phone signing public key, complete signed-offer digest, and a fresh nonce. The response
is signed by the phone key.

Both sides derive the comparison fingerprint from the complete signed offer and response before
persisting either peer. Signature proof-of-possession does not replace the user comparison.

## Unwrap request

The desktop signs an exact request containing both paired identifiers, request identifier, nonce,
expiry, one-time session public key, complete P-256 tagged recipient stanza, and optional untrusted
caller hint. The phone verifies structure, signature, paired identifiers, expiry, recipient stanza,
and replay state before showing authorization UI.

Expiry must not be in the past or more than 300 seconds in the verifier's future. A request ID or
nonce is consumed on first accepted verification, including later cancellation, so replay cannot
create another prompt.

The request digest is:

```text
SHA-256("age-plugin-phone/request-digest/v1" || 0x00 || complete_signed_request)
```

## Response encryption and binding

After StrongBox unwrap, the phone generates a fresh P-256 response key and response nonce, then
computes ECDH with the request's one-time desktop session public key:

```text
salt     = request_digest || response_nonce
key      = HKDF-SHA256(shared_secret, salt,
                       "age-plugin-phone/session-response/p256/v1")
nonce    = 12 zero bytes
aad      = canonical response metadata excluding ciphertext and signature
ciphertext = ChaCha20-Poly1305(key, nonce, aad, file_key)
```

The signed response binds version, suite, both paired identifiers, request identifier and digest,
phone ephemeral public key, response nonce, and the 32-byte ciphertext. The desktop first verifies
the phone signature and every expected binding, then performs ECDH and AEAD decryption. A response
is consumed at most once.

## Security consequences

- The phone-facing API can return only an encrypted response envelope, never a bare file key.
- Captured responses cannot be moved to another request, identity, desktop, or one-time session key.
- Caller labels remain display-only and are nevertheless signed to prevent post-signature UI
  substitution.
- Durable replay consumption is defined by
  [`ADR 0003`](0003-persistent-replay-state.md). The bounded file backend commits before a verified
  request or decrypted file key is released; the in-memory guard remains test-only.
- Production remains blocked on pairing/mobile integration of persistent replay state, complete
  lifecycle tests, and independent cryptographic review.

## Cross-language evidence

2026-08-24 the Kotlin native implementation consumed the same committed Rust request/response
vector. It strictly re-encoded the canonical CBOR, verified the fixed-width low-S desktop and phone
signatures, reproduced the request digest, and decrypted the response with the fixed desktop
session key. Wrong desktop, expiry, signature mutation, and non-canonical input failed closed.

The original `pairing-transcript-v1.json` vector covered the complete signed offer and response,
offer digest, both static signing public keys, canonical `age1phone` recipient, and transcript
fingerprint. Rust and Kotlin reproduce the same bytes and fingerprint. Both implementations reject
signature mutation and high-S signatures, response binding to another offer, malformed or
non-canonical envelopes, unknown versions, invalid recipients, and oversized display labels in
their applicable parsing paths.

ADR 0014 supersedes this version 1 layout and replaces the committed pairing and envelope vectors
with `pairing-transcript-v2.json` and `offline-envelope-v2.json`.

The Android Doctor now builds a synthetic signed request in native memory, validates it before
authorization, unwraps the synthetic stanza only through the authenticated StrongBox operation,
and seals the result into a request-bound encrypted response. It reports only boolean agreement and
envelope matches. On 2026-08-24 this combined path passed on a Samsung SM-F9660 running Android 16:
`authenticated`, `agreementMatch`, and `responseEnvelopeMatch` were all `true`. The disposable
StrongBox key was then deleted and confirmed absent, and the scoped process-log scan found none of
the prohibited key, payload, alias, or operation-handle material. No production pairing state or
real secret was involved.
