# Offline protocol draft

Status: design draft; not a stable wire format and not suitable for real secrets.

The experimental P-256 file-key wrapping construction is specified separately by
[`ADR 0001`](adr/0001-experimental-p256-recipient.md). It does not select the pairing, request, or
response wire encoding described here.

The experimental canonical pairing/request and encrypted response envelope is specified by
[`ADR 0002`](adr/0002-experimental-offline-envelope.md). Its pairing and unwrap transcripts have
deterministic Rust/Kotlin interoperability vectors, but it remains unsuitable for real secrets or
transport compatibility commitments.

## Pairing

Pairing is a bidirectional QR exchange that authenticates the desktop and phone static public keys.
Both screens show a short fingerprint derived from the complete transcript before either endpoint
persists the peer.

Desktop state contains only public keys, identity identifiers, recipients, and transport metadata.
Phone state contains the private identity, paired desktop public keys, counters, and revocation
state.

## Unwrap request

Each request contains:

- protocol version and algorithm suite;
- paired desktop and phone identity identifiers;
- a random request identifier and nonce;
- a one-time desktop session public key;
- the complete age recipient stanza;
- a short absolute expiry;
- an optional, explicitly untrusted caller label; and
- a desktop signature over the canonical request.

The phone hashes the canonical request, displays its paired device and request fingerprint, and
durably consumes its request ID and nonce before requiring a fresh system user-verification
gesture. Approval is never cached. Missing, corrupt, full, mismatched, or unavailable replay state
fails closed before a prompt appears.

## Unwrap response

The response contains the request identifier and digest, a fresh nonce, and only the age file key
encrypted to the request's one-time session public key. It is signed by the paired phone key.

The desktop rejects a response if any binding, signature, expiry, algorithm, identity, nonce, or
request digest differs. After authenticating the ciphertext it durably consumes the response digest
before returning the file key. A response is consumed at most once.

## Replay state

Persistent consumption is specified in
[`ADR 0003`](adr/0003-persistent-replay-state.md). State is bound to one pairing and endpoint role,
has a clock high-water mark and hard capacity, and stores only request IDs/nonces or response
digests through the request expiry. Opening missing state never silently creates an empty store.
The in-memory guard is for deterministic tests only.

On Android, [`ADR 0004`](adr/0004-android-pairing-state.md) makes the verified public pairing record
and phone request-replay state one atomic, non-backed-up app-private storage unit. Native request
verification uses the identifiers and desktop signing key loaded from that record, then durably
consumes the request before returning it to any authorization path. Pairing deletion makes the
scope unavailable; it never recreates an empty replay set.

## Encoding

Protocol payloads use fixed-length canonical CBOR arrays and reject unknown or extra fields. Signed
envelopes contain the canonical payload bytes and a fixed-width low-S P-256 ECDSA signature. JSON
exists only as a public test-vector container and is never signed. QR framing remains unspecified.

The response file key is encrypted to the request's one-time P-256 session key with a fresh phone
session key, HKDF-SHA256, and ChaCha20-Poly1305. Its AEAD context and phone signature bind both
paired identifiers, request ID and digest, response nonce, and both session participants.

## BLE

BLE transports the same application messages after mutually authenticated ephemeral key agreement.
Advertisements, OS-level BLE pairing, device names, and MAC addresses are discovery hints only and
are never authentication inputs.
