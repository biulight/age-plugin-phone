# Offline protocol draft

Status: design draft; not a stable wire format and not suitable for real secrets.

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
requires a fresh system user-verification gesture. Approval is never cached.

## Unwrap response

The response contains the request identifier and digest, a fresh nonce, and only the age file key
encrypted to the request's one-time session public key. It is signed by the paired phone key.

The desktop rejects a response if any binding, signature, expiry, algorithm, identity, nonce, or
request digest differs. A response is consumed at most once.

## Encoding

The Rust structs currently model required information but do not select a wire encoding. Canonical
CBOR plus explicit QR framing is the leading candidate. JSON must not become the signed canonical
form accidentally through early prototypes.

## BLE

BLE transports the same application messages after mutually authenticated ephemeral key agreement.
Advertisements, OS-level BLE pairing, device names, and MAC addresses are discovery hints only and
are never authentication inputs.

