# ADR 0009: one-shot QR unwrap

Status: accepted for the prototype; not approved for production secrets.

## Decision

The desktop creates a fresh signed unwrap request for every stanza. The request has a new P-256
response-encryption key, request identifier, nonce, digest, and five-minute absolute expiry. The
desktop authentication key and every public field are checked against the selected public identity
stub before the request is displayed as bounded animated QR frames.

Android uses the request identifiers only to locate candidate pairing state. It then strictly
verifies the canonical request with the desktop signing key from that state and durably consumes the
request identifier and nonce before any authorization prompt. Consumption is not rolled back after
cancellation, timeout, lifecycle loss, invalidation, or cryptographic failure.

Each accepted request creates a new Android Keystore `KeyAgreement` initialized with the
non-exportable, auth-per-use StrongBox identity key. That exact object is passed through
`BiometricPrompt.CryptoObject`; only the identical object returned by a successful prompt may unwrap
the tagged-recipient stanza. Authorization is never cached or reused.

The file key is immediately encrypted to the request's one-time desktop session key and the
canonical response is signed by the paired StrongBox phone-signing key. Native code clears the ECDH
secret, plaintext file key, and encoded response after constructing opaque response QR frames. Raw
frames, signed protocol messages, and file keys never enter the WebView.

The desktop verifies every response binding and phone signature, authenticates the ciphertext, and
durably consumes the response digest before returning the file key to its caller. A session closes
on its first response attempt or cancellation.

## Prototype transport

Android scanning and response rendering are fully native. The current desktop prototype renders
requests itself but still relies on an external QR capture helper to populate the response file.
This file is an opaque transport artifact, not trusted protocol state. The standard age state
machines are now connected by [`ADR 0010`](0010-reference-age-state-machines.md); a desktop-native
response scanner remains interoperability work.

## Consequences

- Cancellation intentionally burns a request and requires a new desktop session.
- Missing, corrupt, mismatched, locked, or full replay state fails closed.
- A phone response cannot be moved to another request, desktop, identity, session key, or nonce.
- Caller labels are truncated, explicitly marked untrusted, and never used for authorization.
- The desktop never stores a long-term age identity or writes a plaintext file key.
