# ADR 0008: Bidirectional pairing and public desktop identity stub

- Status: experimental, accepted for implementation testing
- Date: 2026-08-25
- Scope: persistent-key pairing response, transcript comparison, and desktop public identity stub

## Context

ADR 0006 stopped after native Android capture of a signed desktop offer. ADR 0007 then established
two persistent, non-exportable StrongBox keys and their public metadata. Pairing must connect those
boundaries without exporting a key, trusting QR framing, or persisting either peer before the user
compares the complete transcript.

## Decision

After native verification of the desktop offer, Android opens the committed production identity. A
missing identity is explicitly provisioned; malformed, incomplete, mismatched, unsupported, or
wrong-security-level state fails closed. The persistent phone authentication key signs a canonical
pairing response containing the committed identity identifier, recipient and signing public key.
The resulting signature is verified against that same public metadata before the response is used.

The response is fragmented and rendered as animated QR modules by a native full-screen controller.
Neither response bytes nor QR frame strings cross the Tauri/WebView command boundary. The same
controller displays the full lowercase transcript fingerprint and supplies the exact displayed
value to the existing one-shot confirmation session. Cancellation, five-minute timeout, lifecycle
loss, mismatch, duplicate action, existing pairing, or persistence failure is terminal.

The desktop keeps a role-separated P-256 authentication key in a versioned, owner-only file; this
is not an age identity key. Its one-shot session accepts only one canonical signed response bound to
the current signed offer. It displays the same full transcript fingerprint and requires the user to
enter that exact value. Timeout, clock rollback, cancellation, malformed input, wrong-offer
response, mismatch, and duplicate confirmation close the session.

After successful confirmation, the desktop creates a new standard `AGE-PLUGIN-PHONE-...` identity
stub. Its fixed-field canonical CBOR payload contains only identifiers, the canonical recipient,
both signing public keys, offer digest, and transcript fingerprint. It never contains either private
key. Creation uses create-new semantics and never overwrites an existing identity file. The current
CLI accepts response bytes from an external QR capture helper through an unpadded-Base64 file; the
helper transports opaque bytes and is not trusted for authentication.

## Consequences

- Pairing responses survive phone process death because they use the persistent StrongBox signing
  key and metadata, not an in-memory Doctor key.
- Both endpoints compare the fingerprint of the exact signed offer and response before persistence.
- Copying the public identity stub cannot decrypt or impersonate either endpoint.
- Desktop authentication-state loss requires explicit re-pairing; it never falls back to an age
  private identity on the desktop.
- A bundled desktop camera adapter remains packaging work. Its output will enter the same strict
  response verifier and cannot weaken transcript authentication.

## Validation

Rust tests cover successful confirmation and public-stub round trip plus cancellation, timeout,
wrong-offer response, malformed response, fingerprint mismatch, duplicate confirmation, unknown
stub fields, and absence of the desktop private scalar from the stub. Kotlin tests cover response
generation from bound persistent public metadata, signature verification, and wrong-offer rejection.
The existing Android confirmation tests continue to cover cancellation, mismatch, duplicate action,
and atomic persistence. Device validation of the new response-rendering controller remains required.
