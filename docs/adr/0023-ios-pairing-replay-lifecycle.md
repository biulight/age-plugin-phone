# ADR 0023: iOS pairing and replay lifecycle

Status: accepted for experimental iOS 17+ implementation

## Decision

iOS reuses protocol v2, P-256 recipient and stanza formats, canonical CBOR, QR framing, Wi-Fi
discovery, and the stream envelope without wire changes. Raw QR strings, pairing offers, unwrap
requests, stanzas, and file keys remain in Swift native code. Rust/Tauri receives only bounded
status and public summaries.

Each verified pairing and replay scope are one canonical CBOR file in excluded-from-backup
Application Support. Reads are bounded and strict. Writes use complete file protection, an
exclusive non-blocking lock, a same-directory temporary file, full flush, atomic rename, and
directory sync. Initial creation uses an OS-level exclusive rename. Missing, malformed,
rolled-back-clock, full, locked, or uncertain state fails closed. Requests are verified before
durable consumption, and consumption is never rolled back after cancellation, authentication
failure, backgrounding, disconnect, or response loss.

AVFoundation owns QR capture and Core Image owns response QR rendering. Network framework owns at
most one foreground UDP responder and bounded TCP session. Backgrounding, disabling the opt-in,
network failure, or starting another operation closes the exact listener, stream, native view, and
authentication context without transport switching. Network properties are delivery hints only.

Developer USB and ADB remain Android-only. iOS hides the USB action and its native command returns
`unsupported_transport` before protocol work.

## Consequences

- Pairing confirmation, unwrap authorization, cancellation, and response display are one-shot
  native sessions.
- Wi-Fi defaults off and listens only in the foreground with an identity and pairing.
- Revocation becomes deletion-pending before removal; identity deletion journals first, removes
  pairing scopes, then destroys the exact two keys.
- This phase adds no background execution, push wake, BLE, transport fallback, or TestFlight flow.
