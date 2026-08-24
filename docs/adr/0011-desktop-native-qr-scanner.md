# ADR 0011: desktop-native response QR scanner

Status: accepted for the prototype; not approved for production secrets.

## Decision

The desktop binary owns response capture. A dedicated worker opens camera index 0 through the
platform-native AVFoundation, Video4Linux, or Media Foundation backend, decodes each frame to
bounded grayscale memory, and searches it for QR symbols. No preview, pixel buffer, decoded QR
text, partial fragment, or response is written to disk or logs.

Only values with the versioned `age-phone:qr1:` prefix enter the existing strict Rust QR
reassembler. Unrelated and standalone malformed symbols do not alter active assembly. Conflicting
fragments, clock rollback, digest failure, or poisoned state terminate the scan. A stale incomplete
transfer may be explicitly reset after its fixed 30-second assembly window so the phone can restart
its animation without extending the overall five-minute operation deadline.

Completed response bytes remain zeroizing until the pairing or unwrap verifier consumes them.
Camera failure, unsupported or oversized frames, worker failure, cancellation, and timeout fail
closed. The camera transport grants no trust: pairing signatures, transcript confirmation, unwrap
bindings, expiry, AEAD, and durable replay consumption remain unchanged.

The `pair`, diagnostic `unwrap`, and standard age `identity-v1` paths all use this scanner. Their
external response-file and Base64-paste interfaces are removed.

## Consequences

- Pairing and one-shot unwrap no longer require an out-of-process capture helper or clipboard.
- Camera-driver behavior is isolated from protocol parsing and cannot bypass authentication.
- Camera index selection, live preview, signed-binary permission strings, and physical-device
  interoperability remain packaging and usability work.

## Validation

Pure Rust tests cover reordered frames, duplicates, unrelated QR symbols, malformed frames,
wrong-transfer frames, stale-transfer restart, cancellation, timeout, and monotonic-clock rollback.
Workspace compilation validates the native macOS backend. Opening a real camera is deliberately
left to an explicit permission-bearing device test.
