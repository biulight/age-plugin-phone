# ADR 0005: Versioned QR fragmentation and animated-frame assembly

- Status: experimental, accepted for implementation testing
- Date: 2026-08-24
- Scope: textual QR transport framing for canonical protocol messages

## Context

Pairing and unwrap messages are canonical signed bytes, but a scanner returns one text value at a
time and larger messages may require an animated sequence. Framing must tolerate frame repetition
and reordering without letting malformed, conflicting, stale, or mixed transfers produce protocol
input. It must not become an authentication layer or expose raw QR values to the WebView.

## Decision

### Text and binary encoding

Every frame is the ASCII prefix `age-phone:qr1:` followed by canonical unpadded base64url of one
canonical CBOR array:

```text
[
  frame_version,       # uint, exactly 1
  frame_type,          # uint, exactly 1 (message fragment)
  transfer_id,         # bstr, 16 random bytes
  message_digest,      # bstr, 32 bytes
  fragment_index,      # uint, zero based
  fragment_count,      # uint
  total_message_bytes, # uint
  chunk                # non-empty bstr
]
```

Arrays have exactly eight fields, integers use their shortest CBOR representation, byte strings are
definite length, and the entire decoded array must re-encode byte-for-byte. Padding, whitespace,
alternate base64 alphabets, trailing data, unknown fields, versions, or frame types are rejected.

`message_digest` is:

```text
SHA-256("age-plugin-phone/qr-message-digest/v1" || 0x00 || complete_message)
```

The digest detects scan corruption and mixed content. It is not a MAC and grants no trust. The
reassembled canonical protocol message still requires all version, algorithm, binding, expiry,
recipient, and signature verification defined by ADR 0002.

### Limits

- message length: 1 through 65,536 bytes;
- chunk length: 1 through 600 bytes;
- fragment count: 1 through 128;
- encoded frame length: at most 2,048 ASCII characters;
- assembly lifetime: 30 seconds from the first accepted frame.

The default and maximum chunk length are both 600 bytes until camera/device testing justifies a
different QR density. Fragmentation uses a fresh random transfer ID for each animation.

### Assembly state machine

One reassembler owns at most one active transfer. Frames may arrive out of order. An identical
duplicate index is idempotent and does not extend the deadline. A frame with different transfer ID,
digest, count, or total length is rejected without evicting the active transfer.

A conflicting duplicate, clock rollback, timeout, byte-count overflow, invalid chunk layout,
length mismatch, or digest mismatch clears buffered chunks, marks the reassembler poisoned, and
requires an explicit reset. Cancellation also explicitly resets and clears buffered chunks.
Malformed standalone scanner input is rejected before it can alter an active assembly.

At completion, all non-final chunks must have one equal non-zero length, the final chunk must be
non-empty and no larger, concatenated length must match the declared total, and the domain-separated
digest must match. Only then are bytes returned to the native protocol verifier.

### Exposure and cleanup

Encoded-frame and completion debug representations redact content. Kotlin clears decoded chunk
buffers on use, reset, poisoning, and completion; Rust stores chunks and completed messages in
zeroizing buffers. QR strings are never logged and are not Rust, Tauri command, or WebView inputs on
the Android pairing path. A reviewed native scanner controller will feed the Kotlin reassembler and
pass only a completed byte message to the native pairing-confirmation session.

## Consequences

- QR framing is deterministic and independently implemented in Rust and Kotlin.
- Repetition and reordering from animated QR capture are harmless within one bounded transfer.
- A malicious or noisy scanner can cause denial of service but cannot make partial bytes reach the
  protocol parser.
- Frame-level digest validation does not replace protocol authentication or persistent replay
  consumption.
- Camera capture, animation cadence, QR error-correction level, and desktop rendering remain
  separate implementation work.

## Validation

Rust and Kotlin unit tests share a deterministic interoperability anchor and cover reordered and
duplicate frames, transfer mixing, corruption, timeout, clock rollback, non-canonical encoding,
unknown versions/types, conflicting duplicates, poisoning, and explicit reset.

On 2026-08-24, the Android Doctor passed on a Samsung `SM-F9660` (Android 16, API 36): QR
fragmentation, reverse-order duplicate reassembly, corruption rejection, and timeout rejection were
all `true`. Together with the pairing transcript and replay-state checks, all 16 report booleans
were `true` and `errorCategory` was null. The Doctor directory was absent after cleanup, and the
App-PID-scoped sensitive-data and crash log scans were empty.
