# ADR 0006: Native Android QR capture and desktop terminal animation

- Status: experimental, accepted for implementation testing
- Date: 2026-08-25
- Scope: initial pairing-offer capture plumbing (extended by ADR 0008)

## Context

ADR 0005 defines textual framing and bounded assembly, but it deliberately leaves the camera and
renderer outside the framing layer. Android must scan animated frames without routing raw strings or
completed signed bytes through the WebView. The desktop needs a renderer that can exercise the same
framing without creating durable pairing state before that state format is wired into the CLI.

## Decision

### Android capture boundary

The Kotlin plugin owns a full-screen CameraX preview and an ML Kit analyzer configured for QR codes
only. CameraX, including its explicit Camera2 backend, is pinned to 1.5.3 for the current Tauri
Kotlin 1.9 toolchain. The ML Kit 17.3.0 model is bundled in the APK so first use does not depend on a
model download or network access. Camera initialization exceptions fail closed as
`camera_unavailable` instead of escaping through the permission callback.

The controller requests the camera permission through the Tauri native permission API, permits only
one scanner or permission request at a time, and uses the back camera with image-analysis
backpressure. Ordinary QR values are ignored before assembly. Strings beginning with the controlled
transport prefix enter the Kotlin reassembler unchanged and are never logged, persisted, emitted as
events, or returned by a Tauri command.

An identical frame may repeat. A valid different transfer is ignored without evicting the active
assembly. A malformed candidate, conflicting fragment, clock rollback, 30-second assembly timeout,
60-second overall scan timeout, explicit cancellation, Activity stop/destruction, or verifier error
closes the controller and clears the reassembler. A retry creates a new controller and assembly.

The current verifier accepts exactly one canonical signed pairing offer. After signature
verification, the completed byte array and verifier copies are cleared. The WebView result contains
only:

- whether the scanner started and the message verified;
- the caller-controlled desktop label as an explicitly untrusted display hint;
- the signed-offer digest rendered as lowercase hexadecimal;
- the number of accepted scan observations; and
- a coarse error category.

It does not yet generate the phone response or enter the full transcript confirmation session.

### Desktop rendering

The desktop library borrows `EncodedQrFrame` values and renders QR modules at medium error
correction without copying or printing their textual representation. A monotonic scheduler advances
every 250 milliseconds, cycles deterministically, and rejects clock rollback.

The `qr-capture-probe` command creates an in-memory disposable P-256 signing key, canonical signed
offer, and fresh QR transfer, then animates three or more frames by using an 80-byte chunk. Its
terminal mode prints only QR modules, frame progress, and the offer digest. Its optional offline HTML
mode embeds independently rendered SVG modules and a fixed local animation timer; it does not embed
frame text or load network resources. The signing key and offer are not persisted, so this command
is a camera/interoperability probe and cannot establish a pairing.

## Consequences

- Raw camera results stay below the presentation-only WebView boundary.
- The bundled detector increases APK size but keeps offline first-use behavior deterministic.
- A malicious code can deny service or terminate a scan, but cannot make partial bytes reach the
  protocol parser.
- Terminal QR readability still depends on font geometry, contrast, window size, and physical
  camera placement.
- Phone response rendering, full transcript comparison, and durable desktop public pairing state
  are implemented by ADR 0008.

## Validation

Unit tests cover desktop rendering/scheduling and Android unrelated-code handling, repeated and
out-of-order frames, mixed transfers, timeout, cancellation, malformed candidates, verifier failure,
and completed-buffer clearing.

On 2026-08-25, the prototype was device-validated on a Samsung `SM-F9660` running Android 16. The
system permission prompt granted camera access, explicit cancellation returned `user_cancelled`, and
the overall deadline returned `scan_timeout`. A three-frame offline SVG animation was then captured
in eight observations. The phone returned `messageVerified: true`, the expected untrusted label, the
exact desktop offer digest, and `errorCategory: null`. CameraService reported no active camera client
after completion. App-PID-scoped scans found no raw frame prefix, protocol material, sensitive data,
or post-fix crash marker; the Doctor directory remained absent.
