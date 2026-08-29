# Independent cryptographic and implementation review — 2026-08-29

## Review statement

An independent source review was performed against immutable Git commit
`130538fa4a6f0fb24f32ab3ff698add05d9b18f2`. The review covered the experimental version 2
protocol and the implementation map in [`security-review-package.md`](security-review-package.md).
The review found one low-severity strict-decoding defect. The defect is resolved in the accompanying
change and has dedicated regression tests. No finding remains open that affects key custody,
authorization freshness, message binding, replay consumption, strict parsing, or transport
independence.

This is a source and portable-test review, not a certification or production-readiness statement.
The reviewed protocol remains experimental and unfrozen. Native Windows execution, physical
StrongBox behavior, signed-package provenance, and the remaining physical/interoperability matrix
were not re-run by this reviewer and remain separate Alpha gates.

## Scope and method

- Baseline: commit `130538fa4a6f0fb24f32ab3ff698add05d9b18f2` on 2026-08-29.
- Resolution: the accompanying working-tree change; its final commit identifier is to be recorded
  in the review package when committed.
- Environment: macOS Darwin 25.5.0 arm64; Rust 1.96.0; Cargo 1.96.0; Azul Zulu JDK 17.0.20.1;
  Gradle wrapper 8.14.3; Bun 1.4.0.
- Design reviewed: architecture, protocol, threat model, ADRs 0001–0017, committed public vectors,
  Alpha/release evidence boundaries, and the security-review package.
- Rust reviewed: recipient construction, canonical protocol, replay persistence, QR and stream
  framing, age recipient/identity state machines, pairing/unwrap state, ADB orchestration, Windows
  CNG, Windows private storage, locator handling, and native camera boundary.
- Android reviewed: tagged-recipient and envelope cryptography, StrongBox key policy, exact
  `BiometricPrompt.CryptoObject(KeyAgreement)` lifecycle, pairing/replay storage, confirmation,
  QR/stream controllers, revocation/deletion journals, Tauri presentation boundary, and tests.
- Methods: manual data-flow and state-machine tracing, independent reconstruction of signature,
  HKDF, AEAD, transcript and selector coverage, negative-path inspection, RustSec dependency scan,
  cross-language vector review, and portable regression execution.

Excluded runtime evidence:

- Microsoft Platform Crypto Provider, TPM 2.0 and Windows ACL/FFI tests could not execute on macOS.
- No physical biometric, StrongBox invalidation, Android lifecycle, wrong-phone, injected-response,
  camera, ADB cable, or signed-package test was repeated.
- No release artifact was produced, so artifact SHA-256 values are not part of this source review.

## Findings and closure

### ISR-001 — Low — Android accepted text values in integer-only CBOR header/state fields

Affected locations:

- `OfflineEnvelopeCrypto.header`
- `PairingStateStore.decode`
- `PhoneIdentityKeyStore.decodeState`

The Android implementation used Jackson `JsonNode.asInt`, which coerces textual values such as
`"2"` into integers. A canonically encoded CBOR message or state record could therefore use text
for an integer-only version, message type, suite, or journal phase. Rust rejected the same values.
This violated the fixed-field canonical schema and created a cross-language parser differential.

Exploit preconditions and impact: an attacker needed to supply a newly signed request for the
protocol path, or modify app-private state for the persistence paths. Existing ECDSA, pairing,
expiry, replay, and AEAD checks were not bypassed, and the defect did not directly release a file
key. Severity is Low because the immediate effect was schema-policy bypass and implementation
divergence, not authentication bypass; it nevertheless violated a mandatory fail-closed invariant.

Resolution: every affected field now requires `isIntegralNumber`, exact `Int` conversion, and the
expected value. Regression tests construct canonical CBOR with textual header/state values and
require rejection before request routing or state opening. Android JDK 17 unit tests pass.

Status: **Resolved**.

### ISR-002 — Informational — transitive `lru 0.16.4` RustSec unsoundness warning

`cargo audit` reported RUSTSEC-2026-0253 through `rqrr 0.10.1`. The advisory affects
`LruCache::pop()` when a stored key's `Drop` implementation panics and unwinding is caught. The
current `rqrr` release is the newest available release; in the reviewed code it uses
`LruCache<u8, ColoredRegion>`, never calls the affected `pop()` method, and a `u8` key has no
panicking destructor. The preconditions are therefore unreachable through this dependency path.
Replacing or vendoring the QR decoder solely to silence the warning would enlarge the audited
surface without reducing reachable risk.

Status: **Accepted informational risk**. Reassess when `rqrr` publishes a release using patched
`lru >= 0.18.2`, or immediately if its key type or cache operations change.

## Cryptographic assessment

### P-256 recipient v1

The construction uses a fresh P-256 ephemeral scalar, canonical compressed SEC1 points, the
big-endian 32-byte ECDH x-coordinate, HKDF-SHA256 over both participant public points, a unique v1
domain, and ChaCha20-Poly1305 over the 16-byte age file key. The all-zero AEAD nonce is safe under
the stated construction because each randomly generated ephemeral key derives an independent
wrapping key; deterministic scalar entry points are confined to public vectors and tests. Point,
length, tag, argument, Base64, and recipient encodings are checked before private-key use.

Assessment: no cryptographic finding. V1 remains intentionally anonymous and is safely restricted
to an unambiguous single-identity/single-stanza selection path.

### P-256 recipient v2 and private selector

One fresh ephemeral scalar performs separate ECDH operations with the phone identity and desktop
selection keys. Independent HKDF domains produce the file-key and selector keys. The selector AEAD
binds the version/tag, ephemeral key, phone key, desktop selection key, and complete encrypted
file-key body; authenticated splicing therefore fails. The phone file-key body is independently
bound to its phone identity. Desktop selection recovers only the fixed 16-byte identity identifier
and compares it in constant time.

Assessment: domain separation and binding are adequate for the stated privacy claim. The selector
hides the stable identity identifier from parties lacking the paired desktop selection key; it is
not claimed to hide ciphertext equality, the phone public recipient, or traffic metadata.

### Pairing, request, and response envelope

- Pairing covers distinct desktop signing and selection public keys, desktop ID/label/nonce, phone
  identity/recipient/signing key, offer digest, and response nonce. Proof of possession is followed
  by comparison of a digest over both complete signed messages.
- ECDSA uses P-256/SHA-256, fixed-width P1363 signatures, role/version domains, low-S production,
  and high-S rejection. All long-term key roles are required to be distinct.
- Each request binds both pairing IDs, request ID and nonce, expiry, one-time desktop session key,
  the complete recipient stanza, and the untrusted caller hint. The signed-request digest covers
  the complete canonical envelope.
- Each response binds the pairing IDs, request ID/digest, fresh phone session key and nonce, and
  ciphertext in both AEAD associated data and the phone signature. HKDF salt contains the request
  digest and response nonce under a separate response domain.
- Invalid points are rejected before ECDH. P-256 cofactor one avoids small-subgroup handling.

Assessment: no missing transcript, signature, KDF, or AEAD binding was found. Captured envelopes
cannot be transferred to another pairing or one-time desktop session without failing signature,
binding, or AEAD verification.

## Implementation assessment

### Rust and age state machines

Rust decoders require exact fixed arrays, exact lengths/types, canonical re-encoding and complete
input consumption. File keys, shared secrets and derived keys use zeroizing storage at the return
boundaries. V2 selection occurs before a request is created; v1 refuses ambiguous multi-stanza or
multi-identity inputs. The sole file-key return follows response signature/AEAD verification and a
durable response replay commit. Cancellation closes the one-shot desktop session.

### Replay and persistent storage

Phone requests are consumed after signature/binding/expiry validation and before authorization.
Desktop responses are consumed after signature and AEAD authentication but before returning the
file key. Failed persistence poisons the active guard. Scope, role, capacity, canonical ordering,
duplicate IDs/nonces/digests, expiry, and clock rollback fail closed. The crash asymmetry may deny a
legitimate retry but does not repeat authorization or file-key release.

### Android custody and authorization

The identity ECDH key is generated StrongBox-only, non-exportable, agreement-only,
`BIOMETRIC_STRONG`, auth-per-use, and enrollment-invalidated. The response-signing key is a distinct
StrongBox signing-only key. An unwrap request is durably consumed before creating one new
`KeyAgreement`; `BiometricPrompt` must return that exact object. A recoverable biometric mismatch
keeps only that same prompt/object pending, while cancellation, timeout, lifecycle loss and errors
are terminal. The file key is encrypted and signed below the WebView boundary and transient arrays
are cleared.

### Windows custody and storage

Static review found distinct ECDSA/ECDH Platform Crypto Provider handles, rejection of partial
state, non-export policy checks plus attempted-private-export rejection, canonical public export,
validated ECDH import and explicit raw-secret endianness handling. Private storage checks absolute
paths, protected current-user-only ACLs, owner, file type, reparse points, hard-link count,
zero-share locks, write-through replacement and bounded reads. Runtime validation remains excluded
from this review environment.

### Transports and presentation boundaries

QR and stream framing bound allocation, transfer/session identity, direction and purpose but never
provide peer trust. ADB serials, device state, reverse rules and loopback connections remain
selection/transport hints. Protocol bytes are not passed as ADB arguments. Android raw QR and
stream payloads remain below the WebView, and display labels are treated as untrusted hints.

## Security-claim decision

The source design and reviewed implementation support the stated claim for the Windows 11 x64 TPM
plus Android StrongBox Alpha configuration: copied desktop files alone do not contain a reusable
age identity or TPM private keys; a file key is returned only for one bound request after fresh
phone authorization and durable replay consumption; malformed, replayed, expired, wrong-device,
cancelled and transport-failure paths do not introduce a weaker fallback.

Decision: **claim validated at source-review level, subject to the documented threat model and
excluded native/physical evidence**. This decision does not freeze protocol v2, approve production
secrets, validate non-Windows software desktop-key custody as a production boundary, or close the
remaining signed-package and physical Alpha matrix.

## Verification evidence

The following completed after the resolution:

```console
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bun install --frozen-lockfile
bun run build
./gradlew :tauri-plugin-phone-identity:testDebugUnitTest   # JDK 17
cargo audit
```

Results: Rust formatting and Clippy passed; 71 Rust tests in 20 suites passed; the mobile production
build passed; Android native unit tests passed; RustSec reported no vulnerability finding and 19
allowed warnings, including ISR-002. The review-package physical and native-platform exclusions
remain unchanged.
