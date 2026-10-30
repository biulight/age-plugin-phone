# Public protocol and recipient vectors

Inventory date: 2026-10-30. Baseline: `69b3cdfa006d8bbe4f1154ec5874ea954f2ae717`.
The sole source of fixture bytes is [crates/core/test-vectors](../../crates/core/test-vectors).
There are **seven original JSON files plus one D3 boundary fixture**. Keep them packaged in core; do not copy JSON into this directory.
The original hashes pin the assessment baseline; the additional D3 fixture pins the working change.
See the [consolidated specification](../protocol-v2-spec.md) and
[freeze preparation decisions](../protocol-v2-freeze-preparation.md).

All scalars, file keys and ciphertexts in these fixtures are intentionally public synthetic values.
Never provision fixture keys into platform hardware or use fixed ephemeral inputs for real data.
JSON field order/whitespace is not a signed representation: signatures cover the canonical CBOR
payload bytes. The file hashes below pin the entire JSON artifact, including its formatting.

## Coverage and consumers

| Fixture | Expected coverage | Existing consumers | Limit |
| --- | --- | --- | --- |
| [pairing-transcript-v2.json](../../crates/core/test-vectors/pairing-transcript-v2.json) | Complete v2 signed offer/response, offer digest and full fingerprint | Rust protocol pairing_transcript; Kotlin OfflineEnvelopeCryptoTest and pairing confirmation/state tests | No full Swift shared-transcript test found at baseline |
| [offline-envelope-v2.json](../../crates/core/test-vectors/offline-envelope-v2.json) | V2 signed request/response, digest and response opening; embedded stanza is phone-p256-v1 | Rust protocol round_trip_and_replay; Kotlin OfflineEnvelopeCryptoTest and state tests | Not a full phone-p256-v2 stanza envelope despite filename |
| [p256-recipient-v1.json](../../crates/core/test-vectors/p256-recipient-v1.json) | Single-phone recipient, one-argument stanza and file-key unwrap | Rust public_vector; Kotlin TaggedRecipientCryptoTest | Legacy stanza construction, not protocol v1 compatibility |
| [p256-recipient-v2.json](../../crates/core/test-vectors/p256-recipient-v2.json) | 83-byte paired recipient, private selector and file-key body | Rust public_vector_v2; Kotlin TaggedRecipientCryptoTest | No complete signed request/response or public stub in this fixture |
| [p256tag.json](../../crates/core/test-vectors/p256tag.json) | Standard recipient/stanza and HPKE open | Rust p256tag; Kotlin TaggedRecipientCryptoTest; Swift PhoneIdentityTests (including CryptoKit HPKE comparison) | Public-key software fixtures do not prove fresh hardware authorization |
| [p256tag-collision.json](../../crates/core/test-vectors/p256tag-collision.json) | Two recipient keys with the same public tag, only one authenticating the body | Rust p256tag; Kotlin TaggedRecipientCryptoTest; Swift PhoneIdentityTests; desktop selection fixture | Collision proves public tag matching is not authorization |
| [p256tag-envelope-v2.json](../../crates/core/test-vectors/p256tag-envelope-v2.json) | Tag stanza inside v2 signed request/response and replay path | Rust p256tag_replay; Kotlin OfflineEnvelopeCryptoTest | No full Swift shared-envelope test found at baseline |

The offline-envelope fixture's v2 refers to the envelope, not its embedded stanza. Rust also has
`v2_two_argument_stanza_round_trips_canonically`, but that is an in-code test rather than a complete
shared JSON phone-v2 request/response fixture. The pairing recipient is the single-phone key encoding;
it must not be confused with the paired recipient in `p256-recipient-v2.json`.

## D3 boundary corpus

[protocol-boundaries-v2.json](../../crates/core/test-vectors/protocol-boundaries-v2.json) records
portable time/creation expectations and malformed CBOR inputs. Rust protocol tests, Kotlin
`ProtocolBoundsTest`, Swift `ProtocolBoundsTests` and the
[Swift production request harness](../../scripts/test-ios-protocol-boundaries.py) consume it.
The harness compiles production envelope code with synthetic public metadata; it does not exercise
hardware keys or replace D5 full pairing/response coverage. Run it with
`python3 scripts/test-ios-protocol-boundaries.py` on macOS. Decimal strings in this fixture represent
test integers beyond host-language ranges; they are not allowed on the protocol wire.

## SHA-256 manifest

These digests pin baseline files without requiring a new machine-readable ledger:

| File | SHA-256 |
| --- | --- |
| `pairing-transcript-v2.json` | `baaa4289a6ca0eb7f6c3876ff0a0eb1074cde98eb5b158b2ae870ca9a80e18bd` |
| `offline-envelope-v2.json` | `5e1cca6da4f06ce1f1c0e3f19b42908871a3710e84fee6ff38af41e9da90699b` |
| `p256-recipient-v1.json` | `6028deb7ae9122407214d1e8d6c3bdeb8d53c33f85340c499568ac1ac969d1e6` |
| `p256-recipient-v2.json` | `3765db88b82b8f3ec9710a22090f09826502602d2be90611cbbadbc85ad3c48c` |
| `p256tag.json` | `d298ccda3620109a1f593af956910ef96bdbdbd848e014ce6694a09d25ea7b09` |
| `p256tag-collision.json` | `9dad2c42a5e26819a7ef8f7a935f95fd6a07f2b7d9b3099157bb9db34d2b3e62` |
| `p256tag-envelope-v2.json` | `832e81cece94cd848d4350ff2af8a95947a006ba235e6e9fec8d502e88432f04` |

Additional D3 fixture SHA-256: `09475ec03003ab22653596ad279027d458e2644a3d299f34541b079f2c1ad1aa`.

## Reproduction and packaging

Source consumers:

- [Rust protocol tests](../../crates/core/src/protocol/mod.rs),
  [recipient v1](../../crates/core/tests/public_vector.rs),
  [recipient v2](../../crates/core/tests/public_vector_v2.rs),
  [tag tests](../../crates/core/tests/p256tag.rs) and
  [tag envelope/replay tests](../../crates/core/tests/p256tag_replay.rs).
- [Kotlin envelope tests](../../plugins/tauri-plugin-phone-identity/android/src/test/java/io/github/biulight/phone_identity/OfflineEnvelopeCryptoTest.kt)
  and [recipient tests](../../plugins/tauri-plugin-phone-identity/android/src/test/java/io/github/biulight/phone_identity/TaggedRecipientCryptoTest.kt).
  Gradle maps core's vector directory into test resources and instrumentation assets.
- [Swift core tests](../../plugins/tauri-plugin-phone-identity/ios/Core/Tests/PhoneIdentityCoreTests/PhoneIdentityTests.swift)
  load the tag and collision files. The production Swift envelope lives outside the Core test module;
  a successful iOS build or Core test suite does not establish complete shared-envelope coverage.

The Rust suite is `cargo test -p age-plugin-phone-core --locked`; external-client tag tests are
ignored unless explicitly invoked with the real client as described in
[tag evidence](../tagged-recipient-evidence.md#reproduction). Native Kotlin/Swift commands and their
historical results are recorded there separately. These commands were not rerun for this catalog.

Existing examples `public_vector`, `public_vector_v2`, `public_tag_vector` and `public_tag_envelope`
provide deterministic generation helpers; they are not instructions to overwrite accepted fixtures.
Pairing and ordinary envelope expected bytes are checked in Rust protocol tests; no dedicated
standalone generator for those two was found in the baseline examples directory.
[Package validation](../../scripts/check-package-layout.py) pins the four original vector hashes and
includes core's test-vectors directory; the three tag hashes above additionally identify the current
inventory. Do not claim the existing script separately pins all seven hashes.

## Missing conformance evidence

- A complete shared signed request/response fixture containing `phone-p256-v2`, including the
  selector, response opening and expected digests.
- Full Swift pairing and envelope verification against the same committed public fixtures.
- A dedicated public-stub canonical CBOR/text vector linked to the pairing transcript. The
  [acceptance public stub](../../scripts/fixtures/acceptance-public-stub.txt) is supporting test data,
  not a replacement for a shared conformance vector with serialization expectations.
- A cross-language negative-case matrix: unsupported version/suite/type, extra/trailing fields,
  non-minimal CBOR, high-S signatures, wrong roles/bindings, malformed supported stanzas, expiry
  extremes and response tampering. Existing tests and fixture mutation lists are partial evidence,
  not one exhaustive corpus. Durable replay and cancellation need stateful tests beyond static JSON.

D5's required set is now accepted in the preparation record; generating the additional fixtures and
closing their implementation coverage remain outstanding. Retain these seven baseline files unchanged.
The D3 corpus is additive; all seven original fixture hashes are retained.
