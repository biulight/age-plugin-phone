# Public protocol and recipient vectors

Inventory date: 2026-10-30. Baseline: `69b3cdfa006d8bbe4f1154ec5874ea954f2ae717`.
The sole source of fixture bytes is [crates/core/test-vectors](../../crates/core/test-vectors).
There are **eleven JSON files: seven original fixtures, one D3 boundary fixture and three D5 additions**. Keep them packaged in core; do not copy JSON into this directory.
The original hashes pin the assessment baseline; the D3/D5 additions identify subsequent conformance evidence.
See the [consolidated specification](../protocol-v2-spec.md) and
[freeze preparation decisions](../protocol-v2-freeze-preparation.md).

All scalars, file keys and ciphertexts in these fixtures are intentionally public synthetic values.
Never provision fixture keys into platform hardware or use fixed ephemeral inputs for real data.
JSON field order/whitespace is not a signed representation: signatures cover the canonical CBOR
payload bytes. The file hashes below pin the entire JSON artifact, including its formatting.

## Coverage and consumers

| Fixture | Expected coverage | Existing consumers | Limit |
| --- | --- | --- | --- |
| [pairing-transcript-v2.json](../../crates/core/test-vectors/pairing-transcript-v2.json) | Complete v2 signed offer/response, offer digest and full fingerprint | Rust protocol pairing_transcript; Kotlin OfflineEnvelopeCryptoTest and pairing confirmation/state tests; Swift production harness | Swift production harness now checks offer verification, response payload/signature and full fingerprint |
| [offline-envelope-v2.json](../../crates/core/test-vectors/offline-envelope-v2.json) | V2 signed request/response, digest and response opening; embedded stanza is phone-p256-v1 | Rust protocol round_trip_and_replay; Kotlin OfflineEnvelopeCryptoTest and state tests; Swift production harness | Not a full phone-p256-v2 stanza envelope despite filename |
| [p256-recipient-v1.json](../../crates/core/test-vectors/p256-recipient-v1.json) | Single-phone recipient, one-argument stanza and file-key unwrap | Rust public_vector; Kotlin TaggedRecipientCryptoTest | Legacy stanza construction, not protocol v1 compatibility |
| [p256-recipient-v2.json](../../crates/core/test-vectors/p256-recipient-v2.json) | 83-byte paired recipient, private selector and file-key body | Rust public_vector_v2; Kotlin TaggedRecipientCryptoTest | No complete signed request/response or public stub in this fixture |
| [p256tag.json](../../crates/core/test-vectors/p256tag.json) | Standard recipient/stanza and HPKE open | Rust p256tag; Kotlin TaggedRecipientCryptoTest; Swift PhoneIdentityTests (including CryptoKit HPKE comparison) | Public-key software fixtures do not prove fresh hardware authorization |
| [p256tag-collision.json](../../crates/core/test-vectors/p256tag-collision.json) | Two recipient keys with the same public tag, only one authenticating the body | Rust p256tag; Kotlin TaggedRecipientCryptoTest; Swift PhoneIdentityTests; desktop selection fixture | Collision proves public tag matching is not authorization |
| [p256tag-envelope-v2.json](../../crates/core/test-vectors/p256tag-envelope-v2.json) | Tag stanza inside v2 signed request/response and replay path | Rust p256tag_replay; Kotlin OfflineEnvelopeCryptoTest; Swift production harness | Swift production harness now verifies requests and compares response payload/AEAD bytes |

Additional D5 consumers:

| Fixture | Expected coverage | Consumers |
| --- | --- | --- |
| [phone-v2-envelope.json](../../crates/core/test-vectors/phone-v2-envelope.json) | Complete paired phone-v2 stanza, private selector, signed request/digest and signed encrypted response/file key | Rust `protocol_conformance`; Kotlin `OfflineEnvelopeCryptoTest`; Swift production conformance harness |
| [public-identity-stub-v2.json](../../crates/core/test-vectors/public-identity-stub-v2.json) | Canonical CBOR, uppercase plugin identity, identity-file text and derived phone/tag recipients, linked to the existing pairing transcript | Desktop `public_stub_vector` example checks its production serializer/parser; independent Python schema/Bech32 checker |
| [protocol-rejections-v2.json](../../crates/core/test-vectors/protocol-rejections-v2.json) | 39 named reject cases: version/suite/type, extra/trailing/nonminimal fields, high-S, reused roles, wrong bindings, malformed supported stanza and response ciphertext tampering | Rust/Kotlin: all 39; Swift: the 18 inbound offer/request cases |

The offline-envelope fixture's v2 refers to the envelope, not its embedded stanza. Rust also has
`v2_two_argument_stanza_round_trips_canonically`, and now consumes the complete
shared phone-v2 envelope fixture as well. The pairing recipient is the single-phone key encoding;
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

## D5 scope and reproduction

The Swift phone receives pairing offers and unwrap requests; it generates pairing responses and
unwrap responses. Its harness compiles the actual production files, checks all fixed signatures,
offer/request digests and full pairing fingerprint, opens legacy/phone-v2/tag stanzas using the
production post-ECDH primitives, and compares generated response payload/ciphertext bytes to all
three envelope fixtures. It does not introduce an unused mobile desktop-response decoder.
Rust/Kotlin check response rejection and opening; Swift checks its outbound construction against
those independently consumed bytes. Hardware wrappers still obtain native identity agreement and
Secure Enclave signatures; no production software-key fallback or cached authorization is added.

Run from the repository root:

```console
cargo test -p age-plugin-phone-core --locked --test protocol_conformance
cargo run --locked -p age-plugin-phone --example public_stub_vector -- crates/core/test-vectors/pairing-transcript-v2.json crates/core/test-vectors/public-identity-stub-v2.json
python3 scripts/check-public-stub-vector.py
python3 scripts/test-ios-protocol-conformance.py
```

The last command requires macOS/CryptoKit. Kotlin's regular plugin unit suite consumes the same
files from core test resources. CI runs the Swift harness and runs both stub checks in the Rust
OS matrix. The Python checker uses only the standard library and independently reconstructs the
specified CBOR/Bech32 and public recipients; it does not call the desktop encoder. Generators
`public_phone_v2_envelope`, `public_protocol_rejections` (core) and `public_stub_vector` (desktop,
with only the pairing input argument) emit deterministic public JSON. Regenerate into temporary
files for comparison; do not overwrite the seven original fixtures.

Rejection cases are re-signed after payload mutation to test semantic rejection independently of
signature corruption. High-S cases use the equivalent malleated signature; trailing-byte cases
retain the original signed message. Rust and Swift/CryptoKit also check mathematical signature
validity for all 39 cases (normalizing only high-S cases), so semantic rejection cannot be credited
to a broken fixture signature. Rust additionally asserts each expected local error category; those
categories are regression evidence, not a cross-language diagnostic contract. The explicit stanza
fields are checked against the signed request, and the envelope recipient is tied to the public
stub's paired recipient. D3 time/size cases remain a separate shared corpus. This is a
finite conformance matrix, not exhaustive malformed-input coverage. Stateful cancellation, replay,
timeout, uncertain persistence and native authorization remain separate acceptance evidence.

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

D5 `phone-v2-envelope.json` SHA-256: `adcc6d11df6dd0912a1e73718c6a9efe3b933ec82fa2b0c4a28700a8f203d343`.

D5 `public-identity-stub-v2.json` SHA-256: `d98dd78d8fcf5c946f8c9f036a5f486ded5258844bfa14df05ef232de8171496`.

D5 `protocol-rejections-v2.json` SHA-256: `61b352d605259bb9194e299348f0b26bd8c8fe275f76c40ad7dabfe1da3104a3`.

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
  the separate production conformance harness supplies pairing/envelope evidence; a build alone does not.

The Rust suite is `cargo test -p age-plugin-phone-core --locked`; external-client tag tests are
ignored unless explicitly invoked with the real client as described in
[tag evidence](../tagged-recipient-evidence.md#reproduction). Native Kotlin/Swift commands and their
historical results are recorded there separately. D5 validation is recorded in the freeze-preparation record.

Existing examples `public_vector`, `public_vector_v2`, `public_tag_vector` and `public_tag_envelope`
provide deterministic generation helpers; they are not instructions to overwrite accepted fixtures.
Pairing and ordinary envelope expected bytes are checked in Rust protocol tests; no dedicated
standalone generator for those two was found in the baseline examples directory.
[Package validation](../../scripts/check-package-layout.py) pins the four original vector hashes and
includes core's test-vectors directory; the three tag hashes above additionally identify the current
inventory. Do not claim the existing script separately pins all seven hashes.

## Remaining acceptance

The D5 fixture set and source-level consumers are implemented. Full Swift durable-store restart
and hardware authorization are not exercised by these static fixtures. Bind source/fixture hashes,
CI and independent increment review to the final candidate, and retain separate stateful/native
acceptance and the breaking-update exercise. No protocol freeze is declared. The seven original
fixture hashes and the D3 corpus remain unchanged.
