# Protocol v2 consolidated specification candidate

Status: review draft, 2026-10-30. Source baseline:
`69b3cdfa006d8bbe4f1154ec5874ea954f2ae717`. This consolidates the current implementation;
it does not declare a protocol freeze, change runtime behavior or certify all implementations.
[Freeze preparation](protocol-v2-freeze-preparation.md) records accepted D1–D5 decisions, evidence and outstanding acceptance.
[Protocol policy](protocol.md#prerelease-compatibility-policy) governs prerelease updates.

Read this document for the current byte layouts; use historical ADRs for rationale. A discrepancy
between this draft, source and vectors must be resolved explicitly before freeze, not hidden by
changing a vector. Public fixture scalars and file keys are synthetic test inputs only.

## Conventions and source map

`||` means byte concatenation; quoted strings are exact UTF-8/ASCII bytes; `0x00` is one zero byte.
`CBOR(x)` is the canonical encoding described below, `B[n]` a byte string of exactly n bytes,
and `T[n]` UTF-8 text of at most n encoded bytes. `H` is SHA-256. All identifiers are B[16],
all protocol nonces/digests B[32], file keys B[16]. Generate identifiers/nonces with a CSPRNG;
use fresh ephemeral P-256 scalars for each encryption/session. Fixed inputs are for vectors only.

| Surface | Owning source at baseline |
| --- | --- |
| Signed messages, domains, session response | [Rust protocol](../crates/core/src/protocol/mod.rs) |
| Phone recipient v1/v2 and selection | [Rust recipient](../crates/core/src/recipient/mod.rs) |
| Native tag HPKE | [Rust tag](../crates/core/src/recipient/tag.rs) |
| Public stub and confirmation | [Desktop pairing](../crates/desktop/src/pairing.rs) |
| age input selection | [Desktop age adapter](../crates/desktop/src/age_identity.rs) |
| Durable response/request semantics | [Rust replay](../crates/core/src/protocol/replay.rs) |
| Android envelope implementation | [Kotlin envelope](../plugins/tauri-plugin-phone-identity/android/src/main/java/io/github/biulight/phone_identity/OfflineEnvelopeCrypto.kt) |
| iOS envelope implementation | [Swift envelope](../plugins/tauri-plugin-phone-identity/ios/Sources/OfflineEnvelopeCrypto.swift) |

## Key roles and encoding

Four long-term public keys in a verified pairing must be pairwise distinct:
phone identity (ECDH), phone signing (ECDSA), desktop signing (ECDSA), desktop selection (ECDH).
The phone identity private key never leaves hardware and each use requires fresh native verification.
The selection private key opens only the identity selector; it cannot unwrap the age file key.
One-time desktop and phone response keys are separate ECDH roles, not long-term identity keys.

P-256 protocol keys are valid canonical compressed SEC1 points, 33 bytes with prefix 0x02/0x03.
ECDH produces the 32-byte big-endian affine x-coordinate, retaining leading zeros.
Signatures are ECDSA-P256-SHA256 in fixed 64-byte `r || s` form, not ASN.1 DER. Reject invalid
signatures and high-S forms; generators normalize S to the low half of the group order.
The standard tag stanza uses a 65-byte uncompressed point instead, as specified below.

## Canonical signed messages

Only fixed, definite-length arrays, unsigned integers, byte strings, UTF-8 strings and the specified
null are accepted. Use shortest integer/length encodings. Reject extra/trailing fields or bytes,
indefinite lengths, wrong CBOR types (including numeric strings), unsupported versions/suites/types
and noncanonical re-encodings. JSON is a fixture container, never a signed representation.

Every signed envelope is the two-element array:

```text
[ payload_bytes : bstr, signature : B[64] ]
```

`payload_bytes` contains one complete canonical array below. Header order is **version, message
type, algorithm suite**, not version/suite/type. Version is 2 and suite is 1 in all four messages.

| Payload | Exact ordered array |
| --- | --- |
| Offer (8 fields) | `[2, 1, 1, desktop_id, desktop_label, desktop_signing_public_key, desktop_selection_public_key, offer_nonce]` |
| Pairing response (8 fields) | `[2, 2, 1, identity_id, recipient, phone_signing_public_key, offer_digest, pairing_response_nonce]` |
| Unwrap request (11 fields) | `[2, 3, 1, request_id, identity_id, desktop_id, desktop_session_public_key, stanza, request_nonce, expires_at_unix, caller_hint]` |
| Unwrap response (10 fields) | `[2, 4, 1, request_id, request_digest, identity_id, desktop_id, phone_session_public_key, response_nonce, encrypted_file_key]` |

`desktop_label` is T[64]. `recipient` is T[160] and must parse as the canonical single-phone
recipient (`0x01 || phone_identity_public_key`), even inside a protocol v2 pairing. It is not the
paired v2 recipient exported for normal encryption. `caller_hint` is null or T[64]; empty text and
null have different signed bytes. Labels/hints are untrusted presentation only; no normalization
or authorization semantics are implied.

`stanza = [tag : T[64], args : array of 1 or 2 T[128], body : B[32]]`. The supported tag further
restricts argument count, encoding and lengths. Unknown stanzas inside a signed request are rejected.
This differs from ignoring unrelated stanza tags at the standard age `identity-v1` input boundary.
`expires_at_unix` is unsigned integer Unix seconds. Accepted decision D3 limits the target domain
to `[0, 2^63-1]`; the baseline implementations do not yet enforce identical range/arithmetic rules.
See the accepted target requirements below rather than assuming the entire UInt64 domain is portable.
`encrypted_file_key` is B[32], ciphertext followed by the 16-byte AEAD tag.

## Signature and digest domains

For every domain below, `domain_input = domain || 0x00 || bytes`. Sign ECDSA over
`H(domain_input)`; SHA256-with-ECDSA APIs hash the domain input themselves, so do not hash twice.

| Purpose | Exact domain | Bytes |
| --- | --- | --- |
| Offer signature | `age-plugin-phone/pairing-offer-signature/v2` | Offer payload |
| Pairing response signature | `age-plugin-phone/pairing-response-signature/v2` | Pairing response payload |
| Request signature | `age-plugin-phone/unwrap-request-signature/v2` | Request payload |
| Response signature | `age-plugin-phone/unwrap-response-signature/v2` | Response payload |
| Offer digest | `age-plugin-phone/pairing-offer-digest/v2` | Complete signed offer |
| Request digest | `age-plugin-phone/request-digest/v2` | Complete signed request |
| Transcript fingerprint | `age-plugin-phone/pairing-fingerprint/v2` | Complete signed offer followed by complete signed pairing response |
| Desktop replay digest | `age-plugin-phone/unwrap-response-signature/v2` | Complete signed response, hashed rather than signed again |

The final four rows produce H(domain_input). Fingerprints are 32 bytes; comparing a short prefix
is insufficient. Verify both signatures, offer-digest binding and all four key roles before either
endpoint confirms/persists the peer. Both endpoints require exact full-fingerprint confirmation.
Cancellation, mismatch, duplicate confirmation, lifecycle loss or failed persistence terminates
the attempt; retries require a fresh exchange. The fingerprint helper alone is not verification.

## Request-bound encrypted response

The phone verifies the request under the stored paired desktop signing key, validates scope,
stanza and expiry, then durably consumes the request before identity authorization. The phone
wraps only the selected file key after fresh native verification:

```text
shared = ECDH(fresh_phone_session_private, desktop_session_public)
salt = request_digest || response_nonce
key = HKDF-SHA256(ikm=shared, salt=salt,
                  info="age-plugin-phone/session-response/p256/v2", length=32)
aad = CBOR([2, 4, 1, request_id, request_digest, identity_id, desktop_id,
            phone_session_public_key, response_nonce])
encrypted_file_key = ChaCha20-Poly1305(key, nonce=12 zero bytes, aad, file_key)
```

The AAD array has 9 fields and omits ciphertext. The response has no separate expiry field or echoed
desktop session key: the signed request digest commits to the request and its session key, while
ECDH requires the corresponding desktop private key. The fresh response nonce is not expected to
equal the request nonce; it is authenticated by the signature, KDF and AAD.

The desktop checks the pending request's expiry, request ID/digest, paired desktop and identity,
paired phone signature, phone session point and AEAD authentication. It durably consumes the signed
response digest before returning the 16-byte file key. Failure returns no key. Session secrets and
transient keys are cleared; none may be logged or returned through WebView/Tauri presentation data.

## Recipient and stanza formats

Use canonical lowercase Bech32 (not Bech32m) for recipients. The payloads below are raw Bech32 data
bytes before base32 conversion. Stanza arguments use standard unpadded Base64, not base64url; reject
padding and noncanonical encodings. Body bytes are raw ciphertext, not Base64 inside the CBOR stanza.

| Format | Recipient HRP and payload | Stanza tag and arguments | Body |
| --- | --- | --- | --- |
| Single-phone v1 | `age1phone`: `0x01 || P` (34 bytes) | `phone-p256-v1`: `[b64(E)]` | 32 bytes |
| Paired phone v2 | `age1phone`: `0x02 || P || D || identity_id` (83 bytes) | `phone-p256-v2`: `[b64(E), b64(selector)]` | 32 bytes |
| Native tag | `age1tag`: `P` (33 bytes, no phone payload-version byte) | `p256tag`: `[b64(tag4), b64(enc)]` | 32 bytes |

P is the compressed phone identity key, D the compressed desktop **selection** key, E a fresh
compressed ephemeral key. `selector` is 32 bytes. `enc` is a valid uncompressed P-256 point (65
bytes, prefix 0x04); `tag4` is 4 bytes. Never convert a paired phone recipient into tag by swapping HRP.

For phone v1/v2, `K(shared, salt, info)` denotes HKDF-SHA256 Extract+Expand to 32 bytes;
all AEAD nonces are 12 zero bytes. Fresh ephemeral scalars and domain separation are mandatory.

```text
phone_shared = ECDH(ephemeral_private, P)
v1_key = K(phone_shared, E || P, "age-plugin-phone/recipient/p256/v1")
v1_aad = "phone-p256-v1" || 0x00 || E || P
v1_body = AEAD(v1_key, zero_nonce, v1_aad, file_key)

v2_key = K(phone_shared, E || P, "age-plugin-phone/recipient/p256/v2/file-key")
v2_aad = "phone-p256-v2" || 0x00 || E || P
v2_body = AEAD(v2_key, zero_nonce, v2_aad, file_key)
selection_key = K(ECDH(ephemeral_private, D), E || D,
                  "age-plugin-phone/recipient/p256/v2/selection")
selection_aad = "phone-p256-v2" || 0x00 || "selection" || 0x00 || E || P || D || v2_body
selector = AEAD(selection_key, zero_nonce, selection_aad, identity_id)
```

The phone validates the v2 selector structure but does not use the desktop selection private key.
Desktop selection authenticates the selector and compares its plaintext identity ID before requesting
phone authorization. The same E is used for the two domain-separated v2 ECDH operations.

Native tag uses HPKE base mode: DHKEM(P-256, HKDF-SHA256) 0x0010, KDF 0x0001, AEAD
ChaCha20-Poly1305 0x0003; info is `age-encryption.org/p256tag`, AAD is empty and sequence is zero.
The KEM context is `enc || uncompressed(P)`. RFC 9180 labeled Extract/Expand uses KEM suite bytes
`KEM || 0x0010`, HPKE suite bytes `HPKE || 0x0010 || 0x0001 || 0x0003` and label prefix `HPKE-v1`;
integers in suite IDs/lengths are big-endian. Base mode has no PSK or PSK ID. The key and base nonce
come from the HPKE schedule; **the nonce is not the phone envelope's all-zero nonce**.

```text
tag4 = HKDF-Extract-SHA256(salt="age-encryption.org/p256tag",
                          ikm=enc || H(P)[0:4])[0:4]
```

A tag match is a public prefilter, not authentication; HPKE Open must succeed after fresh phone
verification. The existing [ADR 0026](adr/0026-native-tagged-recipients.md) pins the C2SP and RFC
references; this consolidation does not change that standard profile.

## Selection and age boundary

Validate all supported stanza structures before opening private state. Ignore unknown age stanza
tags. For each tag stanza, check all configured phone keys: a single stanza matching multiple
distinct keys is ambiguous and fails before private lookup, even if an earlier stanza matched.
Different stanzas targeting different keys are not themselves ambiguous. Select the first matching
tag stanza and first input pairing for that key. If no tag matches, discard tag candidates and
apply phone selection. If any remaining candidate is legacy v1, require exactly one configured
identity and exactly one remaining stanza; mixed phone v1/v2 candidates are rejected. Otherwise
choose the first authenticated v2 match in identity order, then stanza order.

A valid v2 nonmatch with available state is an ordinary identity miss, allowing age to continue to
the next identity. Malformed supported input is terminal. In the v2 search, failures opening other
identities are collected: a valid match among successfully opened identities can still be selected;
if no match exists, collected state errors are returned rather than an ordinary miss. After a pairing is selected,
cancellation, cryptographic/state/transport failure never tries another pairing or recipient mode.
Each successful unwrap requires its own fresh request and native phone verification.

## Public identity stub

The stub is canonical CBOR, with **no message-type field**:

```text
[2, 1, desktop_id, identity_id, recipient, desktop_signing_public_key,
 desktop_selection_public_key, phone_signing_public_key, offer_digest,
 transcript_fingerprint, "phone"]
```

This is 11 fields: stub version 2, suite 1, the same identifier/key/digest widths as above, and the
single-phone recipient carrying P. Reject wrong version/suite/plugin, noncanonical/trailing bytes,
invalid points and reused long-term roles. Standard identity text is uppercase Bech32 with HRP
`age-plugin-phone-` and the CBOR bytes as data. A public stub contains no secret or filesystem path;
it is not itself a signed envelope or independent proof that a peer was confirmed. Private locator
and hardware state must match it. Export derives the paired v2 or tag recipient from its public fields.

## Time, replay and terminal behavior

For ordinary representable clock values, the current acceptance window is inclusive:
`now <= expires_at_unix <= now + 300 seconds`. Reject later/expired requests. The response inherits
the request's expiry. The D3 working implementation additionally enforces `[0, 2^63-1]` for both
values, then checks ordering and a difference at most 300. Creation rejects overflow; see the
implementation status below. These changes do not retroactively describe the historical baseline.

Scope consumption by endpoint role, desktop ID and phone identity ID. A repeated request ID **or**
request nonce is replay. Desktop consumption tracks the complete signed-response digest. Retain
entries while expiry is greater than or equal to now; reject clock rollback against the durable
high-water mark. Bounded capacity exhaustion and missing/corrupt/mismatched/unavailable/uncertain
state fail closed. Cancellation, timeout, authentication failure, backgrounding, disconnection and
response loss never undo consumption. A new attempt creates a fresh signed request; routes are
selected before signing and may not silently switch or retry within an attempt.

Replay file layouts/capacities, native persistence mechanics and transport timeouts are separate
implementation contracts. Preserve the accepted [desktop snapshot-freshness limitation](threat-model.md#desktop-replay-persistence-and-restore-boundary).
The [vector catalog](test-vectors/README.md) distinguishes byte-level fixtures from persistence,
hardware and lifecycle evidence. Error categories must fail safely; matching cross-platform error
strings or the order of diagnostics for multiply-invalid inputs is not a freeze commitment.

## Accepted requirements and implementation status

The source-baseline description above remains auditable as current behavior. The project owner
accepted D1–D5 on 2026-10-30; the following requirements guide subsequent implementation and do not
silently redefine what `69b3cdf` already enforces. Exact criteria and work order are in the
[decision record](protocol-v2-freeze-preparation.md#accepted-decisions-and-acceptance-criteria).

| Decision | Accepted requirement | Remaining acceptance |
| --- | --- | --- |
| D1 | Freeze signed messages, selected recipient/stanza semantics, public stub and safety invariants; version storage/framing/product contracts separately | Select final source/specification/vector revisions after implementation and review; no freeze is declared |
| D2 | Retain restricted legacy phone v1 stanza support and the distinct single-phone public-key encoding in pairing/stubs | Preserve single-candidate success, mixed/ambiguous rejection and protocol-v1/state rejection |
| D3 | Both `now` and expiry are CBOR-compatible nonnegative seconds at most `2^63-1`; check ranges, then `expires >= now`, then `expires - now <= 300`; generation uses checked addition and rejects out-of-range results | Implemented with shared boundary cases; bind local results to the final candidate and independent review |
| D3 | Complete signed envelopes are at most 65,536 bytes, checked before payload decode/copy; preserve exact schema bounds and bounded nesting/allocation | Direct decoder limits implemented and tested; storage limits remain separate; final candidate review pending |
| D4 | Suite 1; paired phone v2, explicit tag and restricted legacy v1; no new negotiation. Incompatible semantics require a new version | Verify the capability set, unknown-input rejection and no fallback; future stanza extensions identify minimum versions and use a new version absent separately accepted safe capability identification |
| D5 | Keep all seven fixtures unchanged; add full phone-v2 envelope and public-stub expectations, shared rejection cases and full Swift pairing/envelope coverage | Exercise production-used logic without software-key fallback; test stateful replay/cancellation/persistence separately |

For D3, a size-eligible message is not automatically valid. Reject numeric strings, negative and
out-of-range times, malformed canonical encoding, oversized declared fields, extra/trailing bytes
and malicious nesting. Native storage may need larger array limits than protocol parsing; do not
apply the protocol parser's limits indiscriminately to persisted replay entries. Bounds are safety
requirements independent of transport authentication.

For D4, unknown age tags are ignored only at the standard `identity-v1` boundary; unknown types
inside a signed request fail closed. Historical protocol-v2 apps need not support the frozen
capability set. For D5, exact signed fixture bytes must verify, but randomized hardware signatures
need not reproduce the same signature bytes. New test seams must not duplicate production crypto.
