# Protocol v2 freeze decision and preparation record

**Frozen on 2026-11-07.** Protocol v2, suite 1, takes effect at source
`41dd48d79bd7497f72ac1e7e3d63ffe97d4462d1`. The normative bytes are identified by the
specification and eleven fixture hashes below. The compatibility commitment begins at this
baseline. Published Alpha and Beta packages retain their original limited-testing scope.

The [O1 implementation follow-up](independent-protocol-v2-review-2026-10-31.md#o1-implementation-follow-up--2026-11-01)
adds a checked iOS clock adapter in a successor implementation change based on `776a38f`.
O1 source remediation is independently closed at `431cf9f`; the
[successor inventory](protocol-v2-candidate-review-2026-10-31.md#successor-candidate--2026-11-02)
binds `41dd48d` to identical runtime/test bytes, unchanged specification/vector inputs and successful
exact-source CI. The original `799b36f` review/CI remains historical evidence for its exact bytes.

## Freeze assessment — 2026-11-07

**G5 accepted.** Freeze the signed pairing and unwrap messages, suite-1 cryptographic and
selection rules, supported recipient/stanza encodings, public identity stub, and rejection
semantics specified in the [normative specification](protocol-v2-spec.md). An incompatible
change requires a distinct version and transition policy. Private storage layouts, transport
framing/discovery, CLI, packaging and release certification are outside the wire commitment.

| Gate | Assessment |
| --- | --- |
| G1 — independent review | Accept the recorded R1–R5 review at `799b36f` and O1 closure at `431cf9f` for their examined source scopes. Runtime and test sources at the pinned successor match the O1 revision. |
| G2 — specification and fixtures | Source/fixture agreement verified for the D1–D5 candidate described below. Accept the exact specification and fixture bytes below as normative. |
| G3a — Android storage | Complete for the recorded scope. Credit the 93 JVM tests and [three physical storage tests](protocol-v2-g3-acceptance-plan.md#physical-android-storage-result--2026-11-07) on Android 16 (SM-F9660). The installed APK hash matched the clean candidate build. |
| G3b–d — native lifecycle and binding | [Android owner session](protocol-v2-g3-acceptance-plan.md#android-native-results--2026-11-07) accepted on the selected package/device. Cancellation and foreground loss returned zero output; fresh verification recovered the expected sample. The [iPhone owner session](protocol-v2-g3-acceptance-plan.md#iphone-native-results--2026-11-07) passed cancellation, both unexpired replays after a verified restart and fresh recovery. Accept G3 for the bound devices, packages and scopes. |
| G4 — breaking update | Accepted for the Alpha 5 → `41dd48d` Windows/Android transition using USB pairing and Wi-Fi unwrap. All six cases and both independent recovery checks passed. [Upgrade evidence](evidence/protocol-v2-g4-2026-11-07/android-upgrade-session.json). |

**G2 binding.** The candidate tree is `4fb7cea34169780fe31dff1dbced57317ee55330`. The committed
review draft has SHA-256 `21f644152ccea6132825c0fb80908dc086a8ff48f089e85010809e67f81e9357`.
The [G2 specification text](protocol-v2-spec.md) has SHA-256
`061e13025115bd22c1110fa37b445c88e5a360b79235b1f792893c3a9b75ee8d` (Git blob
`35f738276fc7c02875e60f93012494571830dd34`). It replaces historical implementation status
with the successor's D3 rules and names the existing phone stanza AEAD explicitly.
All 11 files in the [vector manifest](protocol-v2-candidate-review-2026-10-31.md#public-vector-byte-manifest)
matched their SHA-256 values in both the candidate tree and this checkout. The frozen D3 rules
check the complete
65,536-byte envelope bound before decoding or copying the payload, validate both times in
`[0, 2^63−1]`, require an ordered difference of at most 300 seconds, and reject creation overflow.

Suite 1 includes the four fixed signed messages, public stub, paired phone v2 selection, explicit
`p256tag` and restricted legacy v1 stanzas. Desktop selection checks all public tag matches for
ambiguity. If no tag matches it discards those candidates. Legacy then requires one identity and
one remaining stanza. After selection, a failure is terminal. Unknown age tags are ignored at the
age input boundary and unsupported signed inputs are rejected. Private storage layouts, framing,
discovery and product/platform support have separate contracts under [D1](#accepted-freeze-scope).
The Rust conformance tests passed both cases, including the signed rejection corpus. The independent
stub checker passed. The Swift production harness passed pairing, all three envelope fixtures and
18 inbound rejection cases. Kotlin evidence is the recorded independent JVM run.

**Evidence provenance.** The committed delta from `41dd48d` through assessment revision
`21104ed3c276ff47484d1091d883eea045226162` contains documentation, CI configuration and
the iOS probe with its tests. It has no product implementation or vector delta. Candidate CI
was rechecked on 2026-11-07: [run 41323830238](https://github.com/biulight/age-plugin-phone/actions/runs/41323830238)
reported the exact successor SHA and 11 successful jobs out of 11.
The [macOS reopen observation](protocol-v2-g3-acceptance-plan.md#macos-desktop-replay-store-observation)
remains open for availability: the local contention control preserved consumption and rejected
replay after reopening. Loss of consumption or key output on storage failure would block the affected path.

The iOS device case used the iPhone-only scene overlay. Stock SDK 27 packaging and the corrupt
private-record capacity trap remain platform limitations documented in the [G3 record](protocol-v2-g3-acceptance-plan.md).
Any safety defect found later must be assessed against this baseline. Freeze grants no release
or production-secret approval.

### G4 exercise inputs and results

The selected starting point is `v0.1.0-alpha.5` at `ecde426b055ac75c0791e709b0e4da9cf52698ce`.
The isolated Windows desktop built from it has SHA-256
`a76c585f2ac5b4818a1c147a5b986193bdc6da9b94c282e057c04fa5e806109e`. The two Android debug
packages use the separate, previously absent ID `io.github.biulight.age_plugin_phone.g4test` and
the same development signing certificate. Their SHA-256 values are
`f57420034a6a0252919132699562e74b59a8fcecaf83effba2f2e2874085e653` (Alpha 5) and
`a8294582e2c9cedfe79e35a780b11c0caea1cae1ece4743f702072a149d3d367` (candidate).
The Alpha 5 APK was installed and its on-device hash verified. The owner confirmed the old USB pairing; the Windows stub matched the exported recipient.

An independent age recipient recovered both synthetic inputs before the update. With the desktop
updated first, the Alpha 5 phone rejected a signed `p256tag` request before expiry without
prompting or returning bytes. The old phone still opened its original phone-format ciphertext
with fresh verification. The candidate APK was then installed over the isolated old package.
Its UID and first install time matched. The same tag ciphertext opened with fresh verification
under the existing pairing.

The owner next compared full fingerprints and established a second disposable pairing.
The retained phone-format ciphertext failed with zero output and no prompt under the new
pairing. Independent recovery followed by re-encryption produced a ciphertext that passed both
independent recovery and fresh phone verification against the original 96-byte sample. The
original pairing and its replay state were retained. This tests a change in supported capability,
followed separately by replacement of a pairing. It covers neither a downgrade nor a wire-v1 import.

The [six-case report](evidence/protocol-v2-g4-2026-11-07/android-upgrade-session.json) has
SHA-256 `7ca3903e314e0ed2dd54c7fcbe1023eb5e02c75b5127ee9c0f4caea750f2d387`. The device was
an SM-F9660 running Android 16, with Windows TPM pairing, USB fingerprint confirmation and Wi-Fi unwrap.

## Candidate baseline

The current successor is **`41dd48d79bd7497f72ac1e7e3d63ffe97d4462d1`**, with all 11 jobs in
[main CI 41323830238](https://github.com/biulight/age-plugin-phone/actions/runs/41323830238) successful.
Its reviewed runtime/test bytes match `431cf9f`; the assessment above records subsequent native acceptance.

The original **independent-review candidate** was
`799b36f18b89704bca00417b7af3dee6564054d2` (PR #30 merge). The
[candidate review packet](protocol-v2-candidate-review-2026-10-31.md) pins the source tree,
specification input, eleven vector hashes, complete CI and the `0305c0e..799b36f` review scope.
[Main CI 41067845115](https://github.com/biulight/age-plugin-phone/actions/runs/41067845115)
passed all 11 jobs on this exact commit, rechecked on 2026-10-31. The
[independent agent review](independent-protocol-v2-review-2026-10-31.md) has examined R1–R5; G3 and G4 have separate dispositions in the current assessment. This documentation preparation creates no tag or release.

### Historical preparation baseline

`69b3cdfa006d8bbe4f1154ec5874ea954f2ae717` (PR #26 merge) was the original source candidate for
preparation, not an accepted stable baseline. At preparation start, local dev,
origin/dev and origin/main pointed to that commit. The local Xcode project modification and
untracked files are excluded. These documents record preparation subsequent to the source baseline;
a final freeze decision must also identify the accepted specification revision.

- [Main CI 40928488558](https://github.com/biulight/age-plugin-phone/actions/runs/40928488558)
  passed all 11 jobs, including released-client interoperability, on this commit.
- [Documentation 40928488610](https://github.com/biulight/age-plugin-phone/actions/runs/40928488610)
  passed build and both deployments. Neither run adds physical phone acceptance.
- The candidate inherits recorded reviews through the `0305c0e` iOS follow-up;
  [that review](independent-security-review-2026-09-11.md) does not automatically cover later changes.
  The separate [candidate-delta review](independent-protocol-v2-review-2026-10-31.md) now covers R1–R5,
  including desktop continuation and Android pairing-state/Wi-Fi lifecycle changes. This document
  transcribes that result; O1 source remediation was subsequently independently verified at `431cf9f`.
- Beta 1 `c73b289` and Beta 2 `e08d631` both use v2/suite 1; the candidate does not introduce a
  v1-to-v2 upgrade for published Beta users. Product versions and protocol/stanza versions are distinct.

If code or vectors change, select a new candidate SHA and re-evaluate the affected evidence. Do not
silently transfer these CI results, vector hashes or historical hardware passes to a different tree.

## Documents and authority

| Material | Role |
| --- | --- |
| [Consolidated v2 specification](protocol-v2-spec.md) | Current layouts, domains, cryptographic contexts, selection, stub and replay semantics, traced to source |
| [Protocol overview and policy](protocol.md) | Architecture-level flow, compatibility policy and completed freeze gates |
| [Public vector catalog](test-vectors/README.md) | Seven original fixtures plus D3/D5 additions, hashes, consumers, reproduction routes and remaining acceptance |
| [Candidate review packet](protocol-v2-candidate-review-2026-10-31.md) | Immutable review inputs, increment scope and G1–G5 closure criteria; links the separate review result |
| [Independent increment review](independent-protocol-v2-review-2026-10-31.md) | Reviewer provenance, R1–R5 results, O1, executed checks, exclusions and G3/G4 follow-up acceptance |
| ADRs 0001/0002/0010/0012/0014/0026 | Historical rationale and successive amendments; not an instruction to implement obsolete combined key roles or v1 message domains |
| [Threat model](threat-model.md) | Security invariants and accepted exclusions, including desktop snapshot freshness |

The consolidated specification is normative for the named source and vector bytes.
Independent reviews and device sessions retain their documented implementation scopes.

## Accepted freeze scope

D1 defines the scope accepted in the freeze decision above:

| Include in the v2 baseline | Keep separately versioned or outside this freeze |
| --- | --- |
| Signed pairing/unwrap layouts; suites; domain separation; canonical parsing; key roles and bindings | Private hardware metadata, pairing/locator/journal/replay file byte layouts and migration tooling |
| Recipient/stanza formats and selection semantics for the explicitly selected capability set (D2/D4) | CLI/API stability, setup JSON schema, packaging, OS/device support and installation UX |
| Public identity stub schema and its validation/binding semantics | QR framing, common stream envelope and discovery wire formats unless separately accepted |
| Fresh per-operation authorization, durable consumption and terminal-failure requirements | Specific storage capacities, UI deadlines and native implementation details, subject to safety invariants |

Transport exclusion means no wire-stability promise for that framing; it does not exempt a transport
from signature verification, bounded parsing, fresh authorization or replay rules. Private storage
exclusion similarly does not permit state loss, uncertain replay reset or weaker key custody.

## Accepted decisions and acceptance criteria

The project owner accepted the following recommendations on 2026-10-30. Acceptance of policy does
not establish implementation conformance or close the independent review. D3 implementation
was subsequently authorized; its source/test evidence is recorded below.

### D1 — Scope and baseline

Retain `69b3cdf` as the source assessment baseline and the scope above. Runtime sources and all
seven public vectors were unchanged through `fd6fa6c`. D3 was subsequently merged in `40b8fe4`;
D5 was merged in `799b36f`. Its fixtures and minimal Swift test seams now form part of the proposed
independent-review candidate, without replacing the historical assessment or declaring a final frozen baseline.
Do not select today's HEAD as the final frozen baseline merely because CI passed. After D3/D5
implementation and review, select a new immutable source SHA if code or vectors changed, and bind
it to an accepted specification revision and vector inventory.

Acceptance: the final record names source SHA, specification revision, supported capability set,
vector hashes and applicable CI/review evidence. Private storage, framing and product contracts are
explicitly separated. No historical hardware or CI result is silently promoted to a new candidate.

### D2 — Retain restricted legacy stanza support

Retain `phone-p256-v1` for this baseline under the existing selection constraints. After unmatched
tag candidates are removed, legacy v1 requires exactly one configured identity and one remaining
phone stanza; mixed phone v1/v2 candidates are rejected. This does not promise protocol-v1 message
or state compatibility, nor require automatic migration. The `0x01` single-phone recipient encoding
remains necessary in v2 pairing responses and public stubs, independently of legacy stanza support.

Acceptance: retain positive single-identity/single-stanza coverage and rejection of ambiguous or
mixed candidates before phone authorization. Preserve protocol-v1/state rejection and the pairing/
stub key encoding. Any future removal is a separate decision identifying affected ciphertext and
recovery steps; no removal is part of this work.

### D3 — Portable time and parser boundaries

D3 implemented the following rules, subsequently reviewed and bound to the frozen source:

- Encode Unix seconds as a CBOR unsigned integer in `[0, 2^63-1]`. Apply the same valid range to
  verifier time. Reject negative values, numeric strings and values outside that range.
- Validate range, then `expires >= now`, then `expires - now <= 300`. Both endpoints of the
  ordinary 300-second window remain inclusive; avoid overflow-prone `now + 300` in verification.
- Request creation uses checked addition and rejects expiry beyond the accepted range. Do not
  saturate or wrap. Preserve the durable replay high-water mark and ordinary restart semantics.
- Limit each complete signed envelope to 65,536 bytes at the protocol entry before decoding or
  copying its payload. Apply this independently of QR/stream checks. A frame cap alone does not
  protect a directly invoked decoder.
- Preserve exact array/field bounds and canonical encoding. Reject oversized declared lengths,
  extra/trailing data and malicious nesting without unbounded allocation or recursion. Implement
  schema-specific structural checks or bounded parser constraints; no shared generic depth limit
  is claimed to be implemented already.
- Keep persistent-state parsing limits separate. In particular, do not replace iOS storage-specific
  array limits with the protocol parser's default 128-element limit.

Implementation: Rust now checks the portable range and subtracts only after ordering; desktop
request generation rejects overflow rather than saturating. Kotlin uses the same ordered validation
and checked generation, with a bounded canonical CBOR preflight before Jackson allocation. Swift
validates the portable range in routing and verification and applies the explicit envelope cap.
All signed-envelope decoders reject inputs above 65,536 bytes before payload copying. Persistent
storage limits and durable consumption semantics remain separate.

Evidence: `protocol-boundaries-v2.json` supplies shared time/creation and malformed-CBOR cases.
Rust/Kotlin tests also exercise signed requests at the upper bound; the Swift production harness
compiles the actual envelope implementation with public synthetic metadata. Core Swift tests check
creation arithmetic even though Swift does not currently generate unwrap requests. Size-limit tests
distinguish valid outer framing from a valid signed request. This is local source evidence, not
hardware authorization evidence or a completed independent review.

Local D3 validation on 2026-10-30: Rust workspace tests passed (network/process tests required
an unrestricted test environment); CI-pinned Rust 1.88 Clippy passed with warnings denied; Kotlin
92 unit tests and Swift Core 14 tests passed. The Swift production request harness also passed.
Follow-up D3 tests verify that invalid response clocks do not consume a response, and that Kotlin
rejects invalid time without writing state, preserves maximum-time replay entries across reopen,
and retains the durable high-water mark. Malformed/oversized envelope cases also reach pairing
entry points (and all four Rust signed-message decoders). These targeted regressions passed;
Swift durable-store restart behavior remains source-reviewed here, not newly executed by this harness.
Formatting, diff whitespace, relative documentation links and the seven original vector bytes were
checked. These were the local D3 results; merged D3 subsequently passed all 11 jobs in
[main CI #110](https://github.com/biulight/age-plugin-phone/actions/runs/41032750673) at `40b8fe4`.
That run does not validate the later D5 working change or physical devices.
The host's newer Rust 1.99 Clippy reports an existing `manual_is_variant_and` warning in desktop
`age_identity.rs`; that unrelated source was left unchanged.

Acceptance: shared cases cover negative/text integers, `2^63-1`, `2^63`, `now-1`, `now`, `now+300`,
`now+301` where representable, checked creation near the upper bound, and rejection of invalid
verifier times. Length tests cover zero, limit and limit+1, inflated length declarations, deep
nesting, nonminimal CBOR and trailing bytes. An input at the size limit is only size-eligible, not
necessarily structurally valid. Rejection must occur without a new prompt, state reset or crash;
stateful tests must distinguish pre-consumption rejection from failures after durable consumption.
The same rules must hold at all included Rust/Kotlin/Swift entry points before D3 is closed.

### D4 — Capabilities and extension policy

The baseline capability set is suite 1, current fixed signed-message layouts, default paired phone
v2, explicit `p256tag`, and the restricted legacy stanza path in D2. No negotiation mechanism is
introduced solely for freeze. Historical prereleases sharing v2 are not evidence of this full set.

Incompatible field, algorithm or interpretation changes require a new protocol version. New stanza
capabilities must identify minimum endpoint versions and explicit rejection behavior. Until a safe
capability-identification mechanism is separately accepted, use a new version to distinguish such
extensions rather than treating the same number as proof of support. Unknown age stanza tags remain
ignored at `identity-v1`; unknown signed-request stanza types, protocol fields or suites are rejected.
Unsupported capability never permits downgrade, pairing substitution or within-request transport fallback.

Acceptance: document the capability set and exercise all included stanza paths plus unknown-version,
suite, field and signed-stanza rejection. Retain age-boundary unknown-tag handling and no-fallback
negative tests. An extension must not reinterpret the frozen version's bytes or semantics.

### D5 — Conformance fixtures and implementation coverage

Retain the existing seven public vectors byte-for-byte. Add a complete phone-v2-stanza envelope
fixture with selector, signed request, request digest, response and expected opening result. Add
public-stub canonical CBOR/text expectations linked to a pairing transcript, including derived
phone/tag recipients. Organize shared negative cases with explicit expected outcomes, covering D3
and version/suite/type, reused roles, high-S, wrong bindings and ciphertext tampering.

D5 implementation now adds `phone-v2-envelope.json`, `public-identity-stub-v2.json` and
`protocol-rejections-v2.json`; the [catalog](test-vectors/README.md) records hashes, consumers and
reproduction commands. Rust/Kotlin consume the complete phone-v2 envelope and all 39 rejection
cases. The production Swift harness verifies inbound offers/requests (18 rejection cases), checks
fixed signatures and pairing fingerprints, opens all three stanza modes and compares outbound
pairing/response payloads and response AEAD bytes against the same fixtures. Response input rejection
belongs to the desktop role and runs in Rust/Kotlin; no mobile desktop decoder is added for tests.

Only production-used byte construction/post-ECDH functions are exposed internally for deterministic
fixtures. Secure Enclave signing and native identity agreement stay in their original wrappers;
there is no production software identity or signer injection. Public-stub bytes/text and recipient
exports are checked by the owning desktop code and an independent stdlib CBOR/Bech32 checker.
Fixed signed fixture bytes verify; randomized hardware ECDSA signatures need not reproduce them.

Local D5 validation against `40b8fe4` plus the working change: Rust 1.88 workspace tests and
Clippy with warnings denied passed; Kotlin 93 tests and Swift Core 14 tests passed. The production
Swift boundary/conformance and stream-lifecycle harnesses passed. All three new JSON fixtures were
reproduced byte-for-byte by their generators; the desktop and independent Python stub checks passed.
Workflow lint, four-package archive layout, formatting, links and fixture hashes were checked.
Follow-up checks passed for all 39 mutation signatures in Rust and Swift/CryptoKit and for the
specific Rust rejection categories; signed stanza fields and envelope/stub recipient linkage are
also checked. This strengthens fixture validity evidence without changing production behavior.
D5 subsequently passed all 11 jobs in
[PR CI 41066710639](https://github.com/biulight/age-plugin-phone/actions/runs/41066710639) at `1708706`
and [main CI 41067845115](https://github.com/biulight/age-plugin-phone/actions/runs/41067845115) at
`799b36f`. These runs do not establish physical device acceptance or independent security review.


Acceptance: every required shared fixture has identified consumers and passing expected results;
all newly generated bytes have independently checked expectations rather than self-confirming
round trips alone. Preserve the seven original hashes. Verify stub serialization in its owning
desktop implementation; it is not a new mobile storage contract. Retain separate stateful tests
for cancellation, replay, timeout, persistence failure and restart, plus required native acceptance.
Static JSON and successful iOS compilation do not prove those properties. Existing fixture coverage
and remaining gaps are tracked in the [vector catalog](test-vectors/README.md).

## Implementation order

1. **Decisions recorded:** D1 scope, D2 retention, D3 target limits, D4 capability policy and D5
   required conformance set were accepted before selecting the final baseline.
2. **Establish boundary evidence:** add failing/shared time and parsing cases and complete-message
   expectations to identify actual cross-language differences before changing behavior.
3. **Implement D3 narrowly:** unify time range, safe arithmetic and protocol-entry bounds while
   preserving key custody, native authorization and durable consumption. Validate negative paths.
4. **Complete D5:** add the envelope/stub fixtures and minimal Swift test entry, then run the shared
   conformance matrix and retain existing vectors unchanged.
5. **Independent increment review:** review security-sensitive changes since the historical review
   plus the new D3/D5 changes; resolve findings against the candidate. Implementation self-checks
   are supporting evidence, not independent approval.
6. **Final baseline decision:** bind source/specification/vector revisions and complete the remaining
   protocol gates, including the breaking-update procedure. Decide freeze separately from production
   support and exact-release-package acceptance.

D3 is implemented and D5 now has shared fixtures and role-appropriate production consumers.
Exact-candidate source CI and R1–R5 independent agent review are complete at `799b36f`; O1 source closure and independent JVM execution are recorded at `431cf9f`.
Successor inventory and CI are complete at `41dd48d`; the assessment above records acceptance of G3, G4 and the final baseline. No exhaustive historical Alpha/Beta interoperability matrix is required.

The [G3 acceptance plan](protocol-v2-g3-acceptance-plan.md) provides scoped execution order,
Android storage and native results, iOS restart/replay results and their evidence bindings.
The [macOS desktop replay-store observation](protocol-v2-g3-acceptance-plan.md#macos-desktop-replay-store-observation)
tracks an intermittent reopen failure at `f92e107`. Its CI cause remains unknown. In the local
contention control, the reopened store rejected the previously consumed response as a replay.

## Evidence and remaining work

| Work item | Status and next step |
| --- | --- |
| P0 inventory: source baseline, current schemas, domains, scope and public-vector hashes | Complete as an inventory; D1–D5 policy decisions are accepted, with D3/D5 source evidence now present; final baseline accepted above |
| P0 independent candidate review | R1–R5 review performed; no new defect in the named examined security categories confirmed. O1 source remediation independently closed at `431cf9f`; successor inventory and exact-source CI complete at `41dd48d`; final normative baseline accepted above |
| P1 cross-implementation conformance | Source conformance implemented: complete phone-v2 and stub fixtures, Rust/Kotlin rejection matrix and Swift production pairing/envelope coverage; independent source review recorded; final specification and candidate binding recorded above |
| P1 rejection/lifecycle/persistence evidence | Accepted for the named candidate, physical Android/iPhone sessions, host fault controls and documented reuse in the [G3 disposition](protocol-v2-g3-acceptance-plan.md) |
| P1 breaking-update procedure | Passed for the Alpha 5 → candidate transition described above, including verified independent recovery and fresh use after re-encryption. |
| P2 platform and release acceptance | Retain broader devices, wrong/multiple physical phones, fresh exact-package pairing, QR response replay, roaming, reboot/invalidation/storage/lifecycle rows and distribution readiness in the roadmap |

The [2026-10-29 fixed-pair record](evidence/maintenance-candidate-2026-10-29/README.md) retains
29 scoped accepted cases and 2 exclusions for the published Windows executable plus unpublished
R2 Android APK. The complete Android source inventory was bound to `be46c54`; this preparation does
not rebuild or re-certify those artifacts at `69b3cdf`. The published Beta 2 discovery failure remains
attached to its published bits. Broader coverage alone is not a wire-freeze gate, but any discovered
binding, parsing, authorization or consumption defect must be resolved for the affected path.

Release gates remain in the [roadmap](roadmap.md). The earlier preparation decisions and
the [candidate packet](protocol-v2-candidate-review-2026-10-31.md) retain their historical scope.
