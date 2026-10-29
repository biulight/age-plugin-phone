# Protocol v2 freeze preparation record

Date: 2026-10-30. Status: D1–D5 decisions accepted by the project owner; implementation and acceptance remain open; **not frozen**.
Beta remains limited technical testing. The [prerelease compatibility policy](protocol.md#prerelease-compatibility-policy)
permits clearly announced breaking updates before freeze without cross-version interoperability,
automatic migration or downgrade promises. This record does not authorize code changes or publication.

## Candidate baseline

Use `69b3cdfa006d8bbe4f1154ec5874ea954f2ae717` (PR #26 merge) as the **source candidate for
this preparation**, not as an already accepted stable baseline. At preparation start, local dev,
origin/dev and origin/main pointed to that commit. The local Xcode project modification and
untracked files are excluded. These documents record preparation subsequent to the source baseline;
a final freeze decision must also identify the accepted specification revision.

- [Main CI 40928488558](https://github.com/biulight/age-plugin-phone/actions/runs/40928488558)
  passed all 11 jobs, including released-client interoperability, on this commit.
- [Documentation 40928488610](https://github.com/biulight/age-plugin-phone/actions/runs/40928488610)
  passed build and both deployments. Neither run adds physical phone acceptance.
- The candidate inherits recorded reviews through the `0305c0e` iOS follow-up;
  [that review](independent-security-review-2026-09-11.md) does not automatically cover later changes.
  Targeted candidate-delta review remains open, notably desktop identity continuation and Android
  pairing-state/Wi-Fi lifecycle changes. This documentation task is not an independent security review.
- Beta 1 `c73b289` and Beta 2 `e08d631` both use v2/suite 1; the candidate does not introduce a
  v1-to-v2 upgrade for published Beta users. Product versions and protocol/stanza versions are distinct.

If code or vectors change, select a new candidate SHA and re-evaluate the affected evidence. Do not
silently transfer these CI results, vector hashes or historical hardware passes to a different tree.

## Documents and authority

| Material | Role |
| --- | --- |
| [Consolidated v2 specification](protocol-v2-spec.md) | Current layouts, domains, cryptographic contexts, selection, stub and replay semantics, traced to source |
| [Protocol overview and policy](protocol.md) | Architecture-level flow, compatibility policy and remaining freeze gates |
| [Public vector catalog](test-vectors/README.md) | Seven existing fixtures, hashes, consumers, reproduction routes and missing coverage |
| ADRs 0001/0002/0010/0012/0014/0026 | Historical rationale and successive amendments; not an instruction to implement obsolete combined key roles or v1 message domains |
| [Threat model](threat-model.md) | Security invariants and accepted exclusions, including desktop snapshot freshness |

The consolidated specification is the review entry point for current bytes. It does not declare
all implementations conformant. Resolve discrepancies against the named source and vectors before
accepting normative text; do not alter source or fixtures merely to make the documentation agree.

## Accepted freeze scope

The following scope is accepted under D1. Final baseline selection and freeze approval remain open:

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
not establish implementation conformance, close the independent review, or authorize this
documentation task to modify code. D3 specifies target behavior not yet uniformly enforced.

### D1 — Scope and baseline

Retain `69b3cdf` as the source assessment baseline and the scope above. Runtime sources and all
seven public vectors were unchanged through `fd6fa6c`; the later commits record documentation.
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

Accepted target rules, pending implementation and cross-language verification:

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

Evidence: Rust currently uses u64 with saturating lifetime addition; Kotlin accepts nonnegative
Long and uses ordinary addition; Swift uses UInt64 and ordinary addition. Swift CBOR has a default
65,536-byte limit, while Rust/Kotlin envelope entry points need explicit equivalent protection.
QR/stream already use 65,536-byte limits. These are boundary differences, not evidence of a
practical biometric bypass.

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

Run full pairing/envelope fixtures through Swift as well as Rust/Kotlin. The Swift envelope currently
lives outside the Core test module and its generation APIs depend on Secure Enclave keys. Introduce
only the minimal test boundary needed to execute production-used encoding/crypto logic; do not copy
a second implementation or enable a production software-key fallback. Fixed signed fixture bytes
must verify; randomized hardware ECDSA signatures need not equal deterministic fixture signatures.

Acceptance: every required shared fixture has identified consumers and passing expected results;
all newly generated bytes have independently checked expectations rather than self-confirming
round trips alone. Preserve the seven original hashes. Verify stub serialization in its owning
desktop implementation; it is not a new mobile storage contract. Retain separate stateful tests
for cancellation, replay, timeout, persistence failure and restart, plus required native acceptance.
Static JSON and successful iOS compilation do not prove those properties. Existing fixture coverage
and remaining gaps are tracked in the [vector catalog](test-vectors/README.md).

## Implementation order

1. **Decisions recorded:** D1 scope, D2 retention, D3 target limits, D4 capability policy and D5
   required conformance set are accepted. Final baseline selection is still deferred.
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

Steps 2–6 are outstanding. This sequence defines future work; the current authorization remains
documentation-only. No exhaustive historical Alpha/Beta interoperability matrix is required.

## Evidence and remaining work

| Work item | Status and next step |
| --- | --- |
| P0 inventory: source baseline, current schemas, domains, scope and public-vector hashes | Complete as an inventory; D1–D5 policy decisions are accepted, while implementation, final baseline and freeze acceptance remain open |
| P0 independent candidate review | Open; inspect changes since the historical reviewed candidates and close findings against the chosen SHA |
| P1 cross-implementation conformance | Partial: Rust/Kotlin v2 envelope/pairing and Rust/Kotlin/Swift tag vectors exist; full Swift signed-envelope/pairing fixture execution and a shared phone-v2 envelope remain open |
| P1 rejection/lifecycle/persistence evidence | Existing negative tests and scoped physical results remain useful; bind required cases to the candidate, including D3 boundaries. Source/CI agreement is not hardware verification |
| P1 breaking-update procedure | Open: exercise independent recovery, endpoint update order, any re-pairing and re-encryption on disposable identities. No exhaustive old Alpha/Beta interoperability matrix is required |
| P2 platform and release acceptance | Retain broader devices, wrong/multiple physical phones, fresh exact-package pairing, QR response replay, roaming, reboot/invalidation/storage/lifecycle rows and distribution readiness in the roadmap |

The [2026-10-29 fixed-pair record](evidence/maintenance-candidate-2026-10-29/README.md) retains
29 scoped accepted cases and 2 exclusions for the published Windows executable plus unpublished
R2 Android APK. The complete Android source inventory was bound to `be46c54`; this preparation does
not rebuild or re-certify those artifacts at `69b3cdf`. The published Beta 2 discovery failure remains
attached to its published bits. Broader coverage alone is not a wire-freeze gate, but any discovered
binding, parsing, authorization or consumption defect must be resolved for the affected path.

Next action after implementation is authorized: establish D3/D5 boundary evidence, then follow the
implementation order above. Only separately authorized implementation work may change code or fixtures. Neither this
record nor protocol freeze grants production-secret approval or replaces exact-release acceptance.
