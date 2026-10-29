# Protocol v2 freeze preparation record

Date: 2026-10-30. Status: P0 specification/scope inventory prepared for review; **not frozen**.
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

## Proposed freeze boundary

The following is the candidate scope for decision D1, not a completed freeze:

| Include in the v2 baseline | Keep separately versioned or outside this freeze |
| --- | --- |
| Signed pairing/unwrap layouts; suites; domain separation; canonical parsing; key roles and bindings | Private hardware metadata, pairing/locator/journal/replay file byte layouts and migration tooling |
| Recipient/stanza formats and selection semantics for the explicitly selected capability set (D2/D4) | CLI/API stability, setup JSON schema, packaging, OS/device support and installation UX |
| Public identity stub schema and its validation/binding semantics | QR framing, common stream envelope and discovery wire formats unless separately accepted |
| Fresh per-operation authorization, durable consumption and terminal-failure requirements | Specific storage capacities, UI deadlines and native implementation details, subject to safety invariants |

Transport exclusion means no wire-stability promise for that framing; it does not exempt a transport
from signature verification, bounded parsing, fresh authorization or replay rules. Private storage
exclusion similarly does not permit state loss, uncertain replay reset or weaker key custody.

## Decisions still required

| ID | Question and evidence | Recommended disposition | Closure needed |
| --- | --- | --- | --- |
| D1 | Which source/specification revisions and scope are frozen? Current preparation names `69b3cdf`, but no freeze approval exists. | Review this candidate and the table above; name the final specification revision separately. | Explicit accepted baseline/scope after relevant gates pass; rebaseline if source changes |
| D2 | Retain legacy `phone-p256-v1` stanza support in the stable supported set? It is still accepted with restricted selection, and the pairing response/stub carry the single-phone recipient encoding. | Retain current behavior for this candidate to avoid unrelated code changes; do not promise historical protocol-v1 messages or state. Decide any later removal explicitly. | Confirm legacy stanza policy separately from the single-phone public-key encoding; identify affected ciphertext if removal is chosen |
| D3 | What are the portable clock integer range, overflow behavior and parser resource bounds? Rust uses u64 with saturating lifetime addition; Kotlin accepts nonnegative Long and adds 300; Swift uses UInt64 and ordinary addition. Swift CBOR defaults to 65,536 bytes/128 elements/depth 16; Rust's protocol decoder has field bounds but no equivalent total-input cap in decode_signed. | Specify a bounded interoperable time domain and overflow rejection; distinguish normative message bounds from transport/storage caps. Do not assume all extremes already agree. | Choose limits, inspect each entry boundary and add shared boundary tests in subsequent code work if needed; ordinary-clock vectors alone do not close this |
| D4 | Which stanza capabilities does a frozen v2 endpoint support, and how are future additions versioned? Pre-tag mobile parsers reject tag while retaining protocol number 2. | Name phone v2 and explicit tag in the current profile, subject to D2 for legacy v1; reject unsupported capabilities. Do not add negotiation solely for freeze. | Accept a baseline capability list and an extension/versioning policy that never reinterprets frozen fields |
| D5 | What completes the conformance fixture set? Existing vectors do not cover every full message path or every parser rejection. | Add a shared phone-v2-stanza envelope, full Swift pairing/envelope coverage and public-stub serialization expectations; organize negative mutations with explicit outcomes. | Agree the required vector/negative-test matrix and close its gaps on the selected candidate; no fixture generation or code edits occur in this task |

D3 is a source-observed boundary difference and a review item, not evidence of a practical
biometric bypass. Do not invent a new wire bound in documentation and claim existing code enforces
it. D2/D4 recommendations preserve the current implementation while making future promises explicit.

## Evidence and remaining work

| Work item | Status and next step |
| --- | --- |
| P0 inventory: source baseline, current schemas, domains, scope and public-vector hashes | Prepared here; review the specification/catalog and resolve D1–D5 before claiming closure |
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

Next action: review D1–D5 and the current-byte specification, then perform the targeted P0 independent
review. Only separately authorized implementation work may change code or fixtures. Neither this
record nor protocol freeze grants production-secret approval or replaces exact-release acceptance.
