# Protocol v2 candidate review package — 2026-10-31

Status: **prepared for independent review; not reviewed, not frozen, not a release approval**.
This packet organizes evidence and open questions. Its authors participated in D3/D5 implementation;
preparation, self-checks and passing CI do not close the independent-review gate.

## Immutable inputs

| Input | Revision or evidence |
| --- | --- |
| Proposed source under review | `799b36f18b89704bca00417b7af3dee6564054d2` (PR #30 merge) |
| Source tree | `e6f5c2e7858f4f25a33f9a10ad9ea7de875729eb` |
| Historical reviewed comparison point | `0305c0e9bace45159d601e62471a721cebac3a43`; [review scope and limitations](independent-security-review-2026-09-11.md) |
| Original preparation baseline | `69b3cdfa006d8bbe4f1154ec5874ea954f2ae717`; retained as historical assessment, not current review target |
| D3 implementation | `a6e0c10`, merged as `40b8fe4` in [PR #29](https://github.com/biulight/age-plugin-phone/pull/29) |
| D5 conformance | `1708706`, merged as `799b36f` in [PR #30](https://github.com/biulight/age-plugin-phone/pull/30) |
| Specification input | [protocol-v2-spec.md at the candidate](https://github.com/biulight/age-plugin-phone/blob/799b36f18b89704bca00417b7af3dee6564054d2/docs/protocol-v2-spec.md), SHA-256 `21f644152ccea6132825c0fb80908dc086a8ff48f089e85010809e67f81e9357` |
| Policy and scope | [accepted scope](protocol-v2-freeze-preparation.md#accepted-freeze-scope), D1–D5 decisions and [prerelease policy](protocol.md#prerelease-compatibility-policy) |
| Public vectors | Eleven files at the source SHA; byte manifest below; [consumer/reproduction catalog](test-vectors/README.md) |
| Candidate CI | [main run 41067845115](https://github.com/biulight/age-plugin-phone/actions/runs/41067845115), push event, exact source SHA above, completed successfully |

The specification input is a review draft: historical byte descriptions plus the accepted D3/D5
updates. Review must resolve any disagreement with this source explicitly before selecting normative
text. This packet is a later documentation overlay; it is not part of the immutable source above.
Record its eventual documentation revision separately in the final decision. No tag, release or new
native package was created for this preparation. Exclude local signing edits and untracked files.
If remediation changes runtime sources or vectors, name a successor SHA and reassess affected evidence.

CI was rechecked on 2026-10-31: all 11 jobs succeeded — Rust on Ubuntu/Windows/macOS, Android,
iOS, acceptance tooling on Ubuntu/Windows/macOS, reproducible inputs, release automation and
released-client interoperability. This includes the new public-stub checks and Swift production
conformance harness. Native builds and synthetic tests do not prove fresh hardware authorization.
Documentation deployment is not credited by this CI run; it is a separate workflow.

## Public-vector byte manifest

All values are public synthetic fixtures. Never provision their keys into production hardware.
The original seven files and the D3 corpus are unchanged; D5 adds three files. Hashes pin complete
JSON bytes, not just decoded fields. Keep one source of fixture bytes in core.

| File in `crates/core/test-vectors` | SHA-256 |
| --- | --- |
| `offline-envelope-v2.json` | `5e1cca6da4f06ce1f1c0e3f19b42908871a3710e84fee6ff38af41e9da90699b` |
| `p256-recipient-v1.json` | `6028deb7ae9122407214d1e8d6c3bdeb8d53c33f85340c499568ac1ac969d1e6` |
| `p256-recipient-v2.json` | `3765db88b82b8f3ec9710a22090f09826502602d2be90611cbbadbc85ad3c48c` |
| `p256tag-collision.json` | `9dad2c42a5e26819a7ef8f7a935f95fd6a07f2b7d9b3099157bb9db34d2b3e62` |
| `p256tag-envelope-v2.json` | `832e81cece94cd848d4350ff2af8a95947a006ba235e6e9fec8d502e88432f04` |
| `p256tag.json` | `d298ccda3620109a1f593af956910ef96bdbdbd848e014ce6694a09d25ea7b09` |
| `pairing-transcript-v2.json` | `baaa4289a6ca0eb7f6c3876ff0a0eb1074cde98eb5b158b2ae870ca9a80e18bd` |
| `phone-v2-envelope.json` | `adcc6d11df6dd0912a1e73718c6a9efe3b933ec82fa2b0c4a28700a8f203d343` |
| `protocol-boundaries-v2.json` | `09475ec03003ab22653596ad279027d458e2644a3d299f34541b079f2c1ad1aa` |
| `protocol-rejections-v2.json` | `61b352d605259bb9194e299348f0b26bd8c8fe275f76c40ad7dabfe1da3104a3` |
| `public-identity-stub-v2.json` | `d98dd78d8fcf5c946f8c9f036a5f486ded5258844bfa14df05ef232de8171496` |

## Independent increment review scope

Start with `0305c0e..799b36f`, not only the two latest PRs. Use the full diff to identify changes,
then trace each changed boundary through its unchanged callers and state consumers. In particular,
unchanged key-custody code remains part of the trust-path analysis; absence from the diff is not a
new certification. The following inventory is a review plan, not a finding or vulnerability rating.

| Area / change | Source and evidence entry points | Questions and required result |
| --- | --- | --- |
| R1 — desktop identity continuation (`f249b4b`) | `crates/desktop/src/age_identity.rs`; `unmatched_v2_stanza_is_an_ordinary_identity_miss`; existing selection/ambiguity and terminal-failure tests | Verify only a valid nonmatching identity permits continuation. Malformed state, ambiguous candidates and a selected pairing's cancellation/failure must not become a weaker fallback or contact another phone. Check phone/tag and restricted legacy semantics together. |
| R2 — Android Wi-Fi and operation ownership (`b6360c4`) | `PhoneIdentityPlugin.kt`, `WifiNetworkMonitor.kt`, `UnwrapOperationState.kt`, manifest multicast permission; corresponding JVM tests and state-store cancellation tests | Trace loss/restoration, listener generations, stale callbacks, retry cancellation, multicast-lock ownership and response handoff. No old worker may publish into a replacement operation; no transport event may restore consumed requests or cache authorization. |
| R3 — portable time and parser bounds (`a6e0c10`) | Rust protocol/replay and desktop unwrap; Kotlin `ProtocolBounds.kt`, envelope/state store; Swift Core `ProtocolBounds.swift`, envelope/state store | Check inclusive `[0, 2^63-1]`/300-second rules, safe creation, all decoder entry caps before copying, declared-length/nesting rejection, and state-write ordering. Persistent storage limits must remain separate. |
| R4 — Swift seams and conformance evidence (`1708706`) | Swift `OfflineEnvelopeCrypto.swift` / `TaggedRecipientCrypto.swift`; production boundary/conformance scripts; core generators and `protocol_conformance.rs`; desktop `public_stub_vector.rs`; independent stub checker | Trace real hardware wrappers into shared byte/crypto functions. No software identity/signer fallback or authorization reuse. Verify payload, AEAD, digest, signature, selector and stub expectations independently; check that rejected mutations fail for intended reasons and generators cannot redefine accepted bytes unnoticed. |
| R5 — device-test and evidence support (`215ed44`, `6bc7ba3`, `74f2d32`) | Android build configuration, `PairingStateStoreDeviceTest.kt`, visibility of `AndroidDurableFileOperations`; `.github/workflows/ci.yml`; `scripts/p1`, evidence validators and immutable physical archives | Distinguish tests executing real filesystem operations from substitutes and recorded owner observations. Check failures/unknown outcomes are not counted as passes. Test visibility must not expose a product bypass. Audit evidence binding and exclusions without treating archived tests as new hardware execution. |

Android names above are under
`plugins/tauri-plugin-phone-identity/android/src/main/java/io/github/biulight/phone_identity`,
with JVM tests under `src/test` and native storage tests under `src/androidTest`. Swift production
files are under `plugins/tauri-plugin-phone-identity/ios/Sources`.

Useful read-only scope commands from a checkout of the exact candidate:

```console
git diff --stat 0305c0e..799b36f
git log --no-merges --oneline 0305c0e..799b36f -- crates plugins .github/workflows/ci.yml
git diff 0305c0e..799b36f -- crates plugins .github/workflows/ci.yml scripts
```

Use [architecture](architecture.md), [threat model](threat-model.md), [specification](protocol-v2-spec.md)
and [vector reproduction](test-vectors/README.md) before judging behavior. Reproduce relevant negative
paths from locked dependencies at the candidate; do not edit expected vector bytes to make tests pass.
Use Rust 1.88, JDK 17 and macOS/CryptoKit for the documented native-language test commands.

## Evidence gaps and acceptance order

| Gate | Existing evidence | Still required / closure criterion |
| --- | --- | --- |
| G1 / P0 — independent increment review | Historical review through `0305c0e`; D3/D5 implementation self-checks and exact-candidate CI | A reviewer not acting as the D3/D5 implementer reviews R1–R5, records exclusions and methods, and verifies fixes against exact successor SHAs. No independent verdict has been obtained for this candidate. |
| G2 / P0 — specification and fixture binding | Pinned draft and eleven-vector manifest; Rust/Kotlin 39 rejection cases; Swift 18 inbound rejection cases and outgoing byte comparisons | Reviewer confirms accepted scope and implemented semantics agree, including D2/D4 selection/capabilities. Resolve discrepancies explicitly; bind the final specification revision to the reviewed source. Swift is not claimed to implement a desktop response decoder. |
| G3 / P1 — candidate lifecycle/persistence/native evidence | Rust/JVM replay and failure regressions; Swift source/harness checks; historical device archives | Map every mandatory safety invariant to an executable test or explicitly scoped native result. For changed paths, record justified evidence reuse or perform targeted candidate-native checks. Swift durable-store restart and hardware prompt cancellation/freshness are not established by Core vectors or CI builds. Do not require the whole platform matrix merely because coverage is incomplete. |
| G4 / P1 — breaking-update exercise | Accepted pre-freeze policy; historical independent-recovery cases | On disposable identities, record source/package hashes, independent recovery before changes, endpoint update order, required re-pairing/re-encryption, and verified recovery/output. Keep terminal failures and replay consumption; no manual state reset. Old-version compatibility is not a success criterion. Not executed by this preparation. |
| G5 / P0 — final freeze decision | This candidate packet and accepted scope | After G1–G4, explicitly accept source SHA, specification/document revision, capability set, vector hashes, findings and exclusions. Until then the protocol remains unfrozen. A source change requires reconsidering the candidate. |

For G3, first assess the existing tests and review findings; select only missing checks relevant to
identity selection, time/parser enforcement, authorization ownership or durable consumption. A
physical run must identify its exact package hashes and observed prompt/output behavior. This task
neither installs builds nor deletes/re-pairs identities. Runtime tests were not rerun for this
documentation-only packet; the linked candidate CI and prior scoped results are the evidence inputs.

The [2026-10-29 fixed-pair archive](evidence/maintenance-candidate-2026-10-29/README.md) records
29 accepted cases and two exclusions for the **published Windows Beta 2 executable and unpublished
Android R2 APK**, with Android inventory tied to `be46c54`. It is not a run of `799b36f`.
The [September iOS review](independent-security-review-2026-09-11.md) and its physical follow-up retain
their original candidate/device scope. Neither archive silently supplies a new platform pass.

Second device families, AP roaming, broad distribution, public signing and general platform support
remain release/platform work. The accepted desktop snapshot-freshness limitation remains unchanged.
Any discovered binding, parsing, authorization or consumption defect still blocks the affected
protocol path; calling a feature outside the wire freeze does not exempt its safety invariant.

## Reviewer handoff and finding closure

Review the immutable candidate above against R1–R5 and the stated threat model. Provide the exact
source SHA, reviewer identity/provenance, environment, commands/results, exclusions and any evidence
limitations. Report findings with severity, exploit prerequisites, source location, affected invariant,
reproduction and proposed remediation. For each fix, record its commit and independent re-verification.
An empty findings list is meaningful only with an explicit scope and method; CI success is not a verdict.

No findings or independent approvals are entered by this packet. The final record must distinguish
`not reviewed`, `confirmed`, `fixed awaiting review`, `closed` and explicitly accepted limitations.
Do not dismiss an issue merely because historical tests passed. After review, perform the targeted
G3/G4 work and make the separate final freeze decision; release approval remains separate.
