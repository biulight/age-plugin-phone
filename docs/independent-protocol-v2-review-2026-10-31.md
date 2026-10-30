# Independent protocol v2 increment review — 2026-10-31

Decision: **R1–R5 source review performed; no new authorization bypass, wrong-device binding,
weaker fallback, unbounded parsing or replay-consumption restoration defect confirmed in the
examined scope.** One low-priority existing clock-conversion observation (O1) remains for disposition.
This is not protocol-freeze approval, hardware acceptance or release approval.

## Provenance, candidate and method

- Source: `799b36f18b89704bca00417b7af3dee6564054d2`; tree
  `e6f5c2e7858f4f25a33f9a10ad9ea7de875729eb`.
- Comparison: `0305c0e9bace45159d601e62471a721cebac3a43..799b36f`.
- Reviewer: fresh-context Codex agent `/root/independent_v2_review`, explicitly authorized by the
  project owner for read-only review, with no participation in D3/D5 implementation and no further
  delegation. This is an independent agent review, not an external human audit or certification.
- Review instructions and scope: [candidate packet](protocol-v2-candidate-review-2026-10-31.md).
  The reviewer read repository security instructions, architecture, protocol and threat model;
  inspected the increment and relevant unchanged trust-path callers; and ran targeted checks.
- The workspace was at documentation-only commit `58988035877f35dad2ad0a59097bd738062d9682`.
  Runtime sources, test scripts and CI definition matched the candidate. All eleven public-vector
  hashes matched the packet. Local Xcode edits and unrelated untracked files were excluded.
- This record transcribes the agent's final report; the implementing/coordinating agent prepared
  the documentation. No independent finding is claimed merely from that coordination or prior CI.

The reviewer made no source, vector, document, index or ref changes. Temporary test/build outputs
were not product changes; four newly generated Python cache files were cleaned up. The coordinator
verified tracked-file and original untracked-file hashes, HEAD and index remained unchanged.

## R1–R5 results

| Area | Inspection and result |
| --- | --- |
| R1 — identity continuation | Traced `age_identity.rs` input validation, tag collision/priority, restricted legacy selection, v2 selection, state opening and final exchange. Ordinary v2 identity miss requires no match and no state error; selected-pair cancellation, invalid response or state/transport failure does not reselect another pairing. |
| R2 — Android ownership and Wi-Fi | Traced observation generations, queued callbacks, listener tokens, `publishWifi`, response handoff and multicast-lock cleanup. Followed verify → durable consume → StrongBox agreement → BiometricPrompt returning the identical agreement object. Old workers cannot publish into replacement ownership; network cancellation does not restore consumption. |
| R3 — time/parser bounds | Rust's four signed decoders share the cap and fixed-schema parsing; Kotlin bounds canonical structure before Jackson allocation; Swift checks size before field copies. Range/order/difference checks preserve the inclusive 300-second window, with storage limits separate. O1 identifies a pre-helper production clock conversion not covered by these helper tests. |
| R4 — Swift seams and vectors | Confirmed real hardware wrappers call the shared payload/post-ECDH functions. No software identity/signing fallback was added; unwrap still creates a new LAContext, uses zero reuse and invalidates on exit. Checked corpus signatures and intended Rust errors, Swift inbound rejection and outgoing pairing/response bytes against independently consumed fixtures. |
| R5 — device tests and evidence | Android instrumentation uses the real durable-file implementation with replace/sync failure injection; reopen is not proof of power-loss durability. Internal test visibility adds no external/Tauri API. Evidence validation separates machine results, owner observations, exclusions, request/replay binding and source/package lineage; old archives are not new device execution. |

## Executed checks and limits

These are reviewer-reported executions against candidate-equivalent runtime bytes, not new runs
performed while writing this record. Apple Swift 6.4 / macOS arm64 was used for Swift checks.

| Command (repository root; local RTK wrapper omitted) | Result |
| --- | --- |
| `RUSTC_WRAPPER= cargo +1.88.0 test -p age-plugin-phone-core --locked` | 43 passed; 1 external age-client test ignored |
| `RUSTC_WRAPPER= cargo +1.88.0 test -p age-plugin-phone --locked age_identity` | 13 passed |
| `python3 scripts/test-ios-protocol-boundaries.py` | Passed |
| `python3 scripts/test-ios-protocol-conformance.py` | Pairing, three envelopes and 18 inbound rejection cases passed; all 39 corpus signatures checked with CryptoKit |
| `python3 scripts/check-public-stub-vector.py` | Passed |
| `RUSTC_WRAPPER= cargo run --locked -p age-plugin-phone --example public_stub_vector -- crates/core/test-vectors/pairing-transcript-v2.json crates/core/test-vectors/public-identity-stub-v2.json` | Production serialization/parsing matched; Rust 1.99 |
| `python3 scripts/test-p1-evidence.py` | 10 passed |
| `python3 scripts/test-p1-replay.py` | 4 passed, including normal, `-O` and `PYTHONOPTIMIZE` execution modes |
| `python3 scripts/check-p1-evidence.py docs/evidence/maintenance-candidate-2026-10-29` | 71-file archive check passed, including referenced archive validation |
| `git diff --check` | Passed |

Rust core/identity-selection checks also passed with Rust 1.99. Android JVM tests were attempted,
but Gradle could not write its wrapper lock under the restricted execution environment; tests did
not start. No permission escalation or device operation was performed. Existing candidate CI is
separate evidence, not a substitute for an independently executed Android run.

Not executed: Android instrumentation; StrongBox/Secure Enclave hardware authorization; real prompt
cancellation/freshness; iOS durable-store cross-process/restart; real-client interoperability;
breaking-update/recovery exercise; Windows/macOS hardware-custody revalidation. Historical physical
archives retain their exact original package/source scope. The accepted desktop snapshot-freshness
limitation was not reported as a new defect.

## O1 — existing iOS system-clock conversion may trap

**Classification:** low-priority defensive robustness observation. **State:** observed conversion
failure; actual-device reachability unverified; disposition pending. Not fixed, not accepted as a
risk, and not classified by this review as a P0/P1 protocol-freeze security blocker.

At the candidate, `plugins/tauri-plugin-phone-identity/ios/Sources/PhoneIdentityPlugin.swift`
converts `Date().timeIntervalSince1970` directly to `UInt64` at request receive lines 290/713,
authorization checks 657/701 and pairing lines 221/533. A Unix time of -1 triggers a Swift fatal
trap before `ProtocolBounds` can reject it; `do/catch` cannot turn the trap into a protocol error.

Independent minimal reproduction:

```console
swift -module-cache-path /tmp/phone-review-swift-cache -e 'import Foundation; let clock = Date(timeIntervalSince1970: -1); print(UInt64(clock.timeIntervalSince1970))'
```

Observed: exit 133 / signal 5, with a diagnostic that the Double cannot convert below `UInt64.min`.
The expression and production call sites are confirmed; the reviewer did not demonstrate that a
real iOS system clock can reach the input. LAN traffic and protocol fields do not directly control
`Date()`. No key disclosure, wrong authorization or replay bypass was demonstrated. The file is
unchanged from `0305c0e`, so this is not a new D3 regression. Helper-level negative-time coverage
does not establish safety of the production clock-to-integer adapter.

Suggested follow-up: a checked Unix-clock adapter that checks finite, nonnegative and accepted
upper-bound values before conversion, returns a throwing failure, and is tested at the actual
adapter boundary. NaN/infinity are defensive test inputs, not asserted reachable system states.
The owner must choose remediation or explicit documented deferral with rationale. Remediation
requires a successor source SHA, relevant regressions and independent verification; a deferral
must retain the observed behavior and reachability limits. This record makes neither decision.

## G3 — targeted state and native acceptance still open

Before running devices, map invariants to the existing candidate tests and exact archived packages.
For each required row record `passed`, `not-run`, `excluded`, or a justified evidence-reuse decision;
missing observation or a tool failure is not a pass. Do not claim a full platform matrix.

| Follow-up | Acceptance evidence |
| --- | --- |
| G3a — Android candidate tests | Independently execute the candidate JVM suite in a permitted environment. Execute the existing device storage tests where native evidence is needed: replacement failure, uncertain sync failure and clock rollback. Bind source/build/device identifiers and distinguish reopen from power loss. |
| G3b — iOS durable consumption | With a candidate-bound disposable pairing, verify consumed requests remain rejected after cancellation/failure and an ordinary supported app restart. A fresh request must still require new authorization. Missing/corrupt/uncertain state must fail closed; never reset it to create a pass. Core vectors and compilation do not close this row. |
| G3c — native authorization ownership | On included changed paths, record fresh native approval per operation, cancellation/timeout/disconnect without file-key output, stale callback rejection and fresh-request recovery. Include Android Wi-Fi replacement ownership and iOS cancellation around protected-key use as required by the candidate delta; substantiate any reuse of old evidence. |
| G3d — scope and disposition | Bind every reused/executed result to source and package hashes, exact transport/recipient mode and owner observation. Resolve O1's disposition separately; broader device-family/roaming work stays a release gate unless a concrete safety defect affects the included path. |

Do not install, replace, revoke or delete existing user identities merely to perform this plan.
Use disposable state and the normal native confirmation flows. Keep raw requests, QR contents,
private/file keys, plaintext and private paths out of public evidence. The owner/reviewer records
which rows are necessary for this candidate and why; old package results never silently become
candidate passes. G3 closes only when every required invariant has scoped evidence or an explicit,
justified acceptance decision consistent with repository safety rules.

## G4 — breaking-update and recovery exercise still open

1. Identify the actual pre-freeze transition and affected formats/versions. Bind both endpoint
   packages and the candidate source; state update order and effects on retained ciphertext.
   If no applicable transition/build is available, record `not-run`, not a fabricated migration pass.
2. With disposable identities and synthetic data, include an independent recovery recipient and
   verify it works before any operation that removes access. Keep the required original keys/state
   until recovery is demonstrated.
3. Perform the documented endpoint update and any required fresh pairing through normal full
   fingerprint comparison and native approval. Record supported/rejected old inputs; backward
   compatibility is not promised or required, but incompatible inputs must fail closed.
4. Recover and re-encrypt retained synthetic data for the new pairing; verify recovered output and
   fresh-authorized decrypt. Cancellation/failure must not restore consumed requests or silently
   select another pairing/recipient mode. Do not use manual replay edits/reset or private-key migration.
5. Record package hashes, observations, expected/actual outcomes, exclusions and recovery before
   cleanup. Do not record secret material. A release transition notice must match what was exercised.

G4 closes when the selected real transition demonstrates independent recovery, correct rejection,
required re-pairing/re-encryption and successful fresh use without weakening the safety invariants.
No G3/G4 operation was performed by this documentation task. Final specification binding (G2) and
explicit baseline/freeze approval (G5) remain separate; publication and broad support are not implied.
