# Independent protocol v2 increment review — 2026-10-31

Original decision at `799b36f` (2026-10-31): **R1–R5 source review performed; no new authorization bypass, wrong-device binding,
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

The observation and classification below describe the reviewed candidate. For current remediation
status, see the [implementation follow-up](#o1-implementation-follow-up--2026-11-01).

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

### O1 implementation follow-up — 2026-11-01

The owner requested continued implementation after review delivery. The successor implementation
change based on `776a38f` now routes all six iOS clock-to-integer call sites through
`ProtocolBounds.unixTime`. It rejects negative/non-finite samples and integers above `Int64.max`
before use, preserves whole-second truncation for valid samples, and handles the rounded
`Double(Int64.max)` boundary. Invalid post-authorization time follows the existing file-key clearing
and context/deadline cleanup path; replay consumption is not restored.

Implementation-stage status: **remediation implemented; independent re-verification pending at
the time of implementation**. The subsequent review below records current closure. The original observation and review verdict above describe `799b36f`
and remain unchanged. This follow-up is implementation evidence from the coordinating agent, not
an independent closure or evidence that an actual iOS clock reaches the problematic inputs.
No wire bytes, public fixtures, private-state formats or compatibility policy changed.

Local implementation verification on macOS arm64:

- `swift test --package-path plugins/tauri-plugin-phone-identity/ios/Core`: 15 tests passed,
  including negative/fractional/non-finite/overflow clock samples and existing cancellation,
  deadline, malformed-message and replay regressions. The first sandboxed attempt could not write
  its compiler cache; the permitted retry passed.
- `python3 scripts/test-ios-protocol-boundaries.py`: production adapter/request checks passed.
- `python3 -B scripts/test-ios-protocol-conformance.py`: pairing, three envelopes and 18 inbound
  rejection cases passed; public fixtures remain unchanged.
- `python3 -B scripts/test-ios-stream-lifecycle.py`: passed.
- `swiftc -frontend -parse plugins/tauri-plugin-phone-identity/ios/Sources/PhoneIdentityPlugin.swift`:
  passed (syntax only; not device acceptance).
- `RUSTC_WRAPPER= cargo build --locked --target aarch64-apple-ios --manifest-path
  apps/mobile/src-tauri/Cargo.toml`: passed, including the production Swift plugin; no project
  regeneration, signing, simulator launch or device installation was performed.
- From `apps/mobile/src-tauri/gen/android`, `mise exec -- ./gradlew
  :tauri-plugin-phone-identity:testDebugUnitTest --no-daemon --rerun-tasks`: 93 tests across 17 suites,
  zero failures/errors/skips, with repository-selected Temurin 17. The initial system-JDK 27 attempt
  failed in Gradle configuration before tests; it is not a product failure or a pass. Existing
  Gradle/Tauri deprecation warnings remain.

The Android run is coordinating/implementing-agent evidence; it does not retroactively change the
original reviewer's blocked run or satisfy G3a's independent-execution requirement. No Android
source changed. These implementation checks alone did not close O1; the independent follow-up
below supplies the subsequent source-level closure. Final candidate binding remains required. G3 native acceptance and G4 remain open; no device operation or recovery exercise is implied by this patch.

### O1 independent re-verification — 2026-11-01

**Result: O1 closed in the source scope of `431cf9f821f973953d4c0cfffaebb5d120ee241c`.**
No new P0/P1/P2/P3 finding was reported. This is source-level remediation closure, not a new
full-scope review, native acceptance, final candidate selection or protocol-freeze approval.

The owner authorized a new fresh-context reviewer, Codex agent `/root/independent_o1_review`,
which did not participate in the O1 implementation and did not delegate. Its read-only review
compared `776a38f52ee17fb3c26d22509864a830b436e178..431cf9f821f973953d4c0cfffaebb5d120ee241c`,
read the architecture/protocol/threat model and inspected the relevant unchanged callers.
The coordinator transcribes its result here; this is not an external human audit.

The reviewer confirmed finite/nonnegative checks, exact UInt64 conversion and the final Int64
bound, including the rounded `Double(Int64.max)` input and its accepted predecessor. All six
production uses (lines 221, 290, 533, 657, 701 and 714 at the reviewed commit) use the adapter.
Invalid post-authorization time clears `fileKey` before throwing and executes deadline/context
cleanup; consumption is never restored. The production boundary test's `reachedVerification`
assertion prevents downstream request rejection from masquerading as adapter rejection.

Independent executions (local `rtk proxy` prefix omitted):

| Command | Result |
| --- | --- |
| `swift test --package-path plugins/tauri-plugin-phone-identity/ios/Core` | 15 tests, zero failures |
| `python3 -B scripts/test-ios-protocol-boundaries.py` | Passed |
| `python3 -B scripts/test-ios-protocol-conformance.py` | Pairing, three envelopes and 18 inbound rejection cases passed |
| `python3 -B scripts/test-ios-stream-lifecycle.py` | Exit 0 |
| Android generated directory: `mise exec -- ./gradlew :tauri-plugin-phone-identity:testDebugUnitTest --no-daemon --rerun-tasks` | 33 tasks executed; XML: 17 suites, 93 tests, zero failures/errors/skips; Temurin 17.0.20.1 |
| `git diff --check 776a38f 431cf9f` | Passed |

Initial Swift-cache and Gradle-lock sandbox failures were followed by permitted successful reruns;
existing Gradle/Tauri deprecation warnings remained. G3a's independent JVM execution subitem now
passes at `431cf9f`; its device-storage subitem remains open. This does not rewrite the original
reviewer's blocked execution at `799b36f` or the implementer's separate results.

Not rerun: full iOS target build. Not performed: actual-device clock fault injection, Secure Enclave
or native authentication acceptance, restart durability, device storage tests, or recovery exercise.
Post-auth cleanup conclusions are from source review, not a new phone observation. The historical
`799b36f` review and CI are not transferred to this successor. Final source/specification/vector
binding, successor CI, G3 native evidence, G4 and G5 remain separate outstanding work.
The reviewer changed no files or Git state; the coordinator verified tracked-file and original
untracked-file hashes, HEAD and index were unchanged after review.

## G3 — targeted state and native acceptance still open

Before running devices, map invariants to the existing candidate tests and exact archived packages.
For each required row record `passed`, `not-run`, `excluded`, or a justified evidence-reuse decision;
missing observation or a tool failure is not a pass. Do not claim a full platform matrix.

| Follow-up | Acceptance evidence |
| --- | --- |
| G3a — Android candidate tests | Independent JVM execution passed at `431cf9f` (93 tests); this subitem is complete for that source. Execute the existing device storage tests where native evidence is needed: replacement failure, uncertain sync failure and clock rollback. Bind source/build/device identifiers and distinguish reopen from power loss. |
| G3b — iOS durable consumption | With a candidate-bound disposable pairing, verify consumed requests remain rejected after cancellation/failure and an ordinary supported app restart. A fresh request must still require new authorization. Missing/corrupt/uncertain state must fail closed; never reset it to create a pass. Core vectors and compilation do not close this row. |
| G3c — native authorization ownership | On included changed paths, record fresh native approval per operation, cancellation/timeout/disconnect without file-key output, stale callback rejection and fresh-request recovery. Include Android Wi-Fi replacement ownership and iOS cancellation around protected-key use as required by the candidate delta; substantiate any reuse of old evidence. |
| G3d — scope and disposition | Bind every reused/executed result to source and package hashes, exact transport/recipient mode and owner observation. O1 source closure is recorded above; retain its exact revision and scope; broader device-family/roaming work stays a release gate unless a concrete safety defect affects the included path. |

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
