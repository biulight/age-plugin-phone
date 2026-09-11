# Independent Beta source review — 2026-09-11

Decision: **do not approve the complete Beta candidate claim**. Four new iOS defects
remain open. The transport-cancellation and replay-storage findings affect boundaries
that the candidate review brief requires to be resolved before publication. This
review does not demonstrate private-key extraction, a biometric bypass, or plaintext
delivery to an unpaired endpoint.

## Exact scope and method

- Baseline: `130538fa4a6f0fb24f32ab3ff698add05d9b18f2`.
- Candidate: `a41ba2e5be59f76980bf7d1a42bce94aba0d3019`.
- Comparison: `130538f..a41ba2e`, including renames; 415 changed files.
- Reviewer: Codex, independent inspection in this task; no delegated reviewers.
- Candidate exported with `git archive` to an isolated temporary directory. The
  checkout was at `ac0051fdf422eee58d98737756ce74011626b993` with two existing iOS
  generated-project modifications. Neither those changes nor later documentation
  commits were substituted for the candidate.
- Read candidate architecture, protocol and threat model; traced security-sensitive
  changes through desktop selection/request/response, mobile authorization and
  storage, hardware wrappers, transport, and setup/cleanup. Examined associated
  negative tests and release checks. Existing acceptance documents are review
  inputs, not independently reproduced hardware evidence.
- Used synthetic Swift probes against candidate source to test the newly identified
  codec and callback boundaries. No production pairing, QR payload, private key,
  file key, or plaintext was accessed.

This is a source review with targeted executable verification, not a proof of all
possible interleavings or a fresh certification of every platform/package. Findings
below distinguish deterministic probes, source-established behavior, and unperformed
physical reproductions. Line references refer to the candidate.

## Findings

### F1 — P2 / medium: iOS ignores transport failure after request delivery

Location: `plugins/tauri-plugin-phone-identity/ios/Sources/StreamTransport.swift:45-49`
(also 74-84 and 88-98); caller:
`plugins/tauri-plugin-phone-identity/ios/Sources/PhoneIdentityPlugin.swift:584-602`.

`finish` sets `requestDelivered` when it delivers the request. All later `.failed`,
`.cancelled`, and receive-timeout callbacks return at the same guard, before closing
the session or notifying its owner. There is no separate disconnect observer after
the body read. The plugin therefore cannot invalidate the corresponding `LAContext`
when the transport fails while authorization is pending. If authentication succeeds,
it can still open the stanza and build a signed response before discovering a send
failure. Disabling Wi-Fi similarly closes resources without invalidating that context.

Preconditions: an already valid signed request has reached the iPhone, followed by
connection loss during the pending operation. A LAN adversary needs no signing key
to disrupt an existing connection; it cannot use this finding to forge the request.

Deterministic callback probe: compile the unchanged candidate codec/session with a
minimal Network callback test double; deliver a request, inject `.failed`, then call
`sendResponse`. Observed `requestCallbacks=1`, `cancelCalls=0`, and
`late response sendCalls=1`. The test double accepting the final send is **not**
evidence that a real failed TCP connection delivers bytes. It establishes that the
application state machine neither terminates nor rejects the late send.

Fix: separate one-time request delivery from terminal session notification. Serialize
session transitions, monitor peer closure after the body, and bind termination to
the exact pending authentication owner. Reject late crypto/send completions and keep
the already consumed replay entry. Test disconnect, explicit listener disable and
backgrounding before, during and immediately after authentication.

### F2 — P2 / medium: the 129th live replay entry makes iOS state unreadable

Location: `plugins/tauri-plugin-phone-identity/ios/Core/Sources/PhoneIdentityCore/StrictCBOR.swift:90-95`;
writer: `plugins/tauri-plugin-phone-identity/ios/Sources/PairingStateStore.swift:73,94-98`.

New pairing state advertises capacity 1,024. `verifyAndConsume` accepts the 129th
unexpired entry and persists it using `StrictCBOR.encode`, which has no corresponding
array-count restriction. `StrictCBOR.decode` rejects every array longer than 128.
The next state read fails before expired entries can be removed. Waiting for expiry
or restarting therefore cannot recover the pairing. Summaries and revocation also
decode the same file, so ordinary management of the affected state fails as well.

Preconditions: 129 distinct valid signed requests remain unexpired simultaneously
(maximum lifetime 300 seconds). They need not be approved: consumption happens
before authentication, and a paired desktop can submit structurally valid requests
whose public tag does not match, causing failure before identity ECDH. Unauthenticated
LAN input alone cannot populate the store.

The probe compiles the candidate's unmodified `StrictCBOR.swift` and round-trips the
14-field store layout. Results:

```text
entries=128 encoded=7280 decode=accepted
entries=129 encoded=7335 decode=rejected: limit
entries=1024 encoded=56561 decode=rejected: limit
```

This is a codec-boundary reproduction with synthetic fields, not 129 physical phone
requests. The persistence/management consequences follow from the store call paths.

Fix: provide a bounded storage-specific array limit consistent with the declared
capacity, while retaining the tighter protocol-message limit. Ensure every accepted
state is readable after restart. Cover 128, 129, full capacity, overflow, expiry,
cancellation and reopen without resetting uncertain replay state.

### F3 — P2 / medium: backgrounding an idle iOS pairing leaves operations locked

Location: `plugins/tauri-plugin-phone-identity/ios/Sources/PhoneIdentityPlugin.swift:53-63`;
related `pairPhoneWifi` at 225-254 and `StreamTransport.swift:146`.

`pairPhoneWifi` sets `operationActive` before waiting for a connection. If the user
backgrounds the app while the listener is idle, background handling cancels and
removes the listener. `ForegroundStreamListener.cancel()` does not complete its
callback, and background handling neither resolves the pending invocation nor calls
`endOperation`. No remaining callback can reach `finishPairing`. After returning to
the foreground, `beginOperation` keeps rejecting operations and automatic Wi-Fi
rearming is blocked by `operationActive`.

Preconditions/reproduction sequence: configured iPhone, open Wi-Fi pairing, do not
connect a desktop, background the app, then return and retry pairing. A process
restart clears this in-memory deadlock. No attacker or successful pairing is needed.
This result is established by the source state transitions; no physical UIKit run
was performed in this review. Programmatic dismissal of lifecycle confirmation
alerts has the same missing-completion concern, but is not counted separately.

Fix: retain an operation owner with a one-shot cancellation completion. Background
handling must terminate the invocation and clear ownership exactly once; stale
listener callbacks must not reactivate the cancelled operation. Add a foreground /
background / retry test with no connection and with delayed accept callbacks.

### F4 — P2 / medium: interrupted iOS identity deletion cannot resume

Location: `plugins/tauri-plugin-phone-identity/ios/Sources/PhoneIdentityPlugin.swift:131-135`;
related `IdentityKeyStore.swift:65-84,206-210`.

After `beginDeletion` durably writes `state = "deleting"`, interruption or a later
storage/key-deletion failure leaves `identity.status()` returning `.deletionPending`.
The next `deleteIdentity` invocation requires `.success` and returns before the
idempotent `beginDeletion` / `finishDeletion` path. Provisioning also rejects this
state. The UI explicitly enables the delete button for `deletion_pending`, so the
offered recovery action cannot work. Depending on the interruption point, hardware
references and pairings can remain while the app can neither finish deletion nor
provision a replacement through its supported commands.

Preconditions: process interruption or storage failure after the deletion journal is
installed and before metadata removal. This is a source-established reachability
defect; this review did not interrupt deletion of a real identity.

Fix: allow the deletion-pending state into a native-confirmed, idempotent resume path,
without requiring the already deleted hardware roles to reopen. Test interruption
after each journal, pairing, key and metadata step, including application restart.

## Boundary assessment

| Boundary / brief question | Assessment |
| --- | --- |
| Cryptography / Q1 | No additional defect identified in inspected Rust/Kotlin/Swift tag key schedules: KEM and HPKE suite separation, labeled extract/expand, compressed selector input, uncompressed KEM context, empty AAD and sequence-zero nonce agree with the referenced specifications. Rust vectors and Swift CryptoKit HPKE comparison pass. Android native execution is excluded below. |
| Preselection and age integration / Q2 | Inspected adapter validates supported stanzas before opening private state; unknown types are ignored. Unmatched tags, same-stanza key collisions, first-pairing selection and no fallback have passing Rust tests. No new defect identified here. |
| Fresh native authentication / Q3 | Both native paths consume before identity use; Android compares the returned agreement object; iOS creates a fresh context with zero reuse. iOS transport cancellation is incomplete (F1), so the complete claim is not validated. |
| Authentication deadline / Q4 | The isolated monotonic deadline's winner, late completion and clock checks pass five tests. This does not validate its integration with every cancellation owner; F1 remains. Background races around context registration deserve follow-up testing with the ownership fix. |
| Desktop custody and storage / Q5 | Inspected hardware-role wrappers, signed Mac metadata, descriptor-relative storage and replay pending markers; relevant portable/macOS storage tests pass. No new bypass identified. Native TPM/Enclave enforcement was not revalidated on hardware. The documented desktop snapshot rollback limitation remains an accepted exclusion, not a resolved freshness guarantee. |
| Transport independence / Q6 | Desktop selects one route before signing; authenticated discovery binds the query. No new routing-to-authorization shortcut identified. iOS terminal-state behavior fails F1/F3. |
| Signed response and durable return / Q7 | Inspected unchanged core response binding and the desktop's sole return path; wrong binding, replay, malformed response, cancellation and replay-store failure tests pass for phone/tag paths. No unpaired-key release demonstrated. |
| Setup, cleanup and lifecycle / Q8 | Desktop exact-target/journal checks and relevant interruption tests pass. iOS lifecycle is not validated: F2 prevents state management, F3 strands an operation, and F4 blocks deletion resume. |

Cryptographic references: [C2SP age p256tag specification](https://c2sp.org/age#p256tag-recipient-stanza)
and [RFC 9180 key schedule](https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1).
Agreement with these constructions is narrower than a security proof of the system.

## Verification and exclusions

Environment: Apple Silicon macOS 26.6.2 (25G83), Swift 6.3.3, Python 3.14.7;
initial Rust checks used installed stable 1.96.0. The fmt, clippy and complete
workspace test checks were then repeated successfully with the brief's specified
Rust 1.88.0. All checks used the candidate's lockfiles.

Completed checks:

- `cargo fmt --all --check`: pass (Rust 1.88.0 and 1.96.0).
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: pass (both).
- `cargo test --workspace --locked`: pass (both); 151 top-level tests passed,
  four explicitly ignored tests. Nested process invocations are not double-counted.
  The initial sandbox run had ten loopback/process-group failures; the authorized
  unsandboxed rerun passed. A dependency future-compatibility warning for `block`
  remains, without becoming a new finding in this review.
- `python3 scripts/check-package-layout.py --archives`: pass; archive listing uses
  the installed Cargo 1.88.0 as prescribed by that script.
- `python3 -m unittest discover -s scripts/release -p 'test_*.py'`: 29 passed.
- Swift Core tests: 11 passed, using temporary build/module caches and
  `--disable-sandbox` to avoid nesting Apple's sandbox inside the task sandbox.
- Independent Swift probes: reproduced F1 state-machine behavior and F2 array
  round-trip mismatch. See [reproduction runner](review-evidence/beta-a41ba2e/reproduce.py).

Excluded from new passes: Windows execution and TPM enforcement, Android Gradle and
StrongBox execution, iPhone Secure Enclave/LocalAuthentication/UIKit execution,
ignored native Mac hardware tests, ignored released-age/rage interoperability test,
signed installable packages, distribution/signing, detached registry installation,
full dependency advisory reassessment, and physical transport/lifecycle matrices.
The package-layout check is not a detached-package build. Existing CI and physical
acceptance claims were not promoted to fresh results. No production keys were
created or removed. Python 3.13 was not used for the Python checks.

The complete candidate claim is therefore **not validated** for macOS+iPhone Wi-Fi
(both default phone and explicit tag). No new blocking finding was established in
the inspected Windows+Android or macOS+Android source paths, but the excluded native
tests prevent this review from certifying those device combinations. Resolve and
independently recheck F1–F4, then repeat the affected iOS physical cases before using
this report as release approval.
