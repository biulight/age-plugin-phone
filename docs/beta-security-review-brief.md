# Beta 1 security review brief

Date: 2026-09-11. Status: review input, not a review result. Candidate merge:
`ab9b4ab7d71d923fef6bef926ff1780bdaac6f76`. Previous independent-review
baseline: `130538fa4a6f0fb24f32ab3ff698add05d9b18f2`.

The [2026-08-29 independent review](independent-security-review-2026-08-29.md)
validated its stated source scope. It does not cover the complete Beta 1 delta.
The delta adds macOS Secure Enclave custody and storage, iOS implementation,
foreground Wi-Fi discovery/transport, managed setup and cleanup lifecycle, desktop
crate separation, and native `p256tag`. Reviewers must not transfer the earlier
decision to these additions without examining them.

## Candidate claim

Within the [limited Beta scope](beta-readiness.md), the desktop has no reusable
long-term phone identity. A file key is returned only after strict stanza and
signed-request validation, pairing binding, durable phone request consumption,
one fresh native phone verification, authenticated stanza open, complete signed
response verification, and durable desktop response consumption. Cancellation,
timeout, malformed input, replay, wrong device or transport failure adds no
fallback and restores no consumed request.

The review should validate or reject that claim separately for:

- Windows 11 x64 TPM 2.0 with Android StrongBox over Developer USB and foreground
  Wi-Fi;
- Apple Silicon macOS Secure Enclave with Android StrongBox over foreground Wi-Fi;
- Apple Silicon macOS Secure Enclave with iPhone Secure Enclave over foreground
  Wi-Fi; and
- explicit `p256tag` versus default `phone` selection on each applicable path.

Unverified devices, QR tag, BLE, background wake, publicly trusted Windows
distribution, general iOS distribution, protocol stability and production secrets
are outside the candidate claim.

## Required source clusters

Review the complete candidate diff from the previous baseline, using these clusters
to organize rather than narrow the scope:

| Boundary | Primary implementation |
| --- | --- |
| Standard tag format and HPKE | `crates/core/src/recipient/tag.rs`, `crates/core/tests/p256tag.rs`, public `p256tag` vectors |
| Desktop preselection and no-fallback behavior | `crates/desktop/src/age_identity.rs`, `crates/desktop/tests/recipients.rs` |
| Android hardware open and authorization | `TaggedRecipientCrypto.kt`, `PhoneIdentityPlugin.kt`, `PhoneIdentityKeyStore.kt`, pairing/replay stores and their tests |
| iOS hardware open and authorization | `TaggedRecipientCrypto.swift`, `P256Tag.swift`, `PhoneIdentityPlugin.swift`, `IdentityKeyStore.swift`, `AuthenticationDeadline.swift` and tests |
| Request/response protocol and replay | `crates/core/src/protocol`, Android/iOS offline-envelope and pairing stores |
| Desktop hardware custody | `crates/platform-keys/src/windows.rs`, `crates/platform-keys/src/macos`, archived Swift bridge |
| Private storage and lifecycle | `crates/platform-storage`, desktop locator/setup/cleanup journals, mobile revocation/deletion journals |
| Transport independence | desktop ADB/Wi-Fi/QR and transport policy, Android/iOS stream transport and authenticated Wi-Fi discovery |
| age and CLI boundary | desktop recipient/identity state machines, managed setup JSON and public-only `recipients` export |

The baseline-to-candidate source delta is large because it includes platform and
crate expansion. Renames and evidence commits must not hide functional changes.
Generate the exact inventory with:

```console
git diff --name-status 130538fa4a6f0fb24f32ab3ff698add05d9b18f2..ab9b4ab7d71d923fef6bef926ff1780bdaac6f76
git diff --stat 130538fa4a6f0fb24f32ab3ff698add05d9b18f2..ab9b4ab7d71d923fef6bef926ff1780bdaac6f76
```

## Questions that require explicit answers

1. Does the RFC 9180 key schedule exactly match the standardized P-256 tag format
   in Rust, Kotlin and Swift, including compressed recipient versus uncompressed
   encapsulated point use, labeled extract/expand, mode, suite IDs, nonce and empty
   AAD?
2. Can malformed, colliding, ambiguous or unmatched tags cause private state,
   transport or phone authorization to be attempted too early, or cause another
   pairing/identity/recipient mode to be tried after failure?
3. Do Android and iOS consume the request durably before creating the per-use
   identity operation, require the exact returned native crypto object/context,
   and prevent late callbacks after cancellation, timeout, expiry or lifecycle
   loss from producing a response?
4. Does the iOS monotonic authentication deadline have one winner across timer,
   completion and cancellation races, revoke only its own `LAContext`, reject clock
   rollback/nonfinite values, and clear a file key opened at or after expiry?
5. Do macOS and Windows desktop custody, locator and storage implementations reject
   missing, partial, redirected, linked, insecure, corrupt, concurrent and uncertain
   state without silently repairing or creating an empty replay scope?
6. Can unauthenticated ADB, LAN discovery, TCP, QR or caller labels influence
   anything beyond bounded routing/display, or create retry/fallback after a signed
   request has been created or consumed?
7. Are all response fields bound to the paired desktop, request digest, request ID,
   one-time session key and nonce, with durable response consumption before the
   sole file-key return to age?
8. Do setup, cleanup, revocation, deletion and upgrade paths preserve unrelated
   pairings and replay state across interruption, and is every destructive target
   exact and independently confirmed where required?

## Reproduction and existing evidence

Use Rust 1.88, Python 3.13, JDK 17 and the locked dependency files. Run:

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3.13 scripts/check-package-layout.py --archives
python3.13 -m unittest discover -s scripts/release -p 'test_*.py' -v
swift test --package-path plugins/tauri-plugin-phone-identity/ios/Core
```

Run Android native tests through the generated Gradle wrapper with JDK 17. Run the
ignored native age/rage tests explicitly with released absolute client paths.
Hardware skips and simulator builds are not hardware passes. The branch and PR CI
records for the closeout commit passed Linux, Windows, macOS, Android, iOS,
released-client interoperability, detached package installation, reproducible
inputs and release-automation jobs.

The [tag evidence](tagged-recipient-evidence.md) records exact signed-candidate
hashes and physical observations. Retain failed attempts, especially the original
iOS authentication-timeout failure, separately from replacement-package passes.
The [Beta readiness checklist](beta-readiness.md) lists physical evidence still
required before publication.

`cargo audit` on 2026-09-11 loaded 1,243 advisories and found no vulnerability,
with nine allowed warnings. The two unsoundness warnings remain the documented
`glib::VariantStrIter` Linux-only Tauri path and `lru::LruCache::pop` path whose
current key/API preconditions are not used. Seven additional warnings identify
unmaintained transitive crates. Re-evaluate reachability and replacements rather
than treating a zero exit status as a security finding closure.

## Required output

The independent reviewer should identify the exact reviewed commit, environment,
methods and exclusions; list findings with severity and exploit preconditions;
separately assess cryptography, native authorization, replay/storage, lifecycle,
transport and age integration; and state whether the candidate claim is validated.
Every finding affecting key custody, authorization freshness, message binding,
replay, strict parsing or transport independence blocks publication until resolved
and independently verified. Record physical/package exclusions as exclusions, not
passes.
