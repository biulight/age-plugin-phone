# Beta 1 closeout

Date: 2026-09-11. Target: `0.1.0-beta.1`. Status: **preparing; not approved for
publication or external onboarding**. The owner authorized beta closeout. This
document records the proposed limited technical-user scope and remaining work;
it does not mark deferred Alpha or tagged-recipient gates as passed.

## Scope

Stop feature expansion while closing this candidate. Use synthetic or disposable
data with a separately tested independent recovery recipient. Every unwrap still
requires fresh native phone verification and complete request/session binding.

| Path | Proposed Beta 1 delivery and evidence boundary |
| --- | --- |
| Windows 11 x64, TPM 2.0 → qualified Android StrongBox | Source-installed CLI or optional test-signed Windows ZIP, plus signed ARM64 APK; Developer USB and foreground Wi-Fi. The Windows private test root is not publicly trusted; do not install it as a trusted root. Final beta packages still need acceptance. |
| Apple Silicon macOS → Android | Source-installed CLI; foreground Wi-Fi and explicitly selected Developer USB. Evidence applies to the recorded host and phone, not every macOS/StrongBox combination. |
| Apple Silicon macOS → iPhone | Existing developer-device cohort, foreground Wi-Fi. No externally installable iOS package or TestFlight distribution is promised. |
| Other hardware, OS versions and GUI callers | Unverified unless separately recorded; successful compilation is not device support. |
| QR tag, BLE, background wake | Outside Beta 1's validated transport scope. BLE remains unavailable. Existing QR behavior is experimental. |

The beta label describes a testing stage, not a production security claim. The
current owner-only deployment remains in force until the launch gates below are
closed. The original [Alpha matrix](alpha-matrix.md) remains historical and broader
coverage work; this plan does not claim completion of that matrix.

Windows source installation uses the MSVC Rust toolchain and Visual Studio C++
Build Tools / Windows SDK. After publication, both Windows and macOS can run
`cargo install age-plugin-phone --version 0.1.0-beta.1 --locked` with the
[documented build prerequisites](crates-io-release.md). Publicly trusted Windows
code signing is not required to build from source; hardware runtime checks remain
unchanged. A signed Android app is still required for the Windows/Android route.

## Compatibility policy for the candidate

- `phone` remains the default. Explicit `tag` is opt-in, requires age 1.3+ for native
  encryption, and exposes a publicly testable short selector. No automatic format
  conversion or failure fallback is added.
- Public identity stubs, setup JSON schema 1, pairing state and protocol v2 encodings
  are unchanged by the tag feature. Existing paired installations passed scoped
  in-place candidate updates; that is not final beta-package upgrade evidence.
- Older phone apps strictly reject `p256tag`; update the phone before using tag
  ciphertext. Existing phone v1/v2 vectors and newly generated phone v2 ciphertext
  passed. This is the first public release, so no released-user ciphertext population
  exists for an upgrade-migration test.
- Protocol v2 remains unfrozen. Future prerelease changes may require re-pairing
  and recovery-based re-encryption. Any such release must identify affected versions
  and publish the recovery steps before upgrade; never silently reset or migrate
  uncertain replay state. There is no general downgrade support promise.
- Retain the independent recovery recipient and verify recovery before upgrading
  or deleting old state. Phone v2 ciphertext depends on its original pairing; tag
  ciphertext may be opened through another explicitly confirmed pairing to the
  same surviving phone identity. Neither restores lost hardware keys.

## Evidence and launch gates

The [tag evidence](tagged-recipient-evidence.md) records signed Android/iOS
acceptance, Windows TPM-to-Android Wi-Fi, independent recovery, mixed recipients
and Shine 2.0.3. The original iOS timeout failure and replacement-package retest
are retained separately. The 2026-08-29 independent source review predates the
macOS, iOS and native-tag additions; it is not a review of the complete beta source.

- [x] Define the candidate scope and compatibility limitations.
- [x] Prepare beta version metadata and Alpha/Beta release-channel support without
  weakening commit, signature, checksum or existing-release checks.
- [x] Prepare an exact [security review brief](beta-security-review-brief.md) for
  the post-2026-08-29 source delta; this is review input, not independent approval.
- [x] Review security-sensitive changes since the independent review, especially
  native HPKE/tag selection and the iOS authentication deadline. Record scope,
  reviewer, exact source and findings; local tests are not independent review. The
  [independent review](independent-security-review-2026-09-11.md) covered candidate
  `a41ba2e` and found four iOS issues. F2–F4 were independently closed at `9db0eb1`.
  Physical testing found the F1 remediation incomplete; follow-up `0305c0e` passed
  the exact signed-device disconnect case. A fresh independent review of `0305c0e`
  found no confirmable security defect introduced by the commit; its lack of hardware
  execution is covered by the separately recorded signed-device test.
- [x] Apply the Beta 1 distribution scope to tagged-recipient physical gates. Android
  storage replacement failure, uncertain
  post-rename directory-sync failure and clock rollback passed three instrumentation
  tests on a Samsung SM-F9660 running Android 16. The tests used the test APK's
  disposable `noBackupFilesDir`, exercised the production durable file operations,
  and did not mutate the installed beta application's state. iOS has no external
  distribution route in Beta 1, so iOS storage and clock tests are outside this
  release's advertised platform scope rather than skipped release gates.
- [x] Run local version, release-fixture, workflow, packaging, frontend and Rust
  checks; results are recorded below.
- [x] Complete Linux/Windows/macOS, mobile and interoperability CI against the final
  code-bearing candidate. CI skips are not hardware passes. Merged main commit
  `48f79b0` passed
  [CI run 34586353580](https://github.com/biulight/age-plugin-phone/actions/runs/34586353580).
- [x] Run the four-crate registry preflight against the final main commit using
  `crates-release.yml` in `preflight` mode; record the exact successful CI run.
  Commit `444c6f6` passed
  [preflight run 34579595719](https://github.com/biulight/age-plugin-phone/actions/runs/34579595719)
  without publishing.
- [x] Build and verify final signed beta artifacts; record commit, workflow attempt,
  package hashes and signer identities. Release run `34589811005` published the
  Windows test-signed ZIP and Android ARM64 APK from `c73b289`; its staging checks
  verified their signatures, hashes and provenance. Run a scoped exact-package smoke for
  setup/full fingerprint comparison, fresh repeated unwrap, cancellation/timeout,
  restart/replay rejection, in-place upgrade, old format and independent recovery
  on each advertised combination. Earlier alpha-version candidates are supporting
  evidence, not final-artifact passes.
- [x] Define installation routes for the first Beta: Windows/macOS source install
  and Android delivery. Public Windows signing is not a source-install gate; the
  optional ZIP must retain its test-signing label. iOS external onboarding is
  excluded until a separate usable distribution route exists. Technical-tester
  installation review begins after publication as Beta feedback, when the artifacts
  are available to install; it is not a first-publication gate.
- [x] Publication of the concrete `0.1.0-beta.1` artifacts and release notes was
  explicitly authorized by the project owner on 2026-09-11. Crates run `34589747627`
  published and production-installed all four packages; release run `34589811005`
  published the verified prerelease assets. Public downloads matched the published
  SHA-256 records.

## Exact-candidate acceptance — 2026-09-11

The signed Android ARM64 candidate from commit `a41ba2e` was produced by
[`acceptance_only` run 34558637700](https://github.com/biulight/age-plugin-phone/actions/runs/34558637700).
Its SHA-256 is
`04b18d3182a3b4137f0be91fa98cd52a1c2bfb6c63d655f6d5ee003df4a71f57`;
the device reported version `0.1.0-beta.1`, version code `1000`, ARM64 and APK
Signature Scheme v2. On the recorded Android device, two independent Developer
USB tag unwraps passed with fresh native verification. Native-prompt cancellation
failed without output, and the next freshly verified request succeeded.

PR [#13](https://github.com/biulight/age-plugin-phone/pull/13) added isolated Android
device tests for the remaining pairing-state durability boundaries. All three tests
passed on the connected Samsung SM-F9660 running Android 16: failure before atomic
replacement did not consume the request after reopening; directory-sync failure
after replacement preserved uncertain replay consumption after reopening; and a
clock rollback was rejected without changing the pairing or blocking a later request
at the durable clock. The tests used production Android file operations inside the
test APK's disposable private state. Merged main commit `48f79b0` passed
[CI run 34586353580](https://github.com/biulight/age-plugin-phone/actions/runs/34586353580).

The development-device iOS candidate has SHA-256
`c66a95580a20ddddcd1a003f8c47810a0ccf14b1e36629577ad386a5b5e2e6f3`.
The recorded iPhone accepted the in-place installation and reported short version
`0.1.0`, bundle version `0.1.0.6`. Three independent foreground-Wi-Fi tag unwraps
passed, native-prompt cancellation failed without output, and the next freshly
verified request succeeded. An earlier unobserved request failure is retained and
is not counted as a pass. Host `codesign --verify --deep --strict` returned
`CSSMERR_TP_NOT_TRUSTED`; device installation succeeded, but host trust verification
is not classified as passed.

Post-review testing against main commit `013a075` reproduced the F1 transport defect:
terminating the desktop process that owned the established TCP socket while Face ID
was pending left the prompt active. Follow-up `0305c0e` corrected EOF observation and
authentication-context ownership. Its signed development-device IPA has SHA-256
`891c605474d6e6b4aa143b0a63d672e1ff67d4e9014a8ddc1132dedb91b9d110`, short version
`0.1.0` and bundle version `0.1.0.5`. On the recorded iPhone, the same exact socket
termination made the Face ID prompt disappear automatically and produced no output.
After the app returned to the foreground, a new request required Face ID and matched
the 128-byte synthetic reference. Host certificate-chain trust remains unclassified
because `codesign --verify --deep --strict` returned `CSSMERR_TP_NOT_TRUSTED`.

This closes the candidate's basic signed-package install, repeated unwrap,
cancellation and recovery smoke. The broader signed-package gate remains open for
setup and full fingerprint comparison, timeout, restart/replay rejection and
independent recovery on every advertised combination. These are Beta follow-up rows,
not publication blockers for this first public release.

After publication, collect technical-tester feedback on the documented Windows,
macOS and Android installation routes. Treat findings as Beta feedback and fix
confirmed defects before a stable release.

## Local preparation checks — 2026-09-11

These checks cover the beta-closeout working tree based on `811b967`, with version
`0.1.0-beta.1`; they are not exact-final-commit CI or signed-package acceptance.
No protocol, key custody, pairing, transport or native authentication code changed
during this closeout preparation.

| Check | Result |
| --- | --- |
| Version consistency | Passed for workspace, internal dependencies, mobile and Tauri manifests |
| Candidate validator fixtures | Passed: Alpha/Beta accepted with matching manifests; unsupported channels, absent notes, mismatched commits and existing releases/tags rejected |
| Signed-artifact staging fixtures | Passed for beta filenames, provenance, CRLF signing records, tampering, mismatched source, duplicate assets and missing checksums |
| crates.io release control flow | 29 tests passed using Python 3.13 |
| `actionlint` | Passed |
| Four-package layout and archive checks | Passed |
| Cargo 1.88 isolated registry rehearsal | Minimal and full four-package archive/test/install flows passed; installed `0.1.0-beta.1` CLI and setup help ran successfully |
| Mobile TypeScript/Vite production build | Passed |
| Android native unit tests | Passed with the repository JDK 17 toolchain |
| Swift core tests | 11 tests passed, including HPKE/tag collision and authentication-deadline races |
| Rust fmt / locked workspace Clippy / locked workspace tests | Passed on macOS; ignored hardware/external-client checks remain unverified by this invocation |
| Local Markdown file references / `git diff --check` | Passed |

The first release-unit-test invocation used the host's Python 3.10 and failed to
import `tomllib`; rerunning with the documented Python 3.13 runtime passed all 29
tests. The first Android invocation used the host JDK 26 and failed during Gradle
configuration; the documented JDK 17 invocation passed. The first Swift invocation
could not write the sandboxed compiler cache; the same test command with normal
host cache access passed. Existing local Xcode project/Info.plist edits were
preserved; they are not part of this preparation's version changes. Regenerate and
verify native bundle versions when building final beta artifacts.

## Release mechanics

Use [Beta 1 notes](releases/v0.1.0-beta.1.md), the
[Windows Beta quick start](windows-beta-quickstart.md), the existing
[signing runbook](release-signing.md) and [crate preflight](crates-io-release.md).
The workflow/script filenames, protected environments and provenance marker keep
their historical `alpha` names to preserve configured credentials and rerun
identity; the validator accepts only numbered `alpha` or `beta` prereleases.
Windows ZIP names include the selected channel, e.g.
`age-plugin-phone-0.1.0-beta.1-windows-x64-beta-test-signed.zip`.
Do not dispatch publication merely to obtain acceptance artifacts: the existing
`acceptance_only` mode builds Android without creating a tag or release.

Windows/macOS valid replay-snapshot restoration remains the
[documented limitation](threat-model.md#desktop-replay-persistence-and-restore-boundary),
not a newly fixed issue or evidence of an end-to-end biometric bypass. Stronger
snapshot resistance, wider device families and general distribution remain later
work. No keys, plaintext, raw messages, QR contents or device serials belong in
release evidence.
