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
  passed; retained pre-upgrade ciphertext migration remains unverified.
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
- [ ] Review security-sensitive changes since the independent review, especially
  native HPKE/tag selection and the iOS authentication deadline. Record scope,
  reviewer, exact source and findings; local tests are not independent review.
- [ ] Close the mandatory tagged-recipient physical gaps: Android/iOS storage
  persistence failure and clock rollback; isolated iOS transport disconnect;
  retained old-ciphertext upgrade/re-encryption. Use disposable isolated state and
  preserve existing pairings. If evidence cannot be obtained, explicitly resolve
  the PRD release requirement before advertising the affected capability; do not
  silently waive it because this version is beta.
- [x] Run local version, release-fixture, workflow, packaging, frontend and Rust
  checks; results are recorded below.
- [ ] Complete Linux/Windows/macOS, mobile and interoperability CI against the final
  candidate. CI skips are not hardware passes.
- [ ] Run the four-crate registry preflight against the final main commit using
  `crates-release.yml` in `preflight` mode; record the exact successful CI run.
- [ ] Build and verify final signed beta artifacts; record commit, workflow attempt,
  package hashes and signer identities. Run a scoped exact-package smoke for
  setup/full fingerprint comparison, fresh repeated unwrap, cancellation/timeout,
  restart/replay rejection, in-place upgrade, old format and independent recovery
  on each advertised combination. Earlier alpha-version candidates are supporting
  evidence, not final-artifact passes.
- [ ] Review installation instructions with a technical tester and confirm the
  Windows/macOS source-install and Android delivery routes. Public Windows signing
  is not a source-install gate; the optional ZIP must retain its test-signing label.
  iOS external onboarding is excluded until a separate usable distribution route
  exists.
- [ ] Obtain publication authorization for the concrete artifacts and release
  notes, then publish and verify downloaded assets and registry installation.

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
