# Windows and Android Alpha matrix

Status: active candidate `be1e85e` has verified test-signed packages and has passed the minimal
single-device publication regression for the `v0.1.0-alpha.1` developer prerelease: fresh pairing,
one Developer USB unwrap, independent recovery, one foreground Wi-Fi unwrap, and foreground
lifecycle termination/resume. The preceding `18a94c8` candidate retains broader historical
one-phone interoperability evidence, but those results do not transfer to the active artifact
pair. QR/replay, remaining lifecycle/invalidation, multi-phone, public-signing, and technical-user
release gates remain open.

Additional scoped owner-only validation of the exact `v0.1.0-alpha.3` packages is recorded in
[`windows-acceptance-2026-09-05.md`](windows-acceptance-2026-09-05.md). It covers managed setup,
daily age/Shine use, interruption recovery, pairing/identity lifecycle, and an exact alpha.2-to-alpha.3
upgrade. Wi-Fi required a scoped firewall allowance and retains a discovery reliability limitation.
The historical baseline rows below are not automatically closed by that narrower run; consult its
per-scenario observations and explicit limits before reusing the evidence.

The active deployment posture is an owner-only technical preview. The repository owner may continue
single-device synthetic-data evaluation without claiming that this matrix is complete. UVC-camera
QR/replay, second-family StrongBox, multi-phone, public-signing, and external technical-user rows
are deferred, not passed. See [`owner-only-preview.md`](owner-only-preview.md). Every row remains a
gate before broader use or a public Alpha claim.

This matrix separates the supported Alpha product from interoperability evidence. A row marked
"required" is a release gate, not a promise that every version in that family is supported. The
release candidate must record exact OS, firmware, tool, application, and commit versions for every
physical run.

## Supported product boundary

| Area | Alpha requirement | Current evidence | Gate status |
| --- | --- | --- | --- |
| Desktop OS | Windows 11 client, x64; Windows Server, Windows 10, ARM64, virtualized/software TPM, and compatibility modes are rejected | `be1e85e` completed the minimal regression on Windows 11 Pro 23H2 x64 build 22631.6199 | Required; broader Windows 11 update coverage pending |
| Desktop custody | Enabled and ready TPM 2.0; Microsoft Platform Crypto Provider; distinct non-exportable P-256 ECDSA and ECDH keys; protected `%LOCALAPPDATA%` state | `be1e85e` observed a ready TPM 2.0, Microsoft Platform Crypto Provider support, fresh isolated TPM state, pairing, and two unwraps; the Intel firmware record remains historical | Required; recorded device passed the minimal regression, broader coverage pending |
| Phone OS and custody | Android device whose live key inspection proves StrongBox P-256 ECDH, auth-per-use `BIOMETRIC_STRONG`, StrongBox P-256 signing, and the exact invalidation policy | Exact `be1e85e` APK on Samsung `SM-F9660`, Android 16 / API 36, security patch `2026-07-05`, passed fresh StrongBox identity provisioning, pairing, and two fresh biometric operations | Required; recorded device passed, at least one additional StrongBox family pending |
| Default transport | Developer USB through an explicitly selected online ADB device and `adb reverse`; USB debugging and Android ADB authorization are prerequisites, not authentication | Platform-tools 37.0.1 passed one exact-`be1e85e` Developer USB unwrap with a fresh phone biometric and zero final reverse-rule residue; the broader cold/background/repeated evidence remains historical | Required; broader exact-package lifecycle permutations pending |
| Experimental transport | Explicit, default-off foreground Wi-Fi unwrap to one numeric private IPv4 endpoint on port `47140` | Exact `be1e85e` packages passed one fresh-biometric unwrap, foreground/background close and resume, final pause, and zero ADB reverse residue | Owner-only developer-prerelease evidence; not a public-Alpha transport gate |
| Fallback transport | Native QR with the same pairing and protocol; no security downgrade and no ADB state | Owner-only exploratory pairing, standard `age` unwrap, cancellation, timeout, and old-response rejection passed with a UGREEN Camera 2K; the run did not use an exact signed candidate | Required; rerun fallback/replay against one exact candidate pair |
| age client | Released reference `age` using standard `recipient-v1` and `identity-v1` plugin state machines | `age` 1.3.1 passed one exact-`be1e85e` phone decrypt plus independent recovery; broader two-file and cross-client work remains on `18a94c8` | Required; active-candidate multi-file and multiple-identity work pending |
| rage client | Released `rage` with the same standard plugin boundary and no client-specific protocol path | `rage` 0.12.1 passed native and age-cross phone decrypt plus independent recovery on historical candidate `18a94c8` | Required; active-candidate physical rerun pending |
| Shine | Existing `age_identity` and `age_recipients` configuration only; no Shine dependency, RPC, URI, environment interpretation, or ciphertext change in this repository | Shine 1.8.0 passed direct encrypt/decrypt, workspace seal, `env run`, and independent recovery on historical candidate `18a94c8` | Required; active-candidate physical rerun pending |
| Recovery | Every important Alpha dataset has the phone recipient plus a verified independent recovery recipient as defined by ADR 0017 | `be1e85e` independently recovered the publication-regression ciphertext without the phone; broader cross-client, Shine, revocation, and retirement evidence remains historical | Required; minimal recovery passed, replacement/re-encryption retirement remains pending |
| macOS | Build and protocol interoperability validation only; not packaged or supported as the Alpha desktop product | Physical Android pairing and reference-age unwrap over QR/ADB were previously validated from macOS | Informational; not an Alpha release gate |

Passing on one device never substitutes for runtime capability inspection. A phone model allowlist,
ADB serial, USB connection, desktop label, or OS-reported biometric success is not a cryptographic
trust input.

Developer USB is the default transport only for this technical Alpha and remains a required Alpha
matrix row. This matrix does not select it as a general-availability default: after a production
convenience transport is validated, ADB is intended to remain a development, diagnostics, and
recovery path. Any BLE, Wi-Fi, or dedicated non-ADB USB transport must carry the same authenticated
protocol and must pass its own physical matrix before it can replace an Alpha gate.

## Required scenario matrix

The release candidate must run the following scenarios against the exact packaged desktop and
Android artifacts. "Portable" means deterministic Rust/Kotlin coverage; "physical" means evidence
from the supported Windows/Android pair.

Current-state entries below describe the preceding `18a94c8` physical baseline unless they
explicitly name `be1e85e`. Only the named minimal publication scenarios transfer to the active
candidate; every other physical row remains pending until rerun with that exact package pair.

| Scenario | Portable gate | Physical gate | Current state |
| --- | --- | --- | --- |
| Managed `setup` with automatic create-only paths, full fingerprint comparison, interruption resume/cleanup, and no overwrite | Required | Required | Portable journal, CLI, preflight, and fail-closed activation coverage implemented; exact packaged Windows/Android physical run pending |
| Fresh identity and pairing, exact transcript comparison, restart, then standard age unwrap | Required | Required | `be1e85e` passed fresh StrongBox identity provisioning, isolated TPM state, complete-fingerprint Developer USB pairing, one fresh-biometric standard unwrap, and independent recovery. Restart and broader lifecycle permutations remain pending for this candidate |
| Automatic Developer USB unwrap wake on cold start, foreground, background, and repeated requests | Required | Required | Exact packaged artifacts passed all four wake modes without manual **Approve USB**; each unwrap required fresh biometrics |
| Encrypt and decrypt with released reference age; multiple files and multiple phone identities | Required | Required | age 1.3.1 passed two-file native/cross-client phone and recovery paths; multiple phone identities remain open |
| Encrypt and decrypt with released rage | Required | Required | rage 0.12.1 passed native/cross-client phone and recovery paths on two synthetic files |
| Shine encrypt, decrypt, seal, and multi-recipient recovery through ordinary age configuration | Required | Required | Shine 1.8.0 exact-candidate phone and independent-recovery paths passed; sealed source no longer contained synthetic plaintext |
| Independent recovery decrypt, new-phone/new-pairing encryption, byte comparison, and retirement of old ciphertext | Required | Required | Independent recovery and byte comparison passed; fresh pairing/re-encryption and retirement remain pending |
| Wrong paired physical phone | Required | Required | Portable coverage exists; physical gate pending from Milestone 4 |
| Captured request and injected response replay after restart | Required | Required | Portable durable-replay coverage exists. An owner-only physical old-response rejection passed with a UGREEN Camera 2K, but the exact signed-candidate and post-restart gate remains pending |
| Cancellation, biometric mismatch then success, lock screen, timeout, no response, and malformed stream | Required | Required | Exact package passed cancellation, mismatch-then-success, lock, timeout, malformed wake, and malformed stream without plaintext, reusable authorization, reverse residue, or a biometric prompt for malformed input |
| Cable removal/reconnect, ADB daemon restart, nonexistent serial, unauthorized/offline device, multiple online devices, and device switch | Required | Required | Exact package passed cable and daemon interruption/recovery; remaining device-state permutations retain their earlier baseline evidence and require exact-package rerun where injectable |
| Existing/stale reverse rule, Ctrl-C, normal exit, forced desktop process exit, and exact rule cleanup | Required | Required | Exact package passed forced exit and native-console Ctrl-C with no output/residue; fresh recovery requests required biometrics and matched digests |
| QR fallback after ADB failure with a fresh authorization and no reverse residue | Required | Required | Owner-only QR pairing and standard `age` unwrap passed with a UGREEN Camera 2K; exact-package ADB-failure fallback and reverse-residue evidence remains pending |
| Desktop restart, phone app restart/background/process death, malformed wake action, and replay persistence | Required | Required | Exact package passed desktop/ADB/app interruption, background/cold wake, and malformed wake; captured-response replay after restart remains pending with the QR/replay row |
| Revoke one desktop while another pairing remains usable | Required | Required | Journaled native revocation and portable isolation/restart tests implemented; physical gate pending |
| TPM signing/selection invalidation and StrongBox identity/signing invalidation | Required | Required | Fail-closed primitives exist; lifecycle implementation and physical matrix pending |
| Identity deletion, Android uninstall/reinstall, backup exclusion, and explicit desktop cleanup | Required | Required | Exact-candidate phone revocation and normal Windows cleanup passed. The exact-locator orphan recovery path passed Windows-native tests and unsigned physical implementation validation; packaged identity deletion, uninstall/reinstall, and invalidation remain pending |
| Corrupt, missing, copied, insecure, full, or concurrently opened security state | Required | Required where injectable | Portable/native storage coverage exists; packaged lifecycle rerun pending |

Every negative scenario passes only when it produces no plaintext or partial output, no reusable
authorization, no silently recreated state, no unrelated pairing damage, and no ADB reverse residue.
A recovery attempt following a consumed or interrupted request must create a new request and require
a new phone biometric operation.

## Version recording

Each release-candidate result must record:

- immutable repository commit and signed artifact digests;
- Windows edition, architecture, build, update revision, TPM manufacturer/firmware and readiness,
  and Platform Crypto Provider capability result;
- Android manufacturer/model, OS/API level, security patch, StrongBox/Keystore inspection result,
  biometric class, and application version;
- platform-tools/ADB, reference age, rage, and Shine versions;
- transport, camera where applicable, scenario identifier, date, and pass/fail; and
- non-sensitive cleanup evidence and recovered-output digest where the input is synthetic.

Reports must not contain private/public key aliases, raw protocol messages, QR contents, recipient
stanza bodies, file keys, plaintext, absolute private-state paths, or caller-supplied labels. Device
serials should be redacted or replaced by run-local labels.

## Release decision

The Alpha gate remains closed while any required row or scenario is pending, while an independent
review finding is unresolved, or while protocol version 2 is still an unfrozen experimental format.
macOS success cannot waive a Windows requirement, and QR success cannot waive the Developer USB
matrix (or vice versa). Owner-only operation does not change this public-Alpha decision.
