# Windows and Android Alpha matrix

Status: active candidate `35bbb60` has verified test-signed packages and awaits physical testing.
The preceding `18a94c8` candidate closed fresh pairing, malformed Developer USB, and the primary
one-phone interoperability paths, but those results are historical and do not transfer to the
active artifact pair. QR/replay, remaining lifecycle/invalidation, multi-phone, public-signing, and
technical-user release gates remain open.

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
| Desktop OS | Windows 11 client, x64; Windows Server, Windows 10, ARM64, virtualized/software TPM, and compatibility modes are rejected | Exact candidate completed the recorded runs on Windows 11 Pro 23H2 x64 build 22631.6199 | Required; broader Windows 11 update coverage pending |
| Desktop custody | Enabled and ready TPM 2.0; Microsoft Platform Crypto Provider; distinct non-exportable P-256 ECDSA and ECDH keys; protected `%LOCALAPPDATA%` state | Intel TPM firmware `600.18.27.2176` was present, enabled, and ready; native CNG/storage tests, fresh exact-candidate pairing, and unwraps passed | Required; recorded device passed, broader coverage pending |
| Phone OS and custody | Android device whose live key inspection proves StrongBox P-256 ECDH, auth-per-use `BIOMETRIC_STRONG`, StrongBox P-256 signing, and the exact invalidation policy | Samsung `SM-F9660`, Android 16 / API 36, security patch `2026-07-05`, passed fresh exact-APK pairing and per-operation authentication | Required; recorded device passed, at least one additional StrongBox family pending |
| Default transport | Developer USB through an explicitly selected online ADB device and `adb reverse`; USB debugging and Android ADB authorization are prerequisites, not authentication | Platform-tools 37.0.1 passed exact-package cold/background/repeated wake and interruption cleanup with one authorized device | Required; release package must pin and test an exact platform-tools range |
| Fallback transport | Native QR with the same pairing and protocol; no security downgrade and no ADB state | Owner-only exploratory pairing, standard `age` unwrap, cancellation, timeout, and old-response rejection passed with a UGREEN Camera 2K; the run did not use an exact signed candidate | Required; rerun fallback/replay against one exact candidate pair |
| age client | Released reference `age` using standard `recipient-v1` and `identity-v1` plugin state machines | `age` 1.3.1 passed exact-candidate native and rage-cross phone decrypt plus independent recovery on two synthetic files | Required; one-phone/multi-file gate passed |
| rage client | Released `rage` with the same standard plugin boundary and no client-specific protocol path | `rage` 0.12.1 passed native and age-cross phone decrypt plus independent recovery on the exact candidate | Required; one-phone/multi-file gate passed |
| Shine | Existing `age_identity` and `age_recipients` configuration only; no Shine dependency, RPC, URI, environment interpretation, or ciphertext change in this repository | Shine 1.8.0 passed direct encrypt/decrypt, workspace seal, `env run`, and independent recovery with the exact candidate | Required; passed for the recorded version |
| Recovery | Every important Alpha dataset has the phone recipient plus a verified independent recovery recipient as defined by ADR 0017 | age/rage cross-client and Shine sealed-workspace recovery matched synthetic digests without the phone or plugin; recovery remained usable after revoking the fresh pairing | Required; fresh-pairing recovery passed, full replacement/re-encryption retirement remains pending |
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
explicitly name `35bbb60`. Treat every physical row as pending for the active candidate until it is
rerun with that exact package pair.

| Scenario | Portable gate | Physical gate | Current state |
| --- | --- | --- | --- |
| Fresh identity and pairing, exact transcript comparison, restart, then standard age unwrap | Required | Required | The fresh-pairing portion passed: a new `18a94c8` pairing with no retained phone pairing or active public Windows pairing passed full-fingerprint comparison, standard unwrap, repeated fresh biometrics, and independent recovery; recorded exact-candidate restart/cold-start paths remained valid. Fresh phone-identity provisioning remains pending with the identity-deletion/uninstall lifecycle row |
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
