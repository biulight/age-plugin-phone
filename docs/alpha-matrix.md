# Windows and Android Alpha matrix

Status: Milestone 6 repository gates are partially implemented; release gates are not yet complete.

This matrix separates the supported Alpha product from interoperability evidence. A row marked
"required" is a release gate, not a promise that every version in that family is supported. The
release candidate must record exact OS, firmware, tool, application, and commit versions for every
physical run.

## Supported product boundary

| Area | Alpha requirement | Current evidence | Gate status |
| --- | --- | --- | --- |
| Desktop OS | Windows 11 client, x64; Windows Server, Windows 10, ARM64, virtualized/software TPM, and compatibility modes are rejected | Windows 11 x64 build 22631 completed capability, pairing, unwrap, failure, and cleanup runs | Required; broader Windows 11 update coverage pending |
| Desktop custody | Enabled and ready TPM 2.0; Microsoft Platform Crypto Provider; distinct non-exportable P-256 ECDSA and ECDH keys; protected `%LOCALAPPDATA%` state | Native CNG and storage tests plus physical pairing/unwrap passed on the designated host | Required |
| Phone OS and custody | Android device whose live key inspection proves StrongBox P-256 ECDH, auth-per-use `BIOMETRIC_STRONG`, StrongBox P-256 signing, and the exact invalidation policy | Samsung `SM-F9660`, Android 16 / API 36 passed the implemented device runs | Required; at least one additional StrongBox device family pending |
| Default transport | Developer USB through an explicitly selected online ADB device and `adb reverse`; USB debugging and Android ADB authorization are prerequisites, not authentication | Platform-tools 37.0.1 passed the recorded Windows run | Required; release package must pin and test an exact platform-tools range |
| Fallback transport | Native QR with the same pairing and protocol; no security downgrade and no ADB state | Physical authenticated QR fallback passed; desktop camera UX remains device-dependent | Required |
| age client | Released reference `age` using standard `recipient-v1` and `identity-v1` plugin state machines | `age` 1.3.1 completed the recorded Windows 11 physical unwrap; Rust integration uses `age-core` 0.11.0 and `age-plugin` 0.6.1 | Required; release candidate retest pending |
| rage client | Released `rage` with the same standard plugin boundary and no client-specific protocol path | No committed physical Alpha evidence yet | Required; blocked until tested |
| Shine | Existing `age_identity` and `age_recipients` configuration only; no Shine dependency, RPC, URI, environment interpretation, or ciphertext change in this repository | Architecture boundary is defined; end-to-end Shine encrypt/decrypt/seal validation is not committed | Required; blocked until tested |
| Recovery | Every important Alpha dataset has the phone recipient plus a verified independent recovery recipient as defined by ADR 0017 | Threat model and lifecycle are defined; end-to-end recovery/re-encryption run is pending | Required; blocked until tested |
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

| Scenario | Portable gate | Physical gate | Current state |
| --- | --- | --- | --- |
| Fresh identity and pairing, exact transcript comparison, restart, then standard age unwrap | Required | Required | Passed on designated Windows/Android baseline |
| Automatic Developer USB unwrap wake on cold start, foreground, background, and repeated requests | Required | Required | Fixed payload-free action and one-shot native dispatch have portable coverage; packaged physical gate pending |
| Encrypt and decrypt with released reference age; multiple files and multiple phone identities | Required | Required | age 1.3.1 production-plugin encryption and independent recovery pass in CI; packaged physical phone unwrap matrix pending |
| Encrypt and decrypt with released rage | Required | Required | rage 0.12.1 cross-client production-plugin encryption/recovery pass in CI; packaged physical phone unwrap pending |
| Shine encrypt, decrypt, seal, and multi-recipient recovery through ordinary age configuration | Required | Required | Pending |
| Independent recovery decrypt, new-phone/new-pairing encryption, byte comparison, and retirement of old ciphertext | Required | Required | Pending |
| Wrong paired physical phone | Required | Required | Portable coverage exists; physical gate pending from Milestone 4 |
| Captured request and injected response replay after restart | Required | Required | Portable durable-replay coverage exists; injected physical response gate pending from Milestone 4 |
| Cancellation, biometric mismatch then success, lock screen, timeout, no response, and malformed stream | Required | Required | Passed on designated baseline; rerun packaged artifacts |
| Cable removal/reconnect, ADB daemon restart, nonexistent serial, unauthorized/offline device, multiple online devices, and device switch | Required | Required | Passed applicable baseline cases; unauthorized/offline packaged rerun required |
| Existing/stale reverse rule, Ctrl-C, normal exit, forced desktop process exit, and exact rule cleanup | Required | Required | Passed on designated baseline; rerun packaged artifacts |
| QR fallback after ADB failure with a fresh authorization and no reverse residue | Required | Required | Passed on designated baseline; rerun packaged artifacts |
| Desktop restart, phone app restart/background/process death, malformed wake action, and replay persistence | Required | Required | Portable coverage exists; complete packaged lifecycle run pending |
| Revoke one desktop while another pairing remains usable | Required | Required | Journaled native revocation and portable isolation/restart tests implemented; physical gate pending |
| TPM signing/selection invalidation and StrongBox identity/signing invalidation | Required | Required | Fail-closed primitives exist; lifecycle implementation and physical matrix pending |
| Identity deletion, Android uninstall/reinstall, backup exclusion, and explicit desktop cleanup | Required | Required | Journaled phone identity deletion and backup exclusion implemented; uninstall/reinstall, desktop cleanup, and physical gate pending |
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
matrix (or vice versa).
