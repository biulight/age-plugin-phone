# Alpha candidate evidence

Status: active private-root test-signed candidate with partial physical evidence. QR/replay,
remaining lifecycle/invalidation, multi-phone, public-trust, and technical-user gates remain open.

## Candidate identity

| Field | Recorded value |
| --- | --- |
| Repository commit | `18a94c8d683457dcaa0aa50a485a999036f805df` |
| Windows executable SHA-256 | `836a0267d450dbe8a8b61d727711fee360d59443445e0d877f9653e98b36ed37` |
| Windows ZIP SHA-256 | `53c6c385b397051edf1dd2fdd20f9d3dd2215000dbfd4854fd1257ee93db13e3` |
| Android APK SHA-256 | `e1e2c68a896b36bbc36f4aaf1eae20c79a1c30e94cc830f0f4abb089d7e94a67` |
| Signing workflow run and attempt | `33295051535`, attempt 1 |
| Windows signature scope | Private Alpha root with trusted timestamp; signer certificate SHA-256 `d64e82d01bb5835b292a0abbf38759a2c36aaa7003af46809e6a5d730e239215`; public trust remains open |
| Android signing certificate | One v2 signer; certificate SHA-256 `9a3e5a00a0a363ca58bbe0abfa1bbc0e36cbdce58e314c0c0dbfa94baff1d58b` |

The final report must refer to one exact Windows/Android artifact pair. Never mix packages from
different commits, workflow runs, or attempts.

## Environment preflight

Read-only preflight on 2026-08-30 for the exact candidate observed Windows 11 Pro 23H2 x64 build
22631.6199; an Intel TPM with firmware `600.18.27.2176`, present, enabled, and ready; and Microsoft
Platform Crypto Provider support. The Android endpoint was a Samsung `SM-F9660` running Android 16
/ API 36 with security patch `2026-07-05`; the StrongBox feature flag reported true and the release
application reported version 0.0.1. Serial-free recounts before and after the physical runs observed
exactly one authorized online ADB device and no unauthorized or second device.

The client/tool baseline was age 1.3.1, rage 0.12.1, Shine 1.8.0, and platform-tools 37.0.1 (ADB
protocol 1.0.41). Rage was run from an isolated copy whose executable SHA-256 was
`69dc313f50df805429685fe016902fc869725aad7d77bc21170d9e9abd829bea`. Shine was run from an
isolated copy whose executable SHA-256 was
`794614e66c1a909cbfaee1a209fb90c69644019f3cf21b9e047fd8879aa0ca2d`; its required GNU
base64 8.32 executable SHA-256 was
`ef4877b2e3f929fa3e9671ff421fe64a8e50c89b3e11c2263d9b802604586e7c`. The planned Shine
1.7.0 baseline was superseded by the actually executed 1.8.0 release and is not claimed by this run.

## Rejected candidate history

Commit `4d2f46c02fd1fe42ce5816731f2806e8d2f3297c`, workflow run `33268115244`, attempt 1,
produced internally consistent test-signed Windows and Android artifacts. It was rejected during
physical pairing because the legacy identity-only locator filename collided with an existing
pairing to the same phone identity. The confirmed pairing left partial replay/TPM metadata and no
public identity stub; no scenario row below is closed by that run. The replacement implementation
uses identity-and-desktop locator names, preserves validated legacy reads and cleanup, and rolls
back newly created local state when the post-confirmation commit fails.

Commit `6650a5f723131ed97855337dd4fcd7f0585d8341`, workflow run `33270706277`, attempt 1,
produced another internally consistent signed pair. Its Windows executable SHA-256 was
`d97e96c2a4807833ec0e5ed78276c2f9060e525efee178ff9acf9336045eb673`; its Android APK SHA-256
was `4f203f45600d707ca1aa9d8ff228f3d922f84ca76bdc33b65eb68862c06edd8b`. Preflight on the
exact artifacts observed one authorized ADB device, a ready TPM, the Android StrongBox feature,
age 1.3.1, rage 0.12.1, and Shine 1.7.0. It was rejected before replacement pairing because the
minified Android release could not deserialize the lifecycle revocation handle and failed closed
with `malformed_request`. No phone pairing state was deleted and no scenario row below is closed by
that run. The replacement marks the public argument model with Tauri's release keep contract and
tests both that contract and Jackson deserialization.

Commit `ec5ebb83a65e5c66d35592a86643a4d750fdda2a`, workflow run `33271841635`, attempt 1,
produced signed artifacts with Windows executable SHA-256
`53b01e358a2df11fe4069fc83c80b2daf697c8d336f8aea45764e84d55878abe` and Android APK
SHA-256 `8149042af7a808b7b218777abc430785628ed1846afe2358004ca0580985ebcc`. Physical
testing confirmed the release lifecycle-argument repair, fresh pairing, repeated per-operation
biometrics, foreground/background Developer USB wake, age/rage/recovery digest equality,
cancellation, biometric mismatch then success, lock-screen failure, and authentication timeout.
It was nevertheless rejected when forced termination of the exact waiting `age.exe` left its one
ADB reverse rule after the plugin and guardian processes exited. The request produced no output and
the single rule was removed exactly before further work. No scenario row below is closed by this
rejected artifact pair. The replacement guardian breaks away from a client Job object and retries
removal of only the fixed rule for a bounded interval.

Commit `932156c37f1edf3f7e22554a964b902af5543db0`, workflow run `33275366275`, attempt 1,
produced signed artifacts with Windows executable SHA-256
`37b3bcac78fa772b91d5ef49cca604f656d2478933fc07193b3b74c4c971d91a` and Android APK
SHA-256 `98e9fa5bbeac381c477fa35bd7d785fc3cda69a86c04470c22a946f53a8c4a38`. Exact-package
preflight observed one authorized ADB device, StrongBox support, a ready TPM, and the pinned client
versions. Forced termination of the exact waiting `age.exe` produced no output, and the guardian
left no reverse rule or related process. The candidate was nevertheless rejected because the
phone's biometric authorization prompt remained visible after desktop process and transport
cleanup; it disappeared only later. No scenario row below is closed by this run. The replacement
binds the pending Android `CancellationSignal` to peer EOF, reset, timeout, or unexpected
post-request input without restoring the already consumed request.

Record the TPM manufacturer/firmware, Windows update revision, Android model/API/security patch,
StrongBox inspection, platform-tools release, artifact signatures, and approved certificate
identities only when the exact candidate is available.

## 2026-08-31 candidate continuation

The exact `18a94c8` Windows executable and installed Android candidate completed a new pairing with
no retained phone pairing and no active public Windows pairing, using full-fingerprint comparison.
Repeated phone decrypts and independent-recovery decrypts matched the synthetic input; each phone
unwrap required a fresh authorization.
Fixed payload-free wake continued to work, while malformed wake and malformed stream injections
failed without output, biometric prompt, reverse-rule residue, or a reusable authorization. A
subsequent valid request succeeded with a new biometric operation.

The newly created phone pairing was then revoked. A request from that revoked desktop failed without
plaintext or a biometric prompt, while the independent recovery recipient remained usable. The
normal fingerprint-confirmed Windows cleanup removed its public stub and bound private state. This
closes fresh pairing and malformed wake/stream for the recorded candidate and supplies partial
lifecycle evidence; it does not close identity deletion, uninstall/reinstall, key invalidation, or
multi-pairing isolation.

## Scenario results

| Scenario group | Status | Coarse result and non-sensitive evidence |
| --- | --- | --- |
| Artifact digest and signature verification | Passed | Exact commit, workflow attempt, three package digests, private-root Windows signer certificate, trusted timestamp, and single Android v2 signer matched the approved release evidence. Public Windows trust is not claimed. |
| Windows/TPM and Android/StrongBox capability inspection | Passed | Exact candidate preflight observed the versions and coarse hardware capability results above with one authorized device. Fresh phone-identity provisioning remains part of the open identity-deletion/uninstall lifecycle work. |
| Fresh pairing, restart, and standard age unwrap | Passed | A new pairing created entirely by `18a94c8` with no retained phone pairing or active public Windows pairing passed full-fingerprint comparison, standard unwrap, repeated fresh biometrics, and independent recovery; the recorded exact-candidate restart/cold-start paths remained valid. |
| Developer USB cold/foreground/background/repeated wake | Passed | Foreground, background, force-stopped cold start, and repeated requests opened the native controller without **Approve USB**; every successful unwrap required a new biometric operation and left zero reverse rules/processes. |
| Cancellation, mismatch, lock, timeout, malformed wake/stream | Passed | Cancel, one unrecognized scan followed by success, locked/dozing rejection, the 60-second phone-authentication timeout, malformed wake, and malformed stream injection passed without output or residue; later valid requests required new biometrics. |
| Cable, ADB daemon, process exit, Ctrl-C, and reverse cleanup | Passed | Cable removal and ADB daemon restart dismissed the phone prompt; forced exact `age.exe` termination and native-console Ctrl-C produced no output. Every recovery request required new biometrics. Formal Ctrl-C audit reported candidate digest match, no output, zero reverse rules, and zero plugin processes. |
| QR fallback and old-response replay after desktop restart | Pending | This Windows host has no camera. No QR request was started and the prepared slot remained empty; attach a UVC camera before executing the exact-package fallback and retained-response replay. ADB screenshots or payload injection are not substitutes. |
| age 1.3.1 multi-file phone and recovery paths | Passed | Native and rage-cross decrypts succeeded with distinct fresh biometrics. Independent recovery succeeded without the phone. Synthetic input SHA-256 values were `5c8b35ff27fe689c46768de65071ab6d15824acf5889618ad391701252e09011` and `b30241823e3ecc1d738752ad0d7e88600aa2677feb6724ef5cb33bb13f083673`. |
| rage 0.12.1 phone and recovery paths | Passed | Native and age-cross decrypts succeeded; all four phone/client combinations and all four independent-recovery combinations matched the two synthetic input digests with zero reverse residue. |
| Shine 1.8.0 encrypt, decrypt, seal, runtime decrypt, and recovery | Passed | Direct encrypt/decrypt and workspace seal/`env run` passed with two fresh phone authentications. Plaintext was absent after sealing. Independent recovery decrypted both the direct ciphertext and a copied sealed workspace without invoking the phone; runtime SHA-256 was `cfb0b37fe6e8592f4aba17979fba91b81bf3660589b701e213429ac6ae33c4be`. |
| Revocation, local cleanup, restart, deletion, uninstall/reinstall | Partial | One freshly created exact-candidate pairing was revoked; a later request failed without output or biometric prompt, recovery remained usable, and normal fingerprint-confirmed Windows cleanup removed that pairing's local state. Identity deletion and uninstall/reinstall remain pending. |
| TPM/StrongBox invalidation and corrupt/private state failures | Pending | |
| Second StrongBox device family and wrong paired physical phone | Blocked | Second device unavailable |
| Publicly trusted Windows signing | Blocked | Free open-source signing program pending |
| Limited technical-user Alpha | Blocked | Begins only after preceding required gates and protocol freeze |

Every negative case passes only if it produces no plaintext or partial output, no reusable
authorization, no recreated replay scope, no unrelated pairing damage, and no ADB reverse residue.
A recovery attempt after an interrupted or consumed request must use a new protocol request and a
new biometric operation.

## Implementation verification (not candidate evidence)

On 2026-08-30, exact commit `18a94c8d683457dcaa0aa50a485a999036f805df` passed the mandatory
Rust formatting, workspace Clippy, and workspace test commands; Android Kotlin unit tests; and the
TypeScript build. CI workflow `33294937183` completed successfully, followed by the signed-package
workflow recorded above. A disposable unsigned Windows build was used only to diagnose a test-
fixture ACL issue and is excluded from every formal result. Failed harness attempts caused by that
ACL, a missing rage PATH entry, a missing base64 PATH entry, or mixed stdout/stderr were discarded;
their partial evidence slots were not reused.

On 2026-08-31, an unsigned Windows-native diagnostic based on `af81a19` plus the orphan-cleanup
working tree passed format, desktop-package Clippy, and all seven native desktop-cleanup tests. It
then removed the validated legacy orphan locator and its bound private state after exact fingerprint
confirmation. A final non-sensitive audit observed zero phone pairings, locators, public stubs,
pairing states/replay locks, cleanup journals, fixed ADB reverse rules, and related processes; the
expected global cleanup lock remained. The diagnostic executable and temporary build inputs were
deleted. This is implementation validation only and is excluded from the signed-candidate scenario
results above.

## Evidence restrictions

Record only exact versions, public capability results, artifact and synthetic-output digests,
coarse error categories, reverse-rule absence, dates, and pass/fail outcomes. Do not record private
or public key aliases, raw identifiers, device serials, caller labels, private paths, protocol
messages, QR contents, recipient stanza bodies, file keys, recovery private material, or plaintext.
