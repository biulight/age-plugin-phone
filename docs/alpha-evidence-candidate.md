# Alpha candidate evidence

Status: candidate commit and signed packages pending. No physical Alpha gate is closed by this
template or by portable/native unit tests.

## Candidate identity

| Field | Recorded value |
| --- | --- |
| Repository commit | Pending immutable commit |
| Windows artifact SHA-256 | Pending |
| Android artifact SHA-256 | Pending |
| Signing workflow run and attempt | Pending |
| Windows signature scope | Pending; test-trusted until public signing is obtained |
| Android signing certificate fingerprint | Pending approved fingerprint comparison |

The final report must refer to one exact Windows/Android artifact pair. Never mix packages from
different commits, workflow runs, or attempts.

## Environment preflight

Read-only preflight on 2026-08-30 observed Windows 11 Pro build 22631 with TPM present, enabled, and
ready; age 1.3.1; Shine 1.7.0; and ADB 1.0.41. The Android device was initially offline; a later
serial-free recount observed exactly one authorized online device and no unauthorized or offline
devices; the platform StrongBox feature flag reported true, without performing live candidate key
inspection. Rage was not installed. These observations are not physical scenario passes. Before
candidate execution, install the pinned rage 0.12.1 release and repeat the single-device check.

The pinned rage 0.12.1 Windows x64 package was subsequently installed after verifying its published
SHA-256. The single-device and StrongBox feature checks must still be repeated for the next exact
candidate.

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

Record the TPM manufacturer/firmware, Windows update revision, Android model/API/security patch,
StrongBox inspection, platform-tools release, artifact signatures, and approved certificate
identities only when the exact candidate is available.

## Scenario results

| Scenario group | Status | Coarse result and non-sensitive evidence |
| --- | --- | --- |
| Artifact digest and signature verification | Pending | |
| Windows/TPM and Android/StrongBox capability inspection | Pending | |
| Fresh pairing, restart, and standard age unwrap | Pending | |
| Developer USB cold/foreground/background/repeated wake | Pending | |
| Cancellation, mismatch, lock, timeout, malformed wake/stream | Pending | |
| Cable, ADB daemon, process exit, Ctrl-C, and reverse cleanup | Pending | |
| QR fallback and old-response replay after desktop restart | Pending | |
| age 1.3.1 multi-file phone and recovery paths | Pending | |
| rage 0.12.1 phone and recovery paths | Pending | |
| Shine 1.7.0 seal, runtime decrypt, and recovery | Pending | |
| Revocation, local cleanup, restart, deletion, uninstall/reinstall | Pending | |
| TPM/StrongBox invalidation and corrupt/private state failures | Pending | |
| Second StrongBox device family and wrong paired physical phone | Blocked | Second device unavailable |
| Publicly trusted Windows signing | Blocked | Free open-source signing program pending |
| Limited technical-user Alpha | Blocked | Begins only after preceding required gates and protocol freeze |

Every negative case passes only if it produces no plaintext or partial output, no reusable
authorization, no recreated replay scope, no unrelated pairing damage, and no ADB reverse residue.
A recovery attempt after an interrupted or consumed request must use a new protocol request and a
new biometric operation.

## Implementation verification (not candidate evidence)

On 2026-08-30, the working tree passed the mandatory Rust formatting, workspace Clippy, and
workspace test commands; Android Kotlin unit tests; and the TypeScript build. A disposable copy on
the Windows host passed a locked release build, the new command help smoke test, Windows-native
desktop cleanup/storage/CNG tests against the ready TPM, and targeted Clippy. These results verify
the implementation but do not identify, sign, or qualify an Alpha candidate.

## Evidence restrictions

Record only exact versions, public capability results, artifact and synthetic-output digests,
coarse error categories, reverse-rule absence, dates, and pass/fail outcomes. Do not record private
or public key aliases, raw identifiers, device serials, caller labels, private paths, protocol
messages, QR contents, recipient stanza bodies, file keys, recovery private material, or plaintext.
