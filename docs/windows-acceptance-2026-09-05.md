# Windows owner-preview acceptance — 2026-09-05

Status: this scoped owner-assisted run is complete. Managed setup, USB daily use and interruption
recovery, phone lifecycle/recovery, and the exact alpha.2-to-alpha.3 upgrade were exercised on one
Windows/Android pair. Wi-Fi functional paths passed with a temporary scoped firewall allowance;
default-environment discovery and one additional discovery failure remain limitations. Unexecuted
broader matrix cases remain pending. This does not close the public-Alpha matrix.

## Outcome by requested area

| Area | Outcome |
| --- | --- |
| Managed setup | Passed the exercised fresh, create-only, storage-conflict/resume and unconfirmed-interruption/cleanup paths. |
| Daily workflow | Passed standard age and Shine direct/workspace use, repeated approval, cancellation, cold app start, timeout, forced age exit, cable interruption and ADB restart, followed by fresh successful requests. |
| Wi-Fi | Conditional functional pass: pairing, unwrap, auto with ADB unavailable, background interruption and pause/re-enable were exercised. An exact-EXE inbound discovery rule was needed on this host; a further failed discovery attempt is retained rather than erased by the later successful retry. |
| Lifecycle and upgrade | Passed pairing revocation/isolation, official cleanup, independent recovery/re-encryption and old-ciphertext retirement, explicit identity deletion, uninstall/reinstall failure of the old identity, and exact alpha.2-to-alpha.3 in-place upgrade. |

## Candidate and environment

- Release: `v0.1.0-alpha.3`, commit `78ae7acd9c7a771bbcbd56f886df98fa8cf24c30`.
- Signing workflow: `33788218198`, attempt `1`.
- Windows EXE SHA-256: `92cc3a45427806018295271507af8a85b9b475324f059d4fa89f8622e4d5bf43`.
- Windows ZIP SHA-256: `de5b643a9d57ae49ed98ed9fe8e87707066d868efcb71caea88a9744524472d8`.
- Android APK SHA-256: `1ff715779c698065f5dfb9504adefd7bda89373b279bcc88139cde9c6f162cf8`.
- All three downloaded artifact digests matched the release provenance. Windows signer
  SHA-256 matched `d64e82d01bb5835b292a0abbf38759a2c36aaa7003af46809e6a5d730e239215`;
  a timestamp certificate was present. Windows reported `UnknownError` for the private-root
  signature. This is not a new independent custom-root chain validation; that result is supplied
  by the release evidence. The APK installed successfully and reported `0.1.0-alpha.3`.
- Windows x64 build 22631; read-only probe reported supported client, TPM 2.0 and Microsoft
  Platform Crypto Provider. Android Samsung `SM-F9660`, Android 16, patch `2026-07-05`.
- Reference age `1.3.1`, ADB platform-tools `37.0.1`, installed Shine `2.0.0-rc.2` (`2c78a55de`).
- Exactly one authorized ADB device; initial reverse-rule count zero.
- Existing PATH executable was unsigned `alpha.2`; the existing phone application was the
  separately scoped Wi-Fi PoC. Neither is used as candidate evidence. The normal release APK
  was newly installed alongside the PoC; desktop acceptance uses an isolated configuration root.

## Observations

| Case | Result | Evidence / limit |
| --- | --- | --- |
| USB setup with stdin EOF | Rejected; harness attempt excluded from success evidence | First SSH session lacked an interactive stdin. Setup reached full-fingerprint comparison, rejected EOF, exited 1 and reported rollback. Follow-up found no setup journal, zero public stubs and zero ADB reverse rules. Owner reported removing the corresponding phone pairing. |
| Resume without a journal | Passed negative check | Exit 1, missing-journal error; no inferred or recreated setup. |
| Reserved BLE setup route | Passed negative check | Exit 1, transport-not-implemented error. |
| Interactive fresh managed USB setup | Passed | Owner confirmed full fingerprint on phone; desktop confirmation then submitted. Exit 0, schema-1 JSON and existing stub validated, setup journal absent. |
| Independent recovery | Passed | Standard age recovery through a disposable independent recipient matched the synthetic digest without phone authorization. |
| Two consecutive USB phone decrypts | Passed | Both outputs matched; zero reverse rules after each. Owner confirmed a new biometric operation for each. |
| Phone cancellation | Passed | Exit 1, zero output bytes, zero reverse rules. |
| Cold app start after cancellation | Passed | Force-stopped only the newly installed normal application; a fresh request reopened it and produced matching output, with zero reverse rules. Owner confirmed new biometrics. |
| First Wi-Fi pairing attempt | Excluded from positive evidence | Explicit Wi-Fi setup found no foreground listener, exited 1 and reported no state creation. Subsequent diagnostic had no ADB device, so phone foreground/network status could not be inspected. |
| Wi-Fi pairing with phone confirmed on same subnet | Required environment adjustment | Discovery still failed with normal application foreground and both ports listening. A temporary inbound rule restricted to the candidate EXE, Private profile, LocalSubnet, UDP remote port 47141 was then added. Pairing discovery succeeded on the next attempt. No blanket firewall disable or trust-store modification occurred. |
| Confirmed setup storage conflict and resume | Passed | An empty directory was injected at only the new pairing's absent replay path. After owner-confirmed full fingerprint, commit exited 1 and retained the journal; only the original stub existed. New setup was rejected. Removing the owned empty directory and running resume with the same full fingerprint completed with exit 0. |
| Repeat setup does not overwrite earlier pairing | Passed | Two different public recipients and stub paths; original stub digest unchanged; two stubs and no setup journal after resume. |
| Missing, malformed and exclusively opened replay state | Passed negative checks | Each returned replay-state-unavailable, exit 1 and zero output bytes. Original unconsumed test replay file restored exactly in finally; zero reverse rules. |
| Wi-Fi standard age unwrap | Passed retry; initial discovery failure retained | First explicit Wi-Fi unwrap failed discovery. Subsequent diagnostic request used the exact candidate process and an observed established TCP connection to 47140, exited 0 and matched the synthetic digest. This does not prove discovery is reliable on every attempt. |
| Shine isolated encryption/decryption | Passed direct integration | Separate configuration and two recipients; phone decrypt exactly matched synthetic input, zero reverse rules. Existing global configuration untouched. Workspace seal/env-run results are recorded separately below. |
| Wi-Fi background interruption | Passed | After observing the candidate's established Wi-Fi connection, HOME backgrounded the app. Request exited 1 within the 15-second bound, output zero bytes, reverse rules zero. App was returned to foreground. |
| Forced desktop age exit | Passed output/transport checks | Terminated only the test age process after observing its reverse rule. Zero output bytes and zero reverse rules within the cleanup bound. Phone UI dismissal was not independently recorded. |
| First unattended authorization timeout | Excluded from clean unattended evidence | Exit 1 after 61 seconds, zero output and zero reverse rules, but owner reported possibly approving one prompt in this phase; a separate repetition was scheduled. |
| Repeated unattended authorization timeout | Passed | Separately announced repetition returned exit 1 after 61 seconds, zero output bytes and zero reverse rules. |
| Unconfirmed setup hard interruption and cleanup | Passed | Terminated only the new test setup after journal and new TPM metadata existed. Resume rejected the unconfirmed stage. Exact-code cleanup exited 0; no setup journal, two pre-existing desktop states/stubs preserved, reverse rules zero. |
| First auto Wi-Fi recovery with ADB absent from process PATH | Inconclusive, superseded by explicit retry | ADB unavailability was asserted before age. Request reached waiting state but later returned response-unavailable; owner authorization for that attempt was not established. |
| Paused Wi-Fi listener | Passed negative path | Used the observed UI Pause control; explicit Wi-Fi failed discovery with exit 1, zero output bytes and zero reverse rules. Listener re-enabled through observed UI in finally. Successful recovery is recorded in the resumed auto Wi-Fi row below. |
| Independent recovery before lifecycle changes | Passed | Both A and B ciphertexts recovered and matched without phone; separate Shine recovery configuration decrypted exactly without phone or TPM. |
| Resumed auto Wi-Fi recovery after timeout/pause | Passed | Owner explicitly prepared for one new authorization. With ADB absent from the test process PATH, auto decrypted through pairing A in 10 seconds, exit 0, synthetic digest matched. |
| Revoke pairing A and reject subsequent request | Passed rejection/output checks | Owner revoked the exact A fingerprint. A new USB request exited 1 in 1 second, zero output and zero reverse rules. Owner did not observe the phone during this rejection, so absence of a biometric prompt is not claimed. |
| Normal packaged cleanup of A | Passed | Official fingerprint-confirmed cleanup exited 0, A stub absent and B stub retained. |
| Replacement pairing cannot directly decrypt old ciphertext | Passed | B attempting A's old ciphertext returned stanza-not-matched, exit 1 and zero output. |
| Recovery, re-encryption and old ciphertext retirement | Passed | After A cleanup, independent recovery matched, new ciphertext encrypted to B plus recovery, both recovery and a fresh B phone unwrap matched. Only then was the old synthetic A ciphertext deleted. B's successful unwrap also establishes pairing isolation through A revocation/cleanup. |
| Shine workspace seal and env-run | Passed | Imported a disposable dotenv fixture, moved its generated value to the pending secret table, sealed to B plus recovery, and verified the generated source no longer contained the synthetic value. Both phone-backed and independent-recovery env-run child checks returned success without printing the value; zero reverse rules. |
| Physical USB cable interruption/reconnect | Passed | Owner unplugged during the approval prompt, observed prompt dismissal and reconnected. Request exited 1 with zero output; a later connected-device audit confirmed zero reverse rules. |
| ADB daemon restart during request | Passed | Restarted ADB after observing the test reverse rule; request exited 1 with zero output. After device reconnection, a successful reverse-list command confirmed zero rules. |
| Fresh recovery after cable/daemon interruptions | Passed | New B request required owner authorization and matched the migrated synthetic ciphertext; final successful reverse-list audit returned zero rules. |
| Explicit phone identity deletion | Passed rejection/state checks | Owner deleted the test identity through native UI. B request then exited 1 with zero output; subsequent UI inspection found the Create StrongBox identity control, rather than automatic reprovisioning. |
| Cleanup of B after identity deletion | Passed | Official full-fingerprint cleanup exited 0; old isolated root now had zero public identity stubs. |
| Exact alpha.2 upgrade baseline | Passed | Installed the verified old package pair, provisioned a new phone identity and created pairing C after owner full-fingerprint comparison. Both phone and independent recovery decrypted its new synthetic ciphertext correctly. |
| In-place alpha.2-to-alpha.3 upgrade | Passed for this exact pair | Updated the APK with install-replace and selected the exact alpha.3 EXE while retaining C's state. Public stub digest unchanged; the original alpha.2 ciphertext decrypted correctly through a new phone authorization under alpha.3, zero reverse rules. |
| Uninstall/reinstall with an existing test identity | Passed rejection and recovery checks | Uninstalled alpha.3 with C present, then reinstalled the same verified APK. Old C decrypt exited 1 with zero output. Create StrongBox identity remained visible after the failed request; independent recovery still matched. This is a normal local reinstall test, not a cloud-backup restore experiment. |
| Final C cleanup | Passed | Official full-fingerprint cleanup exited 0 after app removal had retired the phone identity. Final audits found no remaining pairing state, journals or public stubs in either isolated root. |

## Upgrade artifact provenance

The upgrade source was `v0.1.0-alpha.2`, commit
`ee81fdfe93e3f9b68fbe48467861d3668e91f366`, workflow `33744377590`, attempt 1.
Downloaded hashes matched the release record:

- Windows EXE: `c9734aabec164e1c279838417fe4eca0330b449e1e47d1536af8163fe1766b2c`.
- Windows ZIP: `8c92c54d65636ccb1333c9085a0d6d35f958ad5cb898d81547af76cfad4f3894`.
- Android APK: `1a280a7c0ccd091b9787022ba889f2234bef461bd7b117b783ae135e676bf18b`.

The upgrade destination is the exact alpha.3 pair identified above. This result does not promise
compatibility for future protocol or storage versions, nor validate downgrades.

## Limits beyond this run

- Broader Windows restart permutations beyond the tested process, app, cable and daemon interruptions.
- Whole-device TPM reset, biometric-enrollment invalidation, unexpected StrongBox key loss and
  cloud-backup restore. Native partial-TPM-key tests and app deletion do not close every physical
  hardware-invalidation row.
- Discovery ambiguity/wrong-phone behavior has source-test coverage, not a multi-phone physical run.
- Absence of a biometric prompt on revoked A was not observed by the owner; exit/output rejection
  was verified. Forced-process-exit prompt dismissal was also not independently observed.
- Wi-Fi needs an installation/diagnostic treatment for firewall discovery replies on this host.
  The one additional discovery failure after initial setup was not conclusively diagnosed.
  A later [new-UI and Wi-Fi follow-up](windows-ui-wifi-acceptance-2026-09-05.md) adds
  [reversible configuration and diagnosis](windows-wifi.md) and records bounded transition probes;
  it does not retroactively turn this historical failure into a diagnosed firewall problem.

## Final cleanup

The final audit found zero temporary firewall rules, zero ADB reverse rules, zero candidate
processes, and no pairing state/journal/public-stub files in either isolated test root. Official
cleanup removed the exact test TPM key sets; the expected global lock files may remain. Disposable
data, recovery private material and fixture result/path files were removed after the recovery and
migration checks. Candidate EXE digest remained unchanged.

The normal alpha.3 application remains installed, unconfigured, with Wi-Fi auto-listen disabled.
The original Wi-Fi PoC is still installed and its identity was outside this run. Global PATH and
Shine configuration were not replaced. No TPM reset or biometric-enrollment change was performed.
The public release packages and exact-release source staging remain for reproducibility.

All test content is disposable. No private key material, protocol payloads, QR contents,
plaintext, private-state paths, device serials or key aliases belong in this report.

Synthetic probe SHA-256: `b936379457899f24c54c60486a0acbb2f25706586a13d3e6b7bf604e525976da`.

Harness note: Windows PowerShell treated age-keygen's world-readable-file warning as a
terminating native error. Before any recovery/encryption run, the disposable data directory and
recovery file were restricted to the current Windows user. No key material was printed. This
fixture issue is separate from the plugin's protected state.

The alpha.2 setup SSH pipeline remained open after the plugin process exited and committed its
state, leaving the structured result file locked and initially empty. Stopping the test-started
ADB daemon released the pipeline, flushed the result and exposed setup exit 0. Later upgrade
scripts managed the test daemon before/after the operation. This SSH/daemon pipe observation is
recorded separately from the successful upgrade and is not evidence of a failed pairing commit.

Supplemental Windows-native source tests passed: `cargo test --offline --locked -p age-plugin-phone
-p age-plugin-phone-windows-cng -p age-plugin-phone-windows-storage` on the exact public release
commit completed 62 tests (54 desktop library, 4 CNG, 4 storage), with no failures or ignored tests.
This includes real TPM provisioning/reopening and partial-key rejection, native cleanup/isolation,
ACL, hard-link and locking tests. These test binaries are implementation evidence and did not
replace the signed candidate. Source transfer was initially rejected; after GitHub confirmed the
repository is public and the archive was verified to contain only the published commit, the same
transfer was approved.
