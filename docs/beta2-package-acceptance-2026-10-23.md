# Beta 2 exact-package acceptance — 2026-10-23

Status: **Developer USB core and scoped Wi-Fi security/lifecycle observations recorded;
network automatic-discovery recovery has a reproduced open failure**. Do not treat
this record as an unconditional P1 pass. The broader device/lifecycle matrix remains incomplete.
This remains owner-only testing with synthetic data; protocol v2 is unfrozen.

A subsequent unpublished Android fix passed scoped physical regression; see the
[separate candidate record](android-wifi-network-recovery.md). That result does not
change the failure observed in the published Beta 2 package below.

## Exact artifacts and verification

Both artifacts came from the existing public `v0.1.0-beta.2` release, immutable source
`e08d631b33bd0c16948ca26275bc851b0bf56c15`, workflow `34612479284`, attempt 1.
All six downloaded release assets matched GitHub's SHA-256 digests. The two signature
records agreed on source, version, workflow and attempt. No release assets were changed.

| Artifact | SHA-256 |
| --- | --- |
| Windows x64 test-signed ZIP | `b245990706547b2e66937b2198cdcf1fc854c38737cb8efac4e6617e3184d324` |
| Extracted Windows EXE | `62d8f3836598dd1ab287c3b2ac432539870bfb0cbe7bdfd547d08cf3be373e2b` |
| Android ARM64 APK | `b8c3011739914249f50d81fed4727f438a93b0b5839eed8188e645d5637f1b16` |

Windows SignTool verified the signed content with the expected single failure for an
untrusted private test root. `Get-AuthenticodeSignature` reported `UnknownError` for
that trust boundary. The signer and root certificate SHA-256 values matched the
published record; an in-memory `CustomRootTrust` chain validation passed with exactly
two certificates. No certificate trust store was modified. This is not public publisher
trust or a claim that ordinary Windows installations trust the package.

- Windows signer: `d64e82d01bb5835b292a0abbf38759a2c36aaa7003af46809e6a5d730e239215`.
- Windows test root: `7506695a68ad99f3bcad5e7faee2f4e42fcc0062d91b5f6d68ab850bf1f32c96`.
- Android signer: `9a3e5a00a0a363ca58bbe0abfa1bbc0e36cbdce58e314c0c0dbfa94baff1d58b`.

Android `apksigner` verification passed and the signer matched the installed Beta 1
application. The published Beta 2 APK was installed in place, without uninstalling or
clearing application data. Its version name is `0.1.0-beta.2`, version code `1000`.
The installed APK was read back and matched the published APK byte for byte; its hash
was checked again through Windows after the phone was moved to that computer's USB.

## Environment and method

The extracted Windows EXE reported `0.1.0-beta.2` and `windows_alpha_support: supported`.
The host used PowerShell 7.6.7 and reference age 1.3.1. The phone was a Samsung
SM-F9660 running Android 16. Results apply to this recorded combination only.

The owner authorized Windows USB debugging and supplied the current phone's public
recipient. Read-only product decoding identified an existing matching Windows public
stub and a valid nonmatching stub with a different paired phone recipient. Existing
pairings were reused; this is not fresh-pairing or full-fingerprint setup acceptance.

The P0 helpers from commit `64f0317` were used by a temporary, one-case-at-a-time driver.
This was not an unattended pass of the entire minimum harness: the owner explicitly
confirmed phone observations in the chat after each relevant operation. Successful
machine assertions alone were recorded as awaiting observation until that confirmation.
The payload was 128 disposable bytes encrypted to the selected phone recipient and a
new, independent software recovery recipient. Recovery was tested before phone unwrap.

## Accepted core cases

| Case | Observed result |
| --- | --- |
| Independent recovery | Exit 0; byte-identical synthetic output without phone authorization |
| Nonmatching identity alone | Exit 1; exact reference-age ordinary identity-miss diagnostic; no output; owner observed no biometric prompt |
| Malformed supported phone stanza | Exit 1; explicit `malformed phone stanza` classification; no output; owner observed no biometric prompt |
| Unavailable private state | Exit 1; explicit `paired desktop state is unavailable` classification using an isolated nonexistent configuration root; no output; owner observed no biometric prompt |
| Nonmatch followed by match | Exit 0; byte-identical output; owner confirmed a fresh native biometric prompt and verification |
| Second independent verified request | Exit 0; byte-identical output; owner confirmed another fresh native biometric prompt and verification |
| Cancellation | Owner observed the new native prompt and clicked Cancel; exit 1 with no output |
| Fresh request after cancellation | Exit 0; byte-identical output; owner confirmed a new native biometric prompt and verification |

All decrypt assertions required empty stdout. Every completed core case left zero ADB
reverse rules. The nonmatch test combines the ordinary-miss result with the owner's
no-prompt observation; it does not claim packet-capture proof of zero network I/O.
The malformed-stanza result uses the attempt with the explicit product diagnostic,
not the earlier supporting check that only classified stderr as a generic error.

## Accepted foreground Wi-Fi cases

Each Wi-Fi request explicitly selected Wi-Fi with the ADB device hint removed,
even though USB remained connected. Success required exit 0, empty stdout and
byte-identical synthetic output; failure required nonzero exit, empty stdout and
no nonempty output file. Every completed case left zero ADB reverse rules.

| Case | Observed result |
| --- | --- |
| First and second independent requests | Both succeeded; owner confirmed a fresh native verification prompt for each request |
| Cancellation and fresh recovery | Owner canceled the new prompt; request failed without output; a new request succeeded with fresh verification |
| Backgrounding and foreground recovery | Owner pressed Home during the prompt and observed dismissal; request failed without output; after returning and restoring listening, a new request succeeded with fresh verification |
| Authentication timeout and fresh recovery | Owner left the new prompt untouched and observed automatic dismissal; request failed without output after approximately 64 seconds; a new request succeeded with fresh verification |
| Paused listening with USB still connected | Explicit Wi-Fi request failed without output in approximately 3 seconds; owner observed no native prompt |
| Explicit USB recovery after Wi-Fi failure | While Wi-Fi listening remained paused, a separate request explicitly selected USB and succeeded with fresh native verification |
| Invalid first connection and automatic rearm | A connection sent an invalid fixed stream header without identity or key material; the phone closed it without response, and the owner observed no native prompt or manual listener operation. A subsequent normal Wi-Fi request succeeded with fresh verification |
| Peer disconnection and fresh recovery | After the owner confirmed the native prompt was awaiting verification, Windows terminated only the current test's exact-package plugin process. The owner observed automatic prompt dismissal without interacting with the phone; age exited 1 without output. A new Wi-Fi request succeeded with fresh verification |
| Actual Wi-Fi interface loss and recovery | With the native prompt awaiting verification, ADB disabled phone Wi-Fi and verified both disabled state and removal of its IPv4 address, then restored Wi-Fi and verified an address returned. The owner observed automatic prompt dismissal without touching the phone. The old request exited 1 without output after approximately 94 seconds, without harness termination. A later fresh request succeeded with new native verification |
| Exact signed-request replay within expiry | An in-memory TCP relay forwarded one normal request and response; age exited 0 with byte-identical output and the owner confirmed fresh native verification. Two subsequent connections replayed the same signed request: first the identical complete stream frame, then only a fresh outer stream session ID. Both were closed without any response in approximately 15 ms, with 295 and 294 seconds remaining before expiry; the owner observed no new prompts |
| Fresh request after replay rejection | A new direct Wi-Fi request succeeded with byte-identical output and fresh native verification, confirming the listener remained usable after both rejections |

The paused-listener result and explicit transport selection support failure without
automatic USB recovery for this attempt. Zero reverse rules alone are not proof of
zero USB traffic. Negative lifecycle diagnostics were classified as generic errors;
the record combines machine assertions with the owner's specific observed actions,
without claiming an exact internal failure reason from stderr.

The attempted phone network-toggle case is not accepted as network-change evidence:
the owner observed prompt dismissal when opening the system quick-settings panel,
before Wi-Fi disconnection could be established. The later Windows process-termination
case establishes peer-disconnection behavior only, not network-interface change.
The later ADB-driven interface cycle separately establishes actual Wi-Fi interface
loss and reconnection to the existing network; it does not test roaming to another
access point or subnet. Its first recovery request failed after approximately three
seconds for an unclassified reason; a subsequent explicit retry passed. This is not
an uninterrupted or immediately successful recovery claim, and the initial failure
is not attributed to the owner's inattention. The old request's approximately
94-second completion is consistent with discovery plus the 90-second message timeout.
The first invalid-header attempt lacked phone observation and is not counted; the
accepted retry combined connection closure with explicit no-prompt/no-listener-action
confirmation. The disconnect helper initially rejected its operation marker because
PowerShell automatically parsed its JSON timestamp; preserving the timestamp as a
string allowed the same exact-process checks to pass before termination. The failed
helper invocation did not terminate a process and is not product failure evidence.

The replay probe checked signed-request byte equality and expiry in memory, without
writing raw protocol messages, response envelopes or keys to logs or files. Its
original successful unwrap establishes that the captured request was usable before
replay, and the subsequent direct request establishes continued listener availability.
These are black-box rejection observations, not an internal replay-error diagnostic.
This tests replay after a successful unwrap within one running app session; it does
not establish replay persistence across app/device restart or replay after every
failure category.

## Harness correction and remaining boundaries

Review follow-up: the temporary interface-cycle helper treated an unsuccessful address
query with empty stdout as address removal. The reverse-rule checks had the same
unchecked-command pattern. A fault fixture reproduced the false pass. Maintained
[P1 probes](../scripts/p1/README.md) now require every ADB query to complete successfully,
distinguish a successfully absent interface from query failure, restore Wi-Fi after
an attempted disable, and bind reports to driver/common/P0-helper hashes. The fault
suite passed on macOS PowerShell 7.4.6 and Windows PowerShell 7.6.7, including query
failure, timeout, persistent address, restore failure and reverse-query failure.

The corrected physical repeat verified actual interface loss and restoration. The
pending request failed without output. Its first automatic-discovery recovery attempt
again failed in 3.30 seconds, now classified as `wifi-discovery-no-match`; it started
about 92 seconds after IPv4 restoration. A separate request to the explicit phone
address succeeded with fresh native verification, followed by a successful automatic
discovery request with another fresh verification. No listener-switch intervention
was requested between these attempts. This narrows the failure to discovery availability,
not TCP listening or native authorization. Recreating discovery/reception resources
after a normal session is a possible explanation; socket/UDP or multicast-lock failure
has not been individually proven. The released package was not modified and this
availability issue remains open. A retry success does not close it.

The [evidence archive](evidence/beta2-2026-10-23/README.md) preserves original results,
excluded/failed attempts, owner observations and a separate review disposition. All
five historical driver hashes referenced by accepted Wi-Fi rows have exact matching
recovered sources. Reports that originally lacked source hashes remain explicitly
unbound; hashes were not retroactively claimed. Corrected-run sources and dependency
hashes are archived, and the manifest checker rejects missing, changed or unlisted files.

The first foreground Wi-Fi attempt stopped before authorization because the test
driver retained `AGE_PLUGIN_PHONE_ADB_SERIAL` while selecting Wi-Fi. The product
rejects those inconsistent route hints. The same omission was found in the P0
minimum harness: both drivers were corrected to remove the ADB hint for Wi-Fi while
retaining the explicitly selected device for USB. Regression fixtures passed on
macOS PowerShell 7.4.6 and Windows PowerShell 7.6.7. This attempt is a harness
configuration failure, not a Wi-Fi product pass or a confirmed product defect.

- The requested interface-loss/reconnection and exact-request replay experiments were
  executed for this host/phone/package combination, but automatic-discovery recovery
  is not accepted as consistently passing. Roaming to another access point
  or subnet and replay across app/device restart are outside these observations;
  the accepted cases do not complete every foreground Wi-Fi or device-family gate.
- This record does not establish replay-after-restart, storage fault injection,
  hardware invalidation, fresh pairing, wrong physical phone or second-device-family
  acceptance. Unavailable-state testing did not alter existing pairings or replay files.
- The scoped in-place update and surviving-pairing unwrap do not complete the broader
  upgrade, downgrade, recovery or compatibility matrix.
- Public signing, external-user readiness and production-secret support remain open.

After the follow-up, the disposable synthetic plaintext, ciphertext, recovery key,
outputs and local input-path index were removed from the Windows test directory.
Final inspection found zero ADB reverse rules. Existing product pairing and replay
state were preserved; sanitized reports and temporary driver sources were retained.

See [Beta release readiness](beta-readiness.md), [the execution plan](roadmap.md), and
[the Beta 2 harness instructions](beta2-harness.md) for the separate remaining gates.
