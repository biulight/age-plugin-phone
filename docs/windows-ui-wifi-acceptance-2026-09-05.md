# Scoped Windows / Android UI and Wi-Fi acceptance — 2026-09-05–06

Status: scoped run complete. This run checks the UI introduced by `af804ec` and the Wi-Fi diagnostic
follow-up. It does not reuse the old alpha.3 package as evidence for the new phone UI and does not
rerun the whole [owner-preview matrix](windows-acceptance-2026-09-05.md).

## Candidates

- UI baseline source: `af804ec2d3a5b74f86298fb52ae8d024e65f16f2`.
- Initial new-UI APK SHA-256: `1ad27ef92aa1d36b7c11136366de201d5591ce617e98a41a27b334ef7ff6c8a7`.
- Follow-up APK with Activity-stop cleanup SHA-256:
  `2f3719bd323f206ca282b147e83cb839b812f33d0ef3d75eb4291aa006dd6d07`.
- Both APKs are arm64 debug builds of the isolated `.wifipoc` application, built with the current
  production frontend bundle. Install-replace preserved that application's identity. The normal
  signed alpha.3 application was not replaced or uninstalled.
- Initial USB setup used the signed alpha.3 desktop EXE recorded in the previous acceptance report;
  this is compatible desktop transport evidence, not a substitute for the new APK.
- Wi-Fi diagnostic desktop: isolated Windows debug build using the exact published alpha.3 source
  staging plus this change's `main.rs`; SHA-256
  `526581d2b820822b227a4971ea3b3b92f76b2c98db50122266f5bd83b0057d65`.
  Diagnostic additions do not change the production discovery implementation or window.
- Same Windows 11 / Samsung Android 16 host pair as the prior run. The host has a physical Private
  LAN interface and a separate Private ZeroTier interface. This is not a fresh Windows installation.

## UI observations

| Case | Result | Evidence / limit |
| --- | --- | --- |
| Initial USB desktop wait | Excluded from UI success/failure | Owner and desktop windows were not synchronized; desktop timed out and removed unconfirmed setup state. |
| USB success, initial new UI | Passed | Owner compared the complete fingerprint and confirmed on the phone; desktop then accepted the same fingerprint and exited 0. Main screen reported Paired and the USB button enabled. |
| USB loading, initial new UI | Passed | A controlled loopback endpoint accepted the phone without sending protocol bytes. Main-screen screenshot showed spinner; accessible button state was disabled and the operation text identified USB pairing. |
| USB read timeout, initial new UI | Passed within observation bound | Controlled endpoint remained connected and silent. Button was disabled at 68.4 s and enabled with `usb_transport_failed` at 100.5 s (native read deadline 90 s). A fresh click completed without restarting the app. This is a transport-read timeout, not a five-minute fingerprint-confirmation timeout. |
| Native USB Cancel | Passed | `user_cancelled`, enabled button within the 2.2 s UI observation interval, unconfirmed desktop rollback and zero reverse rules. |
| USB confirmation background, initial new UI | **Failed; fixed in follow-up** | HOME placed the launcher in the foreground, but returning retained the previous native fingerprint confirmation. A separate three-second background check reproduced it. It was not counted as a pass after manually cancelling. |
| USB Cancel, follow-up APK | Passed | `user_cancelled`, enabled main-screen button at 2.152 s; desktop rollback and zero reverse rules. |
| USB confirmation background, follow-up APK | Passed | After two seconds on HOME, return restored the main screen with `user_cancelled` and enabled button at 4.167 s including UI inspection. Desktop rollback and zero reverse rules. |
| Wi-Fi listener timeout, follow-up APK | Passed | The one-shot pairing listener expired with `wifi_transport_failed`; button enabled. A fresh click immediately entered Wi-Fi loading with button disabled. |
| Wi-Fi waiting background, follow-up APK | Passed | After the fresh click, HOME for two seconds and return produced `wifi_transport_failed` with enabled buttons. No app restart or replay reset. |
| Wi-Fi confirmation arriving after desktop expiry | Failed closed; excluded from success | Owner confirmed on the phone, but desktop rejected the late confirmation and removed local state. The phone-side orphan was retained for explicit native revocation. |
| Fresh Wi-Fi success after expired confirmation | Passed | Without restarting the app, a new complete fingerprint comparison and owner phone confirmation completed desktop setup with exit 0. Main-screen buttons enabled and auto-listen became ready. |
| First Wi-Fi decrypt attempt | No successful authorization established | Discovery/connection reached the response stage, then failed at 63.802 s with response unavailable/malformed. No output file existed. Phone returned to ready auto-listen. This is not classified as a firewall or discovery failure. |
| Second Wi-Fi decrypt attempt | Excluded from observed authorization evidence | Response unavailable at 63.665 s. Owner subsequently said they had not been paying attention. No implementation fault or successful biometric operation is inferred from the unattended attempts. |
| Owner-observed Wi-Fi decrypt after failures | Passed | New request completed in 6.325 s, exit 0, synthetic input/output SHA-256 matched. Phone identity operation was required by the unchanged auth-per-use flow. |
| Wi-Fi native Cancel, follow-up APK | Passed | `user_cancelled`, main-screen button enabled at 2.162 s. Desktop rolled back, zero reverse rules. |
| Wi-Fi confirmation background, follow-up APK | Passed | HOME for two seconds then return: `user_cancelled`, main-screen button enabled at 4.249 s. Desktop rolled back, zero reverse rules. |

The lifecycle defect was that the direct Activity-stop coordinator only cancelled Wi-Fi transport
resources. USB and native transcript confirmation depended on Tauri's separate process lifecycle
delivery, which did not dismiss them in this physical run. The direct stop callback now invokes the
existing complete stop cleanup, including pending pairing, native confirmation, USB, Wi-Fi and
authentication resources. This does not preserve a cancelled request or relax replay consumption.

Harness limitations: the first very rapid HOME/start sequence was not sufficient evidence of an
actual stopped Activity. Later checks held HOME and inspected the launcher state. Competing ADB
daemon starts also caused a no-device harness failure while Windows still saw the USB device;
the daemon was restarted and subsequent checks serialized startup. Android exposed the native
Cancel button as uppercase `CANCEL`; a case-sensitive harness selector was corrected. These
attempts are retained as harness exclusions rather than product failures. No unconfirmed negative
test was promoted to a pairing success.
The Wi-Fi harness also needed to wait for the three-second discovery window before looking for the
native confirmation, and to account for Windows PowerShell decoding ADB's UTF-8 separator through
the local code page. The corrected harness passed both Wi-Fi native interruption checks.

## Wi-Fi rule and discovery observations

Use the accompanying [configuration and diagnosis guide](windows-wifi.md). The helper's rule is
restricted to the tested EXE, physical interface, Private profile, LocalSubnet and inbound UDP
remote port 47141, with ephemeral local port and blocked edge traversal.

| Case | Result |
| --- | --- |
| Inspect and Enable `-WhatIf` | Read-only inspection and preview succeeded. |
| Pairing-mode discovery, this rule absent | One candidate, 3014 ms. Phone UDP 47141 and TCP 47140 were visible before the check. |
| Enable twice | One deterministic scoped rule; both invocations succeeded without duplicates. |
| Pairing-mode discovery, rule enabled | One candidate, 3021 ms. |
| Inspect enabled rule | Exact expected program/interface, Private, UDP, LocalSubnet, remote 47141, local Any. |
| Relative executable / wildcard interface | Rejected before mutation. |
| Disable `-WhatIf` | Preview only; the rule was not disabled. |
| Disable, Remove, repeat Remove, Inspect | Actual disable succeeded; removal and repeat removal succeeded. Final inspection reported `Present=False`, `Enabled=Absent`. |
| Windows ZIP layout | Local compression/readback verified the EXE, quickstart, Wi-Fi guide and helper at the documented archive root. This checks layout; it is not a new signed release or a clean-VM installation claim. |
| Authenticated discovery after pairing and enabling auto-listen | Three fresh windows passed: 3010, 3017, 3022 ms. A harness field-name error first rejected empty CLI arguments before discovery; corrected to the setup result's `identity_path`. These are post-pairing checks, not a measurement of the first subsecond after phone commit. |
| Authenticated discovery in background | Expected `no_matching_response`, 3019 ms, while the scoped rule remained enabled. This is an observed lifecycle cause for this negative control. |
| Authenticated discovery after return to foreground | Three fresh windows passed: 3007, 3014, 3018 ms. First command started 16 ms after the foreground-launch command returned. |
| Authenticated discovery immediately after successful decrypt | Three fresh windows passed: 3020, 3014, 3007 ms. First command started 1 ms after digest verification completed. |

The absent-rule success means this run has **not** reproduced the previous host's need for its
temporary EXE rule. It does not prove that an arbitrary fresh Windows environment allows discovery,
or explain the historical extra failure. Existing host policy remains a possible difference. No
blanket firewall disable, network reclassification or trust-store change was made.

Nine valid transition probes passed. The historical extra **foreground** discovery failure remains
unexplained and was not reproduced in this bounded run. The observed background negative control
does not retroactively explain it. No discovery timeout, retransmission, response-cache or routing
change is justified by this run; the implementation change is limited to the independently
reproduced Activity-stop cleanup defect. New `wifi-doctor` output and the guide make future failures
distinguishable without protocol logging or TCP probes that disturb the one-shot listener.

Synthetic probe SHA-256: `4acb45c396565e830a260e945f0ce5c0ae0e4c29d30dccea93cce68c543d82a3`.

## Source verification

- Current frontend TypeScript/Vite build and both APK builds passed.
- All 70 Android native unit tests passed, including the new Activity-stop / stale-confirmation / fresh
  exchange regression and existing cancellation, timeout, replay, wrong-peer and malformed-input
  checks.
- `cargo test --workspace --locked` passed with required loopback/process access. An initial
  sandboxed run failed on denied socket/process operations; it was not a product regression.
- Strict workspace Clippy, formatting, local documentation-reference checks and `git diff --check`
  passed.

## Cleanup and remaining limits

The owner revoked all three phone test pairings through their native confirmations, including the
orphan from the expired desktop comparison. Official full-fingerprint desktop cleanup removed the
two committed desktop pairings; failed/unconfirmed setups had already rolled back. The initial USB
shell did not propagate its intended configuration override and created that one test pairing in
the normal configuration root. Its exact public stub and official cleanup target were verified;
no wildcard or unrelated desktop-state deletion was used. Wi-Fi and subsequent negative setups
used isolated roots.

Final audit: both test stubs absent, zero non-lock state files across the isolated test roots,
zero ADB reverse rules, zero candidate processes, and zero phone paired desktops. The scoped
firewall rule is absent. Wi-Fi auto-listen is restored to disabled. Final main-screen inspection
showed enabled pairing controls with no loading spinner. Owned synthetic data and result files
were removed; candidate APKs/EXEs, source staging and non-sensitive evidence remain reproducible.
The PoC identity remains on the phone, and the normal signed app remains untouched.

This is source/debug-candidate evidence on the existing owner host. A clean Windows VM and a newly
signed production APK/ZIP were not exercised. The original sporadic foreground discovery failure
remains open for a future **bounded** reproduction if it returns; this run supplies a usable
diagnostic and recovery procedure rather than claiming universal reliability.

Only coarse states, timings, source versions and artifact hashes belong in this report. No keys,
protocol payloads, QR contents, plaintext, device serials or private state paths are recorded.
