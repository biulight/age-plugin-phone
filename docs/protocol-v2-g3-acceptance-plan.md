# Protocol v2 G3 acceptance preparation

Prepared 2026-11-02, physical results reviewed 2026-11-07. G3a–d are accepted for the
recorded source, isolated packages, devices and Wi-Fi phone-recipient cases below.
Source candidate: `41dd48d79bd7497f72ac1e7e3d63ffe97d4462d1`.
Use the [successor inventory](protocol-v2-candidate-review-2026-10-31.md#successor-candidate--2026-11-02)
and [G3 criteria](independent-protocol-v2-review-2026-10-31.md#g3--targeted-state-and-native-acceptance-still-open).
This plan does not authorize installing packages, changing networks, restarting apps or modifying
existing identities. Execute on explicitly selected disposable test state with the owner's native
confirmation/observation. Do not clear app data, edit replay files or migrate private keys.

## Current evidence and execution order

| Row | Existing evidence | Next execution / status |
| --- | --- | --- |
| G3a JVM | Independent 17-suite/93-test pass at `431cf9f`; identical successor Android/test bytes | Complete for this source scope; do not repeat merely to accumulate passes |
| G3a Android durable files | All three instrumentation tests passed on physical SM-F9660, Android 16 | Complete for file operations and ordinary reopen on this device |
| G3b iOS durable consumption | Production store source review; Core and protocol harness passes | Accepted for the physical cancel/restart/replay case and scoped host store fault controls |
| G3c native ownership | Existing Android ownership/JVM regressions, Swift deadline/lifecycle tests; scoped historical physical results | Accepted for the recorded Android and iPhone cases, with the reuse and exclusions below |
| G3d evidence binding | Source, spec/vector hashes and main CI pinned | Both reviewed owner-session records bind the package, source, mode, results and observations |

Order: select the disposable device/endpoint scope → bind exact packages and drivers → Android
file-test execution → scoped native cancellation/restart/ownership cases → review evidence and
exclusions. iOS driver preparation can proceed independently of Android device execution.
No complete platform matrix is implied. A safety failure blocks its affected path; broader device
families and roaming remain release work unless a concrete defect changes the freeze assessment.

## Before a device session

Record the intended Android/iOS device model and OS, transport, recipient mode, desktop OS and
hardware-key backend, operator and observer, and whether each endpoint uses disposable state.
Do not discover or manipulate a user's installed phone state merely to fill these fields.

Build from a separate clean checkout of the exact candidate. Keep local Xcode signing changes
out of that source inventory; any necessary local signing overlay must be explicitly identified
without publishing credentials or Team IDs. Record build tool versions, artifact SHA-256, package
identifier/version, source SHA and relevant driver hashes.

Before installation, check the test/target package identifiers and whether they would replace an
existing app. Use an isolated test device or separately scoped test target; do not uninstall or
replace the user's app to avoid a conflict. The operator must explicitly select the device and
confirm the disposable state before any installation, network cycle or app restart.

### Android instrumentation build — 2026-11-07

A clean Git export of the candidate supplied the Gradle project and plugin sources. Local build
settings pointed to that export and the locked Tauri 2.11.5 Android library. With Temurin
17.0.20.1, Gradle 8.14.3 and compile SDK 36, the following offline build succeeded:

```console
./gradlew --offline --no-daemon :tauri-plugin-phone-identity:assembleDebugAndroidTest
```

The debug instrumentation APK had SHA-256
`d11ff3851fd795757c0c80891b5082fffaccb40fea9c682bdddcaad68d88338a`.
Its compiled manifest identifies both the package and instrumentation target as
`io.github.biulight.phone_identity.test`, using `androidx.test.runner.AndroidJUnitRunner`.
This self-targeting library test exercises synthetic storage fixtures.

### Physical Android storage result — 2026-11-07

The operator selected the USB-connected Android on the Windows host. ADB 1.0.41 (platform-tools
37.0.1) identified one authorized physical SM-F9660, Android 16 / API 36. The test package was
absent before installation. The transfer and installed base APK both matched the build hash above.
`am instrument -w -r` ran the named `PairingStateStoreDeviceTest` class with AndroidJUnitRunner.
UTC interval: 2026-11-06 17:51:55.916–17:51:56.692. Runner result: `OK (3 tests)`, with
status code 0 for each named method.

| Case | Observed through the test assertions |
| --- | --- |
| `replacementFailureDoesNotConsumeAndPoisonsOnlyOpenHandle` | Replacement failure and retry on the poisoned handle returned STORAGE. A new handle consumed the previously uncommitted request. |
| `syncFailurePreservesUncertainReplayConsumptionAfterReopen` | Sync failure returned STORAGE. The reopened store rejected the same request as REPLAY. |
| `clockRollbackRejectsWithoutConsumingOrChangingPairing` | Injected rollback returned CLOCK_ROLLBACK and preserved the pairing digest. Reopening at valid time accepted the unconsumed entry. |

The runner removed each synthetic test directory in teardown. After verification the operator
removed the newly installed instrumentation package and checked its absence. Transport, recipient selection,
hardware authorization and owner prompt observations are inapplicable to this file-store row.
The product package was separate from the test target. Native cancellation and Wi-Fi ownership
still require a product session. Ordinary reopen does not establish power-loss durability.

### Native session preflight — 2026-11-07

The Android phone retained the historical R2 product APK (`cd28c3a7…`, identified in the
[R2 archive](evidence/maintenance-candidate-2026-10-29/README.md)). The clean candidate's
`android:build:wifi-poc` task produced a separate `io.github.biulight.age_plugin_phone.wifipoc`
APK, version 0.1.0-beta.2 / 1000, SHA-256
`4136640b525617f09f26d4a2aa27cb4b1be6483559ea4788180fecfd70dadd87`. This ID was absent
before the run. The installed base APK matched and its main activity launched.
For Wi-Fi pairing, the macOS arm64 desktop built with Rust 1.88.0 from the same candidate
has SHA-256 `c59f205c6b44a5e18ca72f25f53ce0f7059ee384f466b9bfe8674c2018cf3168`.
Product acceptance requires the owner's full-fingerprint comparison and per-operation observations.

The Mac Wi-Fi setup attempt failed before creating state. Candidate `wifi-doctor` returned
`local_socket_unavailable`. An interface-scoped probe could send both broadcasts on the LAN
interface. On a second interface, its directed broadcast succeeded and its limited broadcast
returned `EHOSTUNREACH`. The candidate treats a failed interface send as terminal. The Windows
11 (build 22631) x64 candidate was built separately with Rust 1.88.0 for a new USB pairing
attempt, SHA-256 `886b7a11152c2fdd69d6e1248af2cfc9027aa953779ac8486813460612e579d7`.
The Windows candidate completed USB pairing with the side-by-side app after full-fingerprint
confirmation. The wrapper's output-file rename failed after setup succeeded. The sole complete
result was recovered byte-for-byte and its public stub exported the same phone recipient.

### Android native results — 2026-11-07

The [owner session](evidence/protocol-v2-g3-2026-11-07/android-owner-session.json) binds the
Windows/Android candidates above to age 1.3.1, direct Wi-Fi and the paired phone v2 recipient.
The operator answered each observation in the live session. Its SHA-256 is
`69189275ae64e8e33f34129c4901e50e36143b2f7bb2d397af1bec9802501cb9`. The session driver
had SHA-256 `601db77f3f276722acc0e2679ec725fbec9877f99adf2c5070431f499a40e870`.
The driver verified the installed APK and desktop binary, encrypted one synthetic sample to the
phone and a disposable independent recovery recipient, then verified independent recovery before
requesting any phone operation. The desktop fixture and pairing were retained for review.

| Case | Owner observation and desktop result |
| --- | --- |
| Baseline | Fresh verification approved. Exit 0, all 96 recovered bytes matched. |
| Cancel | Fresh prompt cancelled and dismissed. Exit 1, zero output bytes. |
| Foreground loss | Pressing Home dismissed the pending prompt. After the failed request the owner returned to the same app. Exit 1, zero output bytes. |
| New owner / fresh request | Auto-listen handled the new request with fresh verification. The owner observed no stale prompt or response. Exit 0, all 96 bytes matched. |

**Disposition.** Accept these four rows for G3c on this device. For delayed callback injection,
use the candidate JVM ownership regressions, including `UnwrapOperationStateTest`. The physical
foreground transition exercises replacement without forcing a particular scheduler interleaving.
Reuse the [R2 timeout, disconnect and restart results](evidence/maintenance-candidate-2026-10-29/README.md)
for unchanged listener/operation ownership only: the Android runtime delta from `be46c54` to
`41dd48d` changes `OfflineEnvelopeCrypto`, `ProtocolBounds` and `PairingStateStore`. Candidate
source conformance and G3a device results cover the changed parsing and storage paths. The R2
runs retain their original package and do not establish candidate power-loss durability.

### iPhone preflight — 2026-11-07

Xcode identified one wired, paired `iPhone16,1` on iOS 27.2. The connected-device query for
the isolated test bundle returned no installed match. The candidate export built an unsigned
arm64 iPhoneOS IPA with a bundle identifier overlay (`io.github.biulight.age-plugin-phone.g3`,
version 0.1.0 / build 0.1.0.2), SHA-256
`d40cc9340605e562a51d9be8160641afe4da7db539daf07b0980ea779e561938`.
After owner-authorized development provisioning, the signed IPA had SHA-256
`f4703237129b6ab30e43f5e39d6ad73b4595788d01c5d7630f7ee1eaa48fb254`.
Strict signature, device provisioning, application and keychain identifier checks passed.
CoreDevice installed the isolated app and confirmed version 0.1.0 / build 0.1.0.2. The
profile expires on 2026-11-13. The first launch was denied by the device security policy
(FBSOpenApplicationErrorDomain 3). The signing leaf matched the embedded profile.

| iPhoneOS 27.0 SDK build on iOS 27.2 | Observed outcome |
| --- | --- |
| 0.1.0.2, signed candidate above | After the security denial, the app launched and crashed. The isolated bundle's incident recorded SIGTRAP in UIKit's `UIApplicationEvaluateRuntimeIssueForNoSceneLifecycleAdoption`; its plist had no scene declaration. |
| 0.1.0.3, single-scene packaging control, SHA-256 `b2f797051308f66254253db98cf624672314ea65ce4bd72543e68f862766ff78` | The owner saw a black screen. This control supplies no native authorization evidence. |
| 0.1.0.4, iPhone-only Tao scene configuration, SHA-256 `25707f16224c7011b3562ce56aa76e2af9c6a327f2d28f011801245417f6ae5b` | The same PID survived two snapshots. The owner saw the application, completed Wi-Fi pairing with the pinned Windows candidate and confirmed the full fingerprint. The stub export matched and signed discovery found one endpoint. |

The last **test-package overlay** sets `UIDeviceFamily = [1]` and
`UIApplicationSceneManifest.UIApplicationSupportsMultipleScenes = true` to select the locked
Tao 0.35.3 scene delegate. It also changes the build number and signature. All 37 file-backed
Mach-O sections matched the first signed build, including the text section (SHA-256
`c2b82074f11c32d3ecbc380f59fa31c3670aed9fa82da80bcd3cd199fbb431dc`). Lifecycle observations
must be attributed to the last package. The stock SDK 27 launch failure and broader iOS/iPad
packaging remain platform work. The physical restart and replay disposition follows separately.

The Wi-Fi session uses the Windows TPM pairing. Windows runs age, the volatile relay and both
replay sends. The cable-connected Mac checks the exact phone executable and process IDs with
CoreDevice and collects live owner observations. The Windows route is selected by signed
discovery against that public stub. Keep all protocol bytes inside the existing relay
operations. Only control events, process observations and dispositions cross SSH.
The first two-host control attempt stalled before phone authorization. A revised control channel
passed a forced-decline exercise, and the Mac matched one installed process. Those preflights
supply no native restart pass.

Two subsequent physical attempts reached baseline approval and cancellation. In each, the
baseline decrypt matched the synthetic sample, the owner confirmed cancellation, and the
cancelled decrypt exited without output. One controller timed out; in the next attempt the
owner answered NO at the app-quit instruction. Both process checks in that attempt still saw
the original PID. No post-restart replay or final fresh request was observed. A retry needs a
new signed request and a new observed quit/relaunch cycle.

On a later retry the owner reported that Face ID approved the request intended for cancellation.
Exclude this attempt from cancellation and replay evidence. The controller also recorded failed
attempts without a completed restart. Cleanup stopped the isolated app and verified its process
was absent. Only generated synthetic ciphertext and independent test keys from the eight
unsuccessful Windows iPhone runs were deleted. Reports, pairing data and replay consumption
were preserved. The controller now waits for the owner to turn the camera away and confirm
readiness before sending a new cancellation request.

In the next physical run the owner approved the baseline, cancelled a fresh request, then quit
and reopened the isolated app. CoreDevice observed PID 2104, its absence, and PID 2108 for the
same executable. The controller exited at the pre-send readiness question; the Windows worker
had sent zero replays. This attempt established the restart only. At that point both replay dispositions
and the final fresh decrypt were still open. The revised two-host driver sends the first replay
after the owner confirms the relaunched listener and the new PID is checked. For the second
send it asks for `READY` separately. Each send still requires an independent observation of
the transient `(replay)` Wi-Fi status and absence of a biometric prompt.

The following attempt stopped before either send. After the owner-confirmed quit, the original
PID 2108 was absent but PID 2113 was already running. The driver's combined error
`original-process-still-present` obscured the missing snapshot with no app running. To remove
manual timing from the two-host session, the Mac now terminates only the verified isolated PID,
waits for a successful snapshot with neither that PID nor the selected executable present,
then launches the bound bundle and matches its returned PID to the running executable.
In a separate physical control this sequence recorded PID 2120, an empty app snapshot, and
PID 2124. It sent no unwrap request. Native approval, cancellation, listener readiness and
post-send rejection still require owner observation in the live replay session.

### iPhone native results — 2026-11-07

The [reviewed owner session](evidence/protocol-v2-g3-2026-11-07/ios-owner-session.json) binds
the isolated 0.1.0.4 IPA, desktop, drivers and both source reports. The initial approved
request recovered the 96-byte synthetic sample. The operator cancelled the next Face ID
request; the peer closed, the age process failed and returned zero output. CoreDevice then
recorded PID 2124, no selected process, and PID 2131 for the same executable.

| Replay after restart | Time remaining at send (Windows clock) | Network and owner observation |
| --- | --- | --- |
| Identical frame | 252.94 s | EOF with zero response bytes. The owner observed the app's replay rejection and no Face ID prompt. |
| Fresh outer session ID, same signed request | 202.87 s | EOF with zero response bytes. The owner independently observed replay rejection and no Face ID prompt. |

The final fresh request required new Face ID and recovered the matching sample. The independent
recipient had also recovered that sample before the phone exercise. The clocks differed by about
69 seconds; use each host's own timestamps and the acknowledged message order. Both Mac
observations and both Windows sends preceded the signed expiry. Accept G3b–d for this route.
For timeout and stale completions, credit the candidate Swift deadline tests and R4 ownership
review at source level. The hardware case establishes fresh approval, cancellation, durable replay
rejection and recovery. Device power loss, forced callback scheduling and other device or
transport combinations remain outside this physical result.

### iOS private-store fault controls

A macOS Swift harness compiled the candidate's store and protocol sources with synthetic fixture
metadata. It redirected the application-support root in the test copy to an empty temporary
directory. The production `verifyAndConsume` path rejected a missing record and malformed CBOR
without creating or replacing replay data. A valid consumed request was rejected as replay on
reopen, with identical stored bytes. A second host control injected a directory-sync failure
after the production rename in a copy of the store. The first consume returned a storage error,
and reopening rejected the same request as replay with the consumed record byte-for-byte intact.
These are host filesystem controls.

One corrupted record exposed an availability defect: a canonical capacity of `UInt64.max` traps
in `Int(try n[12].exactUnsigned())` during private record decoding. The fixture process exited
on signal 5 before authentication or replay replacement. An ordinary signed request cannot
supply this field; creation sets capacity to 1,024 in protected app storage. Record this as
an implementation limitation for corrupt private state. The affected scope fails closed by
terminating the process. A checked capacity conversion is needed for a normal error return.
No existing phone pairing was altered for fault injection.

## G3a Android durable-file tests

Source: [PairingStateStoreDeviceTest.kt](../plugins/tauri-plugin-phone-identity/android/src/androidTest/java/io/github/biulight/phone_identity/PairingStateStoreDeviceTest.kt).
The library [build configuration](../plugins/tauri-plugin-phone-identity/android/build.gradle.kts)
uses AndroidJUnitRunner and includes the public vectors as androidTest assets. These tests use
synthetic fixture metadata in a random `pairing-state-device-<UUID>` child of the test target's
`noBackupFilesDir`; cleanup is confined to that child. They do not provision fixture private keys
or exercise StrongBox, native authentication or application UI.

| Test method | Required observation | What it does not prove |
| --- | --- | --- |
| `replacementFailureDoesNotConsumeAndPoisonsOnlyOpenHandle` | Injected replacement failure returns STORAGE; same handle stays poisoned; after close/reopen the never-persisted request can be consumed | No consumed request was restored; this is not cancellation replay rollback |
| `syncFailurePreservesUncertainReplayConsumptionAfterReopen` | Failure after replacement returns STORAGE; reopening rejects the request as REPLAY | Reopen does not prove actual power-loss durability |
| `clockRollbackRejectsWithoutConsumingOrChangingPairing` | Earlier injected time returns CLOCK_ROLLBACK; stored offer digest unchanged; after reopen the new unconsumed entry can be consumed at valid time | Uses injected time and a verified-request copy; not a real system-clock change or fresh signature test |

Gradle entry point for future repetitions, from
`apps/mobile/src-tauri/gen/android` after candidate build settings and the device scope are verified:

```console
mise exec -- ./gradlew :tauri-plugin-phone-identity:connectedDebugAndroidTest --no-daemon -Pandroid.testInstrumentationRunnerArguments.class=io.github.biulight.phone_identity.PairingStateStoreDeviceTest
```

This command installs/runs instrumentation and can affect connected targets. Do not run it with
multiple or unapproved devices attached. Capture all three named results, runner/build/device
identity and sanitized test output. An emulator pass may support file-operation behavior but must
be labeled emulator-only; it is not physical storage, hardware-key or native-auth acceptance.
A skipped test, setup error or missing report is `not-run`/`failed`, never a pass.

## G3b/G3c native session procedure

For each selected platform/transport/recipient row, prepare a newly verified disposable pairing
and synthetic ciphertext. A successful operation requires a fresh native gesture; never automate
approval. Record the request digest/opaque case identifier, expiry and observation timing without
recording protocol bytes. First prove a fresh request succeeds and bind its output only by the
approved synthetic-data verification result. For storage-only instrumentation rows, mark transport,
recipient mode and native prompt observation as inapplicable and retain the named test results.

1. Submit a new valid request and observe its native prompt. Cancel, disconnect or let it expire
   as the selected row specifies; require no file-key/plaintext output and prompt/context revocation.
2. For replay cases, retain only that request's signed bytes in volatile driver memory. Replay
   before its expiry and require rejection without another prompt or response. Expiry alone cannot
   demonstrate durable replay rejection. Use both identical and fresh outer frame IDs if supported.
3. For the restart row, terminate/relaunch only the selected test app without clearing data, and
   verify the original process exited and a different process started before sending either replay
   variant from step 2. Record expiry remaining at each send. Count restart persistence only when
   the relaunched app receives the request on a working transport and rejects it before expiry.
4. Submit a new request, observe fresh native verification and successful output. Rejection alone
   could reflect an unavailable app or transport; the recovery step distinguishes that failure.
5. For Android Wi-Fi ownership replacement, cancel the old owner through the normal lifecycle,
   establish the new owner and verify late old callbacks cannot publish a response into it. Record
   the actual trigger and observations; JVM callback tests do not become a native pass.

Missing/corrupt/uncertain store behavior is a separate controlled fixture/fault-injection row;
never corrupt or reset real pairing state to produce it. If no isolated native mechanism exists,
record the tooling gap. Do not assert this coverage from ordinary restart alone.

### Driver limitations that must be resolved first

The existing [P1 probes](../scripts/p1/README.md) have Android/ADB and historical Windows Beta 2
package/path assumptions. Their restart mode is Android-specific and they are not an iOS driver.
Before reuse, audit the selected command's exact paths, package hashes, recipient mode, process
control, time checks and evidence schema against this candidate. Do not execute an archived command
unchanged or relabel archived results. Do not broaden the old archive checker to accept new evidence
without explicit implementation and negative tests.

### iOS driver preparation — 2026-11-06

The [iOS restart/replay probe](../scripts/g3/ios_restart_replay.py) runs on a Mac with Xcode,
Python 3.11+ and an interactive terminal. It targets the candidate source above. The owner supplies
a disposable confirmed pairing, a single public phone identity stub, a small synthetic ciphertext
(up to 65,536 bytes) and the expected SHA-256 of its nonempty plaintext. Use the candidate desktop
plugin, a compatible age binary and the IPA installed on the selected device. Verify build/source,
installed app identity/version, signing overlay and device-to-IP mapping separately. The probe
hashes the supplied artifacts and records owner confirmations. Populate the device/OS and build
provenance fields in the session evidence.

Before execution, separately select and authorize the physical test device, app and pairing.
Record the exact installed app executable path locally using Xcode's device process information.
Keep the phone foreground with Wi-Fi auto-listen enabled. Supply the stable device UDID or
CoreDevice UUID. The driver reads process snapshots using `xcrun devicectl device info processes`;
the owner performs the quit and relaunch. Each snapshot must have a successful JSON outcome and
an unambiguous numeric process ID for the exact executable when running. Unsupported process
output or an unobservable restart leaves this row open.

Example for a separately authorized device session, from the repository root:

```console
python3 -B scripts/g3/ios_restart_replay.py \
  --device "$TEST_DEVICE_ID" --executable "$IOS_APP_EXECUTABLE" \
  --local "$MAC_WIFI_IP" --phone "$IPHONE_WIFI_IP" --mode phone \
  --age "$AGE_BINARY" --plugin "$CANDIDATE_PLUGIN" --ipa "$CANDIDATE_IPA" \
  --config-dir "$DISPOSABLE_CONFIG" --identity "$PUBLIC_STUB_FILE" \
  --ciphertext "$SYNTHETIC_CIPHERTEXT" --digest "$EXPECTED_PLAINTEXT_SHA256" \
  --report "$NEW_REPORT_FILE"
```

The first and final decrypts use the direct phone route, check the synthetic output digest and
require the owner to observe fresh authorization. The middle decrypt uses the selected Mac LAN
address on port 47140 as a one-shot relay. Match the digest prefix in the phone prompt before
cancelling. The driver retains the signed request in memory, checks that the age child fails
without output, then verifies the original PID, its disappearance, and a new PID on the same
device. After restart it sends the original frame and a fresh frame ID with identical signed bytes.
It enforces expiry at send and close using wall and monotonic time. Timeout, any response byte,
wrong/missing process or failed recovery ends the case.

Observe the listener ready before **each** replay, followed by the app's replay rejection for that
attempt and no new prompt. If the UI hides the transient error or delivery cannot be established,
decline the confirmation and retain the incomplete observation. An EOF/reset alone cannot establish
replay rejection. The terminal success marker is `completed-awaiting-evidence-review`. Review its
case times, hashes, process observations and operator/device binding before accepting a physical row.

Run `python3 -B scripts/g3/test_ios_restart_replay.py` for host-only regression checks, including
both public request modes, frame bounds, restart ordering, replay response/timeout, expiry and
fresh recovery output. These checks use simulated process snapshots and peers. The two-host physical results above supply the Xcode process and owner observations. Historical Beta 2 evidence and its checker retain their existing scope.

## macOS desktop replay-store observation

At main commit `f92e107`, the workspace run of
`replaced_lock_and_missing_state_cannot_commit` passed. The detached package run then failed at
line 271: after the old handle rejected the commit and both handles were dropped, reopening the
store returned `ReplayState`. The test had yet to delete the state file. Both runs passed on the
same-commit retry. The CI error identifies the failed reopen but does not distinguish lock
acquisition, pending-marker checks or state reads. [First job](https://github.com/biulight/age-plugin-phone/actions/runs/42230638012/job/127935318371)
and [retry](https://github.com/biulight/age-plugin-phone/actions/runs/42230638012/job/128008778862).

Local checks on macOS arm64 with Rust 1.88.0 at `f92e107` passed 100 isolated runs, 100 runs of
the four file-store tests in parallel, and 12 full core library test runs. A second process
contending for the replacement lock reproduced the same line and error. The state file remained
present with no pending marker. In a separate control with an already consumed synthetic response,
the guard refused to open under contention. After lock release the guard reopened, rejected the
same response as `Replay`, and the stored bytes matched the original consumed state.

Track the CI failure as an open desktop availability observation. Contention reproduces the
symptom locally; the CI cause remains unknown. On recurrence, capture the failed operation and
OS error in test diagnostics without logging state contents. Escalate to a freeze blocker if
evidence shows lost consumption, acceptance of a repeated response or file-key output despite a
store failure. The physical iPhone evidence above is scoped separately from this desktop observation.

## Evidence and closure checklist

Use one compact row per attempted case, keeping failures and retries separate:

| Field | Required content |
| --- | --- |
| Binding | Candidate source; endpoint package identifiers/versions and hashes; driver revisions/hashes; device/OS; transport and recipient mode |
| Execution | Case/test name; UTC start/end; intended trigger; expected and actual result; restart process evidence where relevant |
| Observation | Explicit owner observation linked to the case and time: prompt freshness, cancellation and absence of a new prompt; automated result alone is insufficient |
| Result | `passed`, `failed`, `not-run`, `excluded` or justified evidence reuse; state the exact limitation and reviewer disposition |
| Recovery/cleanup | Fresh request result; disposal limited to named synthetic fixtures; no reset of uncertain consumption or deletion of existing identities |

Never retain keys, raw requests/responses, QR contents, decrypted plaintext or private paths in
public evidence. Artifact hashes and sanitized observations bind what was tested; they do not
prove hardware behavior by themselves. Do not pre-populate observations or invent pass records.

G3a–d are accepted for the scopes and dispositions above. The separate G4 and G2/G5 decisions are in the [freeze record](protocol-v2-freeze-preparation.md).
