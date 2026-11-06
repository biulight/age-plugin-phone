# Protocol v2 G3 acceptance preparation

Prepared: 2026-11-02. **Plan only; no new device result or G3 closure.**
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
| G3a Android durable files | Three production-file instrumentation tests exist; source reviewed | Not run on a device for this candidate; prepare exact test APKs and run the three cases below |
| G3b iOS durable consumption | Production store source review; Core and protocol harness passes | Host relay and synthetic regressions available; review driver and validate on a disposable iPhone |
| G3c native ownership | Existing Android ownership/JVM regressions, Swift deadline/lifecycle tests; scoped historical physical results | Candidate package/transport/recipient rows need fresh execution or documented justified reuse |
| G3d evidence binding | Source, spec/vector hashes and main CI pinned | Device/package identity, owner observations and per-row disposition not yet supplied |

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
identifier/version, source SHA and relevant driver hashes. No candidate device artifact has been
built or installed by this preparation. A debug/instrumentation APK is not a release artifact.

Before installation, check the test/target package identifiers and whether they would replace an
existing app. Use an isolated test device or separately scoped test target; do not uninstall or
replace the user's app to avoid a conflict. The operator must explicitly select the device and
confirm the disposable state before any installation, network cycle or app restart.

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

Execution entry point, **planned and not run by this preparation**, from
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
fresh recovery output. These checks use simulated process snapshots and peers. Physical Xcode
process output, prompt/error observation timing and end-to-end candidate execution remain to be
verified. Historical Beta 2 evidence and its checker retain their existing scope.

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

G3a JVM is the only completed execution subitem credited here. Closing the rest of G3 requires
candidate-scoped required rows to pass or receive explicit justified dispositions consistent with
safety invariants. G4 breaking-update/recovery and G2/G5 normative/freeze decisions remain separate.
