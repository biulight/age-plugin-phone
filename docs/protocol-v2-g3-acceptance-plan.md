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
| G3b iOS durable consumption | Production store source review; Core and protocol harness passes | Native restart/replay observation missing; choose and validate a suitable in-memory replay driver before execution |
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

No ready iOS restart/replay driver has been established by this preparation. Choose a reviewed
volatile-memory relay plus owner-operated app restart, or a narrowly scoped native test harness,
before claiming execution readiness. It must preserve signature/session binding, retain consumed
state, verify restart and in-expiry rejection, and discard raw bytes without logging them. A macOS
store harness or simulator can add supporting evidence but cannot close protected iOS storage or
Secure Enclave/native-gesture rows. Driver implementation is a separate next task.

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
