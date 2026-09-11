# Native tagged recipient implementation evidence

Date: 2026-09-10. Status: source implementation candidate; experimental, not a tag release or
production-support declaration. The [PRD](tagged-recipient-prd.md),
[ADR 0026](adr/0026-native-tagged-recipients.md) and [quick start](tagged-recipient-quickstart.md)
describe the intended behavior. [Machine-readable digests](tagged-recipient-evidence.json)
identify the modified source/tests and local build artifacts. See the dated signing follow-up below; these are acceptance candidates, not published releases.

## Implemented behavior

- Default/explicit phone output is retained. Explicit tag works with `setup`, `pair` and the new
  public-only `recipients` command. Setup JSON remains schema 1 with one selected recipient.
- The phone key, public stub, paired desktop roles, locator, journal, protocol and replay formats
  are unchanged. Output comments do not change the public identity bytes. Canonical public identity
  file reading rejects additional identities, trailing non-comment data and noncanonical case.
- `identity-v1` validates all supported stanzas before any private configuration/state lookup.
  Unmatched tag stanzas do not resolve configuration or parse transport overrides. Ambiguity
  fails before lookup; the first input pairing for the selected phone key is final.
- Android StrongBox and iOS Secure Enclave entry points dispatch p256tag through their existing
  fresh-authentication and consume-before-prompt paths. HPKE key material stays native. iOS
  invalidates the fresh context on both successful and failing open. No fallback was added.

## Recorded automated verification

| Check | Result and scope |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed on macOS; existing third-party `block` future-compatibility notice remains |
| `cargo test --workspace --locked` | Passed on macOS, including core, desktop, storage, replay, CLI and unchanged phone v1/v2 vectors. Explicitly ignored hardware tests are not passes |
| Core tag tests | Deterministic RFC 9180 seal/open, strict encodings/lengths/points, mutated body/enc/tag, wrong key, real public-tag collision, signed envelope and durable request/response replay across restart |
| Desktop tests | No lookup/transport for malformed or unmatched tags, ambiguity before lookup, duplicate pairing order, no fallback after missing state/cancellation/transport failure, tag and phone through the same signed response boundary, public-only CLI export and JSON compatibility |
| Managed setup | Both recipient types tested at each interrupted commit write boundary; public stub/state encoding unchanged |
| Android Kotlin | 75 tests across 14 suites, zero failures/errors/skips; includes shared HPKE/collision and protocol request/response vectors. Native library `assembleDebug` passed |
| Swift core | Six tests passed; shared p256tag and real-collision tests exercise CryptoKit ECDH plus the native HPKE schedule. Apple's independent `HPKE.Recipient` also opens the fixed vector |
| iOS Rust device target | `cargo build --locked --target aarch64-apple-ios --manifest-path apps/mobile/src-tauri/Cargo.toml` passed |
| Full iOS builds | Unsigned ARM64 simulator `.app` and device `.ipa` packaging passed. Device package identifies iPhoneOS and contains no signing profile or signature directory |
| Full Android build | Unsigned release APK passed with JDK 17; only ARM64 native libraries packaged. `apksigner verify` confirms the APK has no signature |
| Native clients | age **v1.3.2** and rage **0.12.1** each encrypted with empty PATH and multiple native recipients. Both P-256 identities independently opened their stanzas and verified the age header MAC and decrypted the payload |
| Old phone interoperability | Existing smoke passed: 12 cross-client independent recoveries and two malformed-recipient rejections with phone v1/v2 recipients |
| Package contract | `python3.13 scripts/check-package-layout.py --archives` passed; old four vector hashes unchanged. New public JSON vectors are packaged in core; desktop tests have no sibling-crate filesystem dependency |
| Native Windows | On `nuc.win.local`, fmt, workspace clippy with warnings denied, debug build and complete workspace tests passed: 103 passed, zero failed, one external-client test ignored by default, no filtered tests. Separate native-client tests passed with age **1.3.1** and rage **0.12.1** |

Host tools: Rust 1.96.0 (`ac68faa20`), Apple Swift 6.3.3, JDK 17 and Gradle 8.14.3.
The existing CI's pinned age 1.3.1/rage 0.12.1 job now explicitly runs the native-tag test;
that future CI run is not represented as a completed local result.

The ordinary sandbox prohibited existing tests' loopback sockets/process groups. The full Rust
suite passed with normal host permissions, without changing tests or adding skips. Swift used
temporary module caches and `--disable-sandbox` to avoid nested sandbox/cache restrictions.

## Reproduction

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
P256TAG_AGE_CLIENT=/absolute/path/to/age cargo test --locked -p age-plugin-phone-core --test p256tag native_client -- --ignored
P256TAG_AGE_CLIENT=/absolute/path/to/rage cargo test --locked -p age-plugin-phone-core --test p256tag native_client -- --ignored
swift test --package-path plugins/tauri-plugin-phone-identity/ios/Core
apps/mobile/src-tauri/gen/android/gradlew -p apps/mobile/src-tauri/gen/android :tauri-plugin-phone-identity:testDebugUnitTest :tauri-plugin-phone-identity:assembleDebug --no-daemon
python3.13 scripts/check-package-layout.py --archives
```

The external-client test is explicitly ignored in the default workspace invocation because it
requires a real client at an absolute path. Both invocations above were separately run successfully.
It empties PATH only for encryption; no phone plugin or mock `tag` plugin is discoverable there.
The test phone scalars are public fixtures, not a production desktop identity implementation.

Regenerate the deterministic standard vectors with the `public_tag_vector` and
`public_tag_envelope` core examples. The collision fixture uses two published test scalars,
one fixed encapsulated key and a ciphertext for the first key. Rust, Kotlin and Swift all confirm
that both selectors match but the second key fails HPKE authentication. No fixture key is
provisioned into StrongBox or Secure Enclave.

## Remaining acceptance and release boundaries

| Platform/scenario | Status |
| --- | --- |
| Android StrongBox p256tag physical matrix | **Partial**: signed in-place update, authenticated ADB and Wi-Fi tag success, repeated requests, cancellation, timeout, background interruption, process-kill and USB-disconnect failure/recovery, replay-after-restart rejection, recovery, old format and observed no-prompt rejection for invalid requests including validly signed malformed/binding-error payloads passed; storage/clock physical fault injection remains unverified |
| iOS Secure Enclave p256tag physical matrix | **Partial**: the replacement package passed Wi-Fi tag and old-format success, fresh authentication after timeout/background/process kill, automatic timeout dismissal, foreground loss, kill-process failure/recovery, observed no-prompt rejection including validly signed malformed/binding-error payloads, cancellation and replay-after-restart rejection; disconnect and storage/clock physical fault injection remain unverified |
| Native Windows candidate build and TPM-to-Android tag flow | **Passed**; real tag decryption over authenticated Wi-Fi reused the existing Windows pairing |
| Upgrade existing phone installations without re-pairing; old phone format and independent recovery | **Passed for recorded devices**; retained historical ciphertext migration was not exercised |
| Mixed real phone + age-plugin-se + ordinary age recipients, with only the matching plugin prompting | **Passed on macOS/iPhone**; all three identities independently decrypted, and phone-only/SE-only selection with both identities configured prompted only the matching hardware |
| Shine version-specific setup/JSON consumption, plugin-free workspace seal, and fresh phone-authorized decrypt | **Passed for Shine 2.0.3 on macOS with the recorded iPhone**; two successive workspace runs each required a separately confirmed Face ID |
| Signed artifacts and in-place installation | **Authorized and completed** for the recorded Android/iOS candidates; no publication or expanded production support |

At the initial 2026-09-10 checkpoint, an Android device and an iPhone were visible to read-only device inventory. No new signed app had been
installed and no person had completed fresh biometric verification for this candidate. Device visibility,
software vectors, unsigned packages and old acceptance records cannot close those rows.
Complete the PRD physical matrix and record exact signed artifact hashes before advertising explicit
tag release support. Shine acceptance remains separate from the standard plugin implementation.
QR tag transport is explicitly outside this version's validation scope by owner direction.

## Build follow-up

The Windows run found a test-fixture permissions error: an ordinary temporary directory did not
meet replay storage's private-DACL requirement. The tag replay test now uses the existing Windows
`ensure_private_directory` helper under LOCALAPPDATA. Runtime permission enforcement was unchanged.
The corrected test also passed again on macOS, along with core all-target clippy and formatting.

The simulator packaging failure was an existing nonempty export directory, not its source archive.
[Tauri CLI 2.11.4](https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.11.4/crates/tauri-cli/src/mobile/ios/build.rs)
uses `fs::rename` into `build/arm64-sim`. The old export was moved aside into a temporary backup;
the next complete packaging run passed. A temporary workspace Cargo configuration bypassed the
host's sccache wrapper for the Xcode subprocess and was removed afterward. Android used an explicit
JDK 17 because the host default JDK 26 was incompatible with this Gradle build.

Unsigned build commands (run from `apps/mobile`, with the above local toolchain configuration):

```console
bun run tauri ios build --debug --target aarch64-sim --no-sign --ci
bun run tauri ios build --debug --target aarch64 --no-sign --ci
bun run tauri android build --apk --target aarch64 --ci
```

All four `AGE_PLUGIN_PHONE_ANDROID_*` signing variables were unset for the Android build. Its
`universal/release` filename contains only the requested ARM64 ABI. No signing, install, publication,
phone prompt or application-level Shine acceptance occurred in that unsigned-build follow-up. The generated
packages retain candidate version 0.1.0-alpha.5 and are not a new release of the published alpha.5.

## Authorized signing and physical follow-up — 2026-09-11

The owner explicitly authorized signing and in-place phone updates. The implementation was
snapshotted in an isolated checkout at `3c13706fcd05679adc2013c4bdd3ce3cb08ccbf9`, branch
`codex/tagged-recipient-acceptance-20260911`. The original workspace and its local Xcode team/build
settings were preserved. Android uses the existing protected, acceptance-only signing workflow
[34503925021](https://github.com/biulight/age-plugin-phone/actions/runs/34503925021); it cannot publish
a tag or release in this mode. The owner-authorized signing environment approval was submitted
through the existing eligible reviewer account.

The iOS device build was signed using the existing Apple development team. The exported package
passed `codesign --verify --deep --strict`, retained application identifier
`88R4BGL627.io.github.biulight.age-plugin-phone`, and installed in place from build 0.1.0.4 to
0.1.0.5. The old public pairing was reused successfully without re-pairing. Signed IPA digests and
physical results are recorded in the JSON evidence. No phone keys, raw protocol payloads, QR
contents, plaintext or device identifiers are included in this record.

Initial physical observations: tag decryption succeeded through the standard age plugin on macOS,
and the owner confirmed fresh Face ID. A second ciphertext with both tag and independent recovery
recipients decrypted through the phone; the recovery identity also decrypted independently with
empty PATH. The first attempted cancellation completed Face ID before the owner could cancel and
is retained as **not a cancellation pass**. A fresh attempt with the camera covered was cancelled:
age exited 1 and no plaintext file was created. A subsequent new tag request succeeded. The old
phone v2 format also decrypted using the same pairing (new synthetic ciphertext in the old format,
not retained historical ciphertext). Moving the app to the background during a pending request
also produced exit 1 with no plaintext file. These are the initial-package observations; later
sections record the replay and timeout follow-up, replacement iOS package, and Shine acceptance.
The mixed real age-plugin-se row is also closed later in this record. The remaining fault-injection
scope is listed in the current matrix and JSON evidence.

Android signing workflow attempt 1 completed successfully. The downloaded APK's SHA-256 matched
its same-run checksum after resolving the artifact's flattened filename, and independent
`apksigner verify --print-certs` matched the installed alpha.4 certificate exactly. `adb install -r`
updated to alpha.5 (versionCode 1000) without uninstall or data clearing. Two tag requests succeeded
through the retained Mac pairing; a cancelled fingerprint request exited 1 without creating plaintext,
and a new request after cancellation succeeded. The old phone v2 format also decrypted successfully.
Independent recovery decrypted the mixed tag ciphertext with empty PATH. Signed APK/IPA copies are
preserved in `target/tagged-recipient-acceptance-20260911` and hashed in the JSON record.

A native Windows TPM-to-Android tag decryption also passed with age 1.3.1 and the recorded Windows
candidate executable. It reused an existing Windows pairing over authenticated Wi-Fi and the same
synthetic tag ciphertext; the recovered bytes matched. No new pairing, key export, fallback or
installation of a trust root was used. This is one successful Windows physical path, not completion
of its entire negative matrix. No GitHub release or final tag was created, and no Shine acceptance
or broader production-support declaration was made.

## Additional negative verification and iOS timeout finding

Android foreground loss terminated the request with no output; the owner confirmed returning to
the home screen while the prompt was active. A separate untouched foreground request failed after
60.47 seconds with no plaintext file. A test harness then retained one signed request only in memory:
the owner cancelled it, the app was force-stopped/relaunched without clearing data, and the exact
same request was rejected after restart with no second fingerprint prompt (owner confirmed).

The harness uses the existing hardware-backed desktop signer and existing pairing records; it does
not implement a software phone key, accept/decrypt returned file keys, record protocol payloads or
reset replay state. Its source and digest are preserved alongside the acceptance artifacts. Expired,
wrong-phone, wrong-stanza, bad-signature and malformed-envelope requests were rejected by Android.
The owner did not watch the complete initial quick sequence, so absence of fingerprint prompts for
those cases was initially unconfirmed. A malformed supported stanza was also rejected by the
desktop production signing API before transport. Both limitations were addressed in later
follow-up runs below.

The five Android invalid requests were later repeated while the owner watched the screen. Expired,
wrong-phone, wrong-stanza, bad-signature and malformed-envelope requests were each rejected within
347 ms with no response, and the owner confirmed that no fingerprint prompt appeared.

The native malformed-stanza follow-up used a canonical protocol envelope with a valid signature
from the paired desktop hardware key. The harness first created a normal request, shortened only the
`p256tag` body by one byte, reproduced the canonical request encoding and re-signed that payload.
Android rejected it in 266 ms and the replacement iOS package rejected it after its 3023 ms Wi-Fi
window. Neither returned a response, and the owner confirmed that neither device showed a biometric
prompt. The harness still never accepts or decrypts a returned file key and does not log the raw
request.

The same hardware-signed method then changed only the request `identity_id` or `desktop_id` before
re-signing each canonical payload. Android rejected the two requests in 277/279 ms; iOS rejected
them after 3126/3097 ms Wi-Fi windows. No response was returned, and the owner confirmed no
fingerprint or Face ID prompts. This reaches the native pairing-binding checks with a valid signer
rather than relying on unauthenticated discovery failure from an unrelated pairing.

Targeted fail-closed tests were rerun after the physical follow-up. The Rust replay filter passed
14 tests covering missing/corrupt/non-private state, write-failure poisoning, uncertain and
post-replacement commits, replay and clock monotonicity. The upgrade replay integration test passed
its pre-refactor state migration case. Android's `PairingStateStoreTest` also passed, including
durable replay after restart, capacity, clock rollback, corrupt/scope and storage behavior. The
previously recorded eleven Swift core tests include monotonic deadline rollback/nonfinite handling.
These are software fault-injection results and are not presented as mutations of retained phone
pairing state.

No retained `.age` ciphertext exists in the repository working tree or Git history, so the
historical-ciphertext migration row cannot be closed from available evidence. Newly generated old
`phone` v2 ciphertext passed on both devices but remains labeled as newly generated. iOS physical
Wi-Fi disconnect was not injected because switching Wi-Fi from Control Center also causes
foreground loss and would not isolate disconnect from the already-passed lifecycle behavior.

The recorded Android pairing also decrypted the same synthetic tag ciphertext from macOS over
authenticated Wi-Fi, independently of the earlier ADB path and Windows-to-Android Wi-Fi check. The
output matched all 128 bytes. QR tag transport is not part of this version's requested validation.

Force-stopping the Android app after its fingerprint prompt appeared ended the request after 7.37
seconds with exit 1 and no output. Relaunching the unchanged app and issuing a new request succeeded
with matching bytes after a new fingerprint verification. The owner confirmed both observations.

Physically unplugging USB after the Android fingerprint prompt appeared ended the ADB request after
2.84 seconds with exit 1 and no output. After reconnecting and reauthorizing the same device, a new
request succeeded in 5.58 seconds with matching bytes and a new fingerprint verification. The owner
confirmed both observations.

iOS rejected expired, wrong-stanza, bad-signature and malformed-envelope requests; the owner
confirmed no Face ID prompts. Cancelled-request replay was also rejected after terminating and
relaunching the app, with no second Face ID prompt (owner confirmed).

The iOS unattended-timeout test exposed a real failure: age exited after 93.20 seconds without
plaintext, but Face ID remained on screen and the listener did not resume. The original stream
receive deadline no longer acts once a request is delivered, leaving native authentication pending.
The failed signed IPA is preserved as `ios-arm64-before-timeout-fix.ipa`; its earlier passes are not
silently transferred to the replacement package.

The source fix adds a per-operation monotonic authentication deadline (at most 60 seconds and bounded
by request expiry) shared by native Wi-Fi and QR unwrap paths. Timeout invalidates only that fresh
LAContext; late completion cannot return a file key. Replay is consumed before authentication and
is not reset. Five new Swift tests cover timer revocation, late completion before timer delivery,
cancellation/new-operation independence, clock rollback/nonfinite time, and completion/invalidation
races. All eleven Swift core tests passed. Replacement signed-device verification is recorded below
when completed; this finding prevents treating the original iOS candidate's timeout gate as passed.

The replacement iOS package from fix commit `2ec6ec808820867ae2ef84416ca9375f2fd874e2`
passed the unattended timeout retest: the standard age operation ended after 67.24 seconds with
exit 1 and no plaintext file. The owner confirmed Face ID/retry dismissed automatically without
manual cancellation. A subsequent read-only authenticated discovery found one candidate in
3001 ms. Fresh successful authentication after timeout is checked separately below.

The replacement package then decrypted a fresh tag request successfully in 4.03 seconds; the
synthetic bytes matched and the owner confirmed a new Face ID verification. Cancellation/restart
replay was repeated on this exact package: the first request was cancelled (no response after
11128 ms), and the identical in-memory request was rejected after app restart (3100 ms). The owner
confirmed no second Face ID prompt. The replacement IPA is retained as `ios-arm64.ipa`; its hash,
fix-source hashes and scoped results are recorded under `signed_acceptance.ios.timeout_fix`.
The original package evidence and failed timeout remain retained separately. This closes the
observed timeout regression without claiming the complete transport matrix.

The replacement package also rejected expired, wrong-stanza, bad-signature and malformed-envelope
requests without a response. Each bounded Wi-Fi probe completed in about 3.0 seconds, and the owner
confirmed that none produced a Face ID prompt.

The same replacement package decrypted a newly generated old `phone` v2 ciphertext with matching
bytes. Moving the app to the background during a fresh pending tag request ended the desktop
operation after 7.89 seconds with exit 1 and no output. After reopening the app, a new request
completed in 3.79 seconds with matching bytes, demonstrating fresh recovery after foreground loss.

Killing the iOS app process after Face ID appeared ended the request after 9.37 seconds with exit 1
and no output. The first operation immediately after relaunch found no candidate in its three-second
discovery window and did not prompt. A read-only follow-up found the authenticated candidate after
3004 ms; the next new request succeeded with matching bytes and a newly confirmed Face ID. This
startup-listener race is retained separately from the process-kill failure and successful recovery.

## Shine integration acceptance

Shine 2.0.3 (`47499e3ab1c765cacd3f96a10eba83be28212ecd`) was exercised with an
isolated temporary config and workspace. The plugin's read-only public export matched the recorded
iPhone `age1tag` recipient. Shine sealed a synthetic workspace secret to that recipient and an
independent recovery recipient while its PATH contained age 1.3.2 but no `age-plugin-phone`.
The pending synthetic value was removed from the source and replaced by an age payload.

With the existing public identity stub configured locally, two successive `shine env run`
operations decrypted the workspace and compared the synthetic value inside the child process;
neither printed plaintext. Both exited successfully, and the owner confirmed that each run showed
and completed a distinct Face ID verification. This covers the normal and cached workspace paths
without changing the user's Shine config, a real workspace, or pairing state. The same recipient
and identity had already passed direct age CLI encryption/decryption, so this path introduces no
Shine-specific ciphertext, RPC, environment override, or plugin interface.

## Mixed phone, Secure Enclave and recovery acceptance

Age 1.3.2, with no phone plugin in PATH, encrypted one synthetic file to the recorded iPhone
`age1tag`, an existing Secure Enclave `age1tag`, and a disposable ordinary age recovery recipient.
Each identity independently recovered matching bytes. The first Secure Enclave attempt was
cancelled and produced no output; its explicit retry succeeded.

With the phone and Secure Enclave identities configured together, a phone-only ciphertext caused
one iPhone Face ID and no Mac Touch ID; the reverse SE-only ciphertext caused one Mac Touch ID and
no iPhone Face ID. Both outputs matched. The owner confirmed all prompt observations. This closes
the scoped mixed-recipient and matching-plugin selection row for macOS/iPhone without treating the
4-byte public tag as authorization or adding a fallback identity.
