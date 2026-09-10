# Native tagged recipient implementation evidence

Date: 2026-09-10. Status: source implementation candidate; experimental, not a tag release or
production-support declaration. The [PRD](tagged-recipient-prd.md),
[ADR 0026](adr/0026-native-tagged-recipients.md) and [quick start](tagged-recipient-quickstart.md)
describe the intended behavior. [Machine-readable digests](tagged-recipient-evidence.json)
identify the modified source/tests and local build artifacts. These are not signed release packages.

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
| Android StrongBox p256tag success, fresh prompt per operation, cancellation, expiry, lifecycle loss and replay on an exact new APK | **Unverified** |
| iOS Secure Enclave p256tag success, fresh LAContext per operation, cancellation, lifecycle loss and replay on an exact new signed app | **Unverified** |
| Native Windows candidate build | **Passed**; TPM-to-phone tag flow remains **unverified** |
| Upgrade existing phone installations without re-pairing; old phone ciphertext → new tag ciphertext; independent real recovery | **Unverified on hardware**; state/format and software regressions passed |
| Mixed real phone + age-plugin-se + ordinary age recipients, with only the matching plugin prompting | **Unverified**; multiple native P-256 recipients and collision behavior tested in software |
| Shine version-specific setup/JSON consumption, plugin-free workspace seal, and fresh phone-authorized decrypt | **Unverified**; no Shine-specific interface or dependency was introduced |
| Signed artifacts, upload, publication, expanded support | **Not performed or authorized by this implementation record** |

An Android device and an iPhone were visible to read-only device inventory. No new signed app was
installed and no person completed fresh biometric verification for this candidate. Device visibility,
software vectors, unsigned packages and old acceptance records cannot close those rows.
Complete the PRD physical matrix and record exact signed artifact hashes before advertising explicit
tag release support. Shine acceptance remains separate from the standard plugin implementation.

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
phone prompt or application-level Shine acceptance occurred in this follow-up. The generated
packages retain candidate version 0.1.0-alpha.5 and are not a new release of the published alpha.5.
