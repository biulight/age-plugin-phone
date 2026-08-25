# Roadmap

## Product sequencing principles

- Address the gap recorded by Shine decision 0032: Windows users need an independent fresh
  user-verification gesture for every age private-key operation without leaving a reusable age
  identity on the desktop. Windows 11 x64 is therefore the first desktop product target; macOS
  remains an interoperability target because Secure Enclave and Touch ID age integrations already
  exist there.
- Keep this repository independent from Shine. The first Alpha integrates through ordinary age
  recipients, public identity stubs, and the external age process only; it requires no Shine code or
  ciphertext-format change.
- Keep the long-term age identity and every fresh user-verification operation in Android StrongBox.
  Windows TPM keys authenticate the paired desktop and privately select its stanza; they never hold
  the age identity or replace phone authorization.
- Keep pairing and unwrap security independent from every transport. QR, ADB, BLE, and a future
  dedicated USB channel carry the same bounded, canonical, end-to-end authenticated messages.
- Use ADB reverse as the default, explicitly developer-oriented USB transport for the Windows
  Alpha. Keep QR as the observable offline fallback that does not require USB debugging, but do not
  require a desktop camera for the default path. ADB authorization, device names, serial numbers,
  and connection state are never authentication inputs.
- Do not freeze the wire format or promise production-secret protection until independent
  cryptographic and implementation review is complete.
- Add convenience transports only through the common transport boundary; no transport may weaken
  per-operation user verification, replay protection, or paired-device binding.

## Milestone 0: scaffold

- [x] Standalone workspace with no Shine dependency.
- [x] Fail-closed age identity-plugin entry point.
- [x] Transport-independent protocol data model.
- [x] Initial architecture and threat model.

## Milestone 1: protocol and test vectors

- [x] Implement the disposable Android StrongBox capability probe in `android-strongbox-poc.md`.
- [x] Complete its on-device authentication, restart, cancellation, and cleanup matrix.
- [x] Select StrongBox P-256 and an age tagged recipient as the Android production candidate.
- [x] Specify the experimental P-256 recipient encoding, KDF, AEAD context, and strict parser.
- [x] Publish and cross-check its non-secret deterministic Rust/Kotlin unwrap vector.
- [x] Validate the exact tagged-recipient construction with a live auth-per-use StrongBox operation.
- [x] Specify experimental canonical pairing/request encoding and transcript hashes.
- [x] Publish a deterministic signed request/encrypted response test vector.
- [x] Cross-check the canonical signed request/encrypted response vector in Kotlin.
- [x] Validate a live StrongBox unwrap through the request-bound encrypted response path.
- [x] Publish and cross-check the complete pairing transcript vector in Kotlin.
- [x] Specify and implement bounded, crash-safe replay-consumption state.

## Milestone 2: bidirectional QR prototype

- [x] Select Tauri 2 as the mobile application shell with an untrusted, presentation-only WebView.
- [x] Commit pairing state and its replay scope atomically in app-private, non-backed-up storage.
- [x] Add a one-shot native confirmation session that creates pairing state from a verified transcript.
- [x] Implement versioned QR fragmentation and bounded animated-frame handling in Rust and Kotlin.
- [x] Wire native camera capture and desktop animated-QR rendering to the framing layer.
- [x] Provision separate production identity and phone-signing keys with crash-safe StrongBox custody.
- [x] Implement a native Kotlin Tauri plugin that binds Keystore/StrongBox operations to fresh user
  verification.
- [x] Implement desktop pairing and public identity stub creation.
- [x] Implement one request/response file-key unwrap with fresh user verification.
- [x] Test cancellation, replay, wrong device, wrong identity, expiry, and corrupted frames.

## Milestone 2.5: reference age integration

- [x] Implement standard `recipient-v1` wrapping for `age1phone` recipients and public identity stubs.
- [x] Implement `identity-v1` one-shot unwrap with private pairing locators.
- [x] Handle multiple files, unknown stanzas, malformed supported stanzas, cancellation, and bad responses.
- [x] Replace external response capture and paste with a desktop-native scanner.
- [x] Fail closed before authorization on ambiguous multiple phone identities or phone stanzas.
- [x] Implement versioned, privacy-preserving multi-phone stanza selection.
- [x] Validate physical pairing and a complete reference-age unwrap on an Android StrongBox device
  and a macOS desktop.

## Milestone 3: Windows custody and experimental protocol upgrade

- [ ] Support Windows 11 x64 with TPM 2.0 as a hard requirement; do not add a software, DPAPI, or
  file-private-key fallback.
- [ ] Use Microsoft Platform Crypto Provider to provision distinct non-exportable P-256 keys for
  ECDSA desktop request signing and ECDH private stanza selection.
- [ ] Separate hardware signing and key-agreement interfaces from the software keys retained only
  for deterministic vectors and tests.
- [ ] Upgrade the experimental pairing transcript, public identity stub, and v2 paired recipient to
  bind the desktop signing and selection public keys independently.
- [ ] Update and cross-check Rust/Kotlin vectors, strictly reject old experimental state, and require
  users to pair again rather than migrate an old pairing.
- [ ] Implement the Windows locator and replay backend under `%LOCALAPPDATA%` with private ACLs,
  reparse-point and hard-link rejection, exclusive locking, bounded reads, and atomic replacement.
- [ ] Test copied desktop files, missing or wrong TPM keys, corrupt state, concurrent access, failed
  persistence, and restart; every unsupported or ambiguous state must fail closed.

## Milestone 4: common transport boundary and Windows ADB Alpha

- [ ] Define one bounded bidirectional transport-session interface for pairing and unwrap, and keep
  QR as the reference and fallback implementation.
- [ ] Implement Windows loopback plus Android `adb reverse` using short-lived in-memory streams;
  never pass protocol payloads through shell arguments, files, shared storage, or logs.
- [ ] Make ADB the Windows Alpha default and allow the same new-version pairing to switch between
  ADB and QR without migrating or weakening its identity.
- [ ] Require explicit device selection when more than one Android device is connected, and fail
  closed on unauthorized, offline, replaced, disconnected, or mid-session switched devices.
- [ ] Enforce hard connection, message, byte, and time limits and remove the exact ADB reverse rule
  on success, cancellation, failure, timeout, and process exit.
- [ ] Keep peer authentication, transcript comparison, request binding, phone user verification,
  and replay consumption above ADB; treat every ADB property as an untrusted display hint.
- [ ] Device-test pairing and unwrap across cancellation, timeout, cable removal, reconnect,
  multiple devices, wrong device, malformed frames, replay, and QR fallback.
- [ ] Document ADB as a Developer USB mode that requires USB debugging and grants the authorized
  desktop broader Android capabilities than this application needs.

## Milestone 5: lifecycle design and security review

- [ ] Define phone replacement, independent recovery-recipient, paired-desktop revocation, identity
  deletion, application removal, and TPM/StrongBox invalidation flows.
- [ ] Define the Alpha matrix for Windows 11 x64, TPM 2.0, Android StrongBox devices, ADB
  platform-tools, reference age, rage, and Shine; keep macOS as interoperability validation only.
- [ ] Prepare a review package covering the P-256 recipient, pairing transcript, split desktop key
  roles, private stanza selection, response envelope, Windows and Android replay storage, CNG/TPM
  custody, Android authorization, transport framing, ADB, and age-plugin state machines.
- [ ] Obtain independent cryptographic and implementation review and resolve its findings.
- [ ] Freeze a stable protocol version only after review, with explicit upgrade,
  downgrade-rejection, and compatibility rules.

## Milestone 6: Windows and Android product Alpha

- [ ] Replace the development Doctor as the primary mobile UI with identity status, public
  recipient, pairing, paired-desktop management, USB/QR request approval, revocation, and recovery
  guidance.
- [ ] Preserve Doctor diagnostics only in explicitly marked development builds, with non-sensitive
  reports.
- [ ] Package and sign Windows 11 x64 desktop and Android builds; macOS packaging is not an Alpha
  release gate.
- [ ] Add CI for Windows Rust builds, Kotlin, TypeScript, deterministic vectors, negative tests,
  reproducible build inputs, and packaged-binary smoke tests.
- [ ] Complete interoperability with released reference age and rage versions, multiple phones,
  multiple files, and an independent recovery recipient.
- [ ] Use Shine's existing `age_identity` and `age_recipients` configuration to test encrypt,
  decrypt, seal, and multi-recipient recovery end to end without changing the Shine repository.
- [ ] Run a multi-device compatibility and lifecycle matrix covering app and desktop restart,
  backgrounding, process death, permission denial, key invalidation, corrupt state, and upgrade.
- [ ] Conduct a limited technical-user Alpha that verifies Windows stores no reusable age private
  identity and every unwrap requires fresh phone user verification.

## Milestone 7: native transports and platform expansion

- [ ] Implement a native BLE Tauri plugin over the reviewed common transport interface, with
  untrusted discovery, bounded fragmentation, explicit phone selection, and fail-closed reconnect.
- [ ] Evaluate a dedicated non-ADB USB channel against real Alpha usage; implement it only if it can
  replace Developer USB mode without introducing driver, permission, or persistence risks that
  outweigh its usability benefit.
- [ ] Evaluate Windows ARM64, Linux, iOS, and macOS product packages after the Windows x64 Alpha;
  platform expansion must not add a weaker key-custody fallback.
- [ ] Define signed update, vulnerability reporting, protocol migration, support lifetime, and
  deprecation policies before general availability.
