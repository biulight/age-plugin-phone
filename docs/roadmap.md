# Roadmap

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
- [ ] Obtain independent cryptographic review before stabilizing version 1.

## Milestone 2: bidirectional QR prototype

- [x] Select Tauri 2 as the mobile application shell with an untrusted, presentation-only WebView.
- [x] Commit pairing state and its replay scope atomically in app-private, non-backed-up storage.
- [x] Add a one-shot native confirmation session that creates pairing state from a verified transcript.
- [x] Implement versioned QR fragmentation and bounded animated-frame handling in Rust and Kotlin.
- [x] Wire native camera capture and desktop animated-QR rendering to the framing layer.
- [x] Provision separate production identity and phone-signing keys with crash-safe StrongBox custody.
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

## Milestone 3: mobile hardware backends

- [ ] Implement a native Swift Tauri plugin that binds Secure Enclave operations to user verification.
- [x] Implement a native Kotlin Tauri plugin that binds Keystore/StrongBox operations to user verification.
- [ ] Define phone replacement, recovery recipient, and paired-device revocation flows.

## Milestone 4: BLE and packaging

- [ ] Implement a native BLE Tauri plugin and reuse the reviewed application protocol over it.
- [ ] Package signed desktop binaries and mobile applications.
- [ ] Complete interoperability with reference age, rage, multiple phone recipients, and downstream tools.
