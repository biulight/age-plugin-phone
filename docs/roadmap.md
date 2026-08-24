# Roadmap

## Milestone 0: scaffold

- [x] Standalone workspace with no Shine dependency.
- [x] Fail-closed age identity-plugin entry point.
- [x] Transport-independent protocol data model.
- [x] Initial architecture and threat model.

## Milestone 1: protocol and test vectors

- [ ] Select the phone hardware key and age recipient construction.
- [ ] Specify canonical encoding, transcript hashes, key derivation, and AEAD contexts.
- [ ] Publish non-secret deterministic pairing and unwrap test vectors.
- [ ] Obtain independent cryptographic review before stabilizing version 1.

## Milestone 2: bidirectional QR prototype

- [x] Select Tauri 2 as the mobile application shell with an untrusted, presentation-only WebView.
- [ ] Implement QR fragmentation and animated-frame handling.
- [ ] Implement desktop pairing and public identity stub creation.
- [ ] Implement one request/response file-key unwrap with fresh user verification.
- [ ] Test cancellation, replay, wrong device, wrong identity, expiry, and corrupted frames.

## Milestone 3: mobile hardware backends

- [ ] Implement a native Swift Tauri plugin that binds Secure Enclave operations to user verification.
- [ ] Implement a native Kotlin Tauri plugin that binds Keystore/StrongBox operations to user verification.
- [ ] Define phone replacement, recovery recipient, and paired-device revocation flows.

## Milestone 4: BLE and packaging

- [ ] Implement a native BLE Tauri plugin and reuse the reviewed application protocol over it.
- [ ] Package signed desktop binaries and mobile applications.
- [ ] Verify interoperability with reference age, rage, multi-recipient files, and downstream tools.
