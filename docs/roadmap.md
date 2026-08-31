# Roadmap

## Product sequencing principles

Current deployment posture: this application is temporarily an owner-only technical preview as
defined in [`owner-only-preview.md`](owner-only-preview.md). The UVC-camera QR/replay matrix,
second capability-qualified StrongBox family, multi-phone interoperability, public Windows signing,
and external technical-user Alpha remain recorded public-Alpha gates but are deferred until use
expands beyond the repository owner. Deferral does not mark them complete or relax any security
invariant.

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
- Keep pairing and unwrap security independent from every transport. QR, ADB, BLE, Wi-Fi, and any
  future dedicated non-ADB USB transport carry the same bounded, canonical, end-to-end
  authenticated messages. A new transport must not define a second pairing or authorization
  protocol.
- Use ADB reverse as the default, explicitly developer-oriented USB transport for the Windows
  Alpha. Keep QR as the observable offline fallback that does not require USB debugging, but do not
  require a desktop camera for the default path. ADB authorization, device names, serial numbers,
  and connection state are never authentication inputs. ADB remains the technical-Alpha default
  and is intended to become a development, diagnostics, and recovery path rather than a promised
  general-availability default.
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

- [x] Support Windows 11 x64 with TPM 2.0 as a hard requirement; do not add a software, DPAPI, or
  file-private-key fallback.
- [x] Use Microsoft Platform Crypto Provider to provision distinct non-exportable P-256 keys for
  ECDSA desktop request signing and ECDH private stanza selection.
- [x] Add platform-neutral P-256 signing and key-agreement operation boundaries plus an isolated
  Microsoft Platform Crypto Provider implementation with no software-provider fallback.
- [x] Route production desktop operations through those hardware boundaries and retain software
  keys only for deterministic vectors and tests.
- [x] Upgrade the experimental pairing transcript, public identity stub, and v2 paired recipient to
  bind the desktop signing and selection public keys independently.
- [x] Update and cross-check Rust/Kotlin vectors, strictly reject old experimental state, and require
  users to pair again rather than migrate an old pairing.
- [x] Implement the Windows locator and replay backend under `%LOCALAPPDATA%` with private ACLs,
  reparse-point and hard-link rejection, exclusive locking, bounded reads, and atomic replacement.
- [x] Test copied desktop files, missing or wrong TPM keys, corrupt state, concurrent access, failed
  persistence, and restart; every unsupported or ambiguous state must fail closed.

## Milestone 4: common transport boundary and Windows ADB Alpha

Status: ADB transport feasibility has been validated on the designated Windows/Android baseline.
The remaining wrong-paired-device and injected-response-replay physical evidence is an Alpha
release gate, not an open question about whether the ADB transport can carry the protocol.

- [x] Define one bounded bidirectional transport-session interface for pairing and unwrap, and keep
  QR as the reference and fallback implementation.
- [x] Implement Windows loopback plus Android `adb reverse` using short-lived in-memory streams;
  never pass protocol payloads through shell arguments, files, shared storage, or logs.
- [x] Make ADB the Windows Alpha default and allow the same new-version pairing to switch between
  ADB and QR without migrating or weakening its identity.
- [x] Require explicit device selection when more than one Android device is connected, and fail
  closed on unauthorized, offline, replaced, disconnected, or mid-session switched devices.
- [x] Enforce hard connection, message, byte, and time limits and remove the exact ADB reverse rule
  on success, cancellation, failure, timeout, and process exit.
- [x] Keep peer authentication, transcript comparison, request binding, phone user verification,
  and replay consumption above ADB; treat every ADB property as an untrusted display hint.
- [x] Device-test Windows 11 x64 pairing and a standard age unwrap with TPM/StrongBox custody,
  byte-for-byte recovery, and exact reverse-rule cleanup.
- [x] Device-test Windows timeout/no-response, locked phone, nonexistent serial, and a real
  `UsbFfs` stale reverse rule; every case produced no plaintext and the fixed stale-rule parser
  rejected rather than overwrote the existing rule.
- [ ] Complete the remaining Windows device matrix: a wrong paired physical device and injected
  response replay. Deferred during the owner-only preview; required before broader Alpha use.
- [x] Complete Windows device and transport tests for native-console Ctrl-C, forced `age.exe`
  process exit, cable removal and reconnect, ADB daemon restart, multiple online devices,
  malformed stream, timeout/lock-screen failure, and QR fallback. Each negative path produced no
  plaintext or reverse residue. Each recovery request required a new phone biometric operation and
  succeeded.
- [x] Rebuild and device-test the Android biometric mismatch regression. An unrecognized scan kept
  the same one-shot prompt pending, a registered fingerprint then completed it, Cancel remained
  terminal, and both recovery paths required a new biometric operation without reverse residue.
- [x] Document ADB as a Developer USB mode that requires USB debugging and grants the authorized
  desktop broader Android capabilities than this application needs.

## Milestone 5: lifecycle design and security review

- [x] Define phone replacement, independent recovery-recipient, paired-desktop revocation, identity
  deletion, application removal, and TPM/StrongBox invalidation flows.
- [x] Define the Alpha matrix for Windows 11 x64, TPM 2.0, Android StrongBox devices, ADB
  platform-tools, reference age, rage, and Shine; keep macOS as interoperability validation only.
- [x] Prepare a review package covering the P-256 recipient, pairing transcript, split desktop key
  roles, private stanza selection, response envelope, Windows and Android replay storage, CNG/TPM
  custody, Android authorization, transport framing, ADB, and age-plugin state machines.
- [x] Obtain independent cryptographic and implementation review and resolve its findings. The
  source review resolved ISR-001 and documented ISR-002's unreachable advisory preconditions;
  native Windows and remaining physical/package evidence remain separate Alpha gates.
- [ ] Freeze a stable protocol version only after review, with explicit upgrade,
  downgrade-rejection, and compatibility rules.

## Milestone 6: Windows and Android product Alpha

- [x] Replace the development Doctor as the primary mobile UI with identity status, public
  recipient, pairing, paired-desktop management, USB/QR request approval, revocation, and recovery
  guidance.
- [x] Preserve Doctor diagnostics only in explicitly marked development builds, with non-sensitive
  reports.
- [x] Implement fingerprint-confirmed, journaled Windows local cleanup that removes only one
  revoked pairing's replay state, TPM metadata, locator, exact CNG keys, and public stub; when the
  stub is already unavailable, allow the same private cleanup only through its exact canonical
  locator without discovering or deleting other public stubs.
- [x] Package, sign, and independently verify the first Windows 11 x64 and Android RC0 artifacts;
  label the private-root Windows package explicitly as test-signed.
- [ ] Move Windows distribution signing to a publicly trusted free open-source program before
  claiming a publicly trusted Windows Alpha; macOS packaging is not an Alpha release gate.
  Deferred while packages remain private and owner-only.
- [x] Add CI for Windows Rust builds, Kotlin, TypeScript, deterministic vectors, negative tests,
  reproducible build inputs, and packaged-binary smoke tests.
- [x] Complete exact-candidate interoperability with released age 1.3.1 and rage 0.12.1 across
  multiple synthetic files, both cross-client directions, the phone path, and an independent
  recovery recipient.
- [ ] Complete multiple-phone interoperability, including a wrong paired physical phone and a
  second capability-qualified StrongBox device family. Deferred during the single-owner,
  single-phone preview.
- [x] Use Shine's existing `age_identity` and `age_recipients` configuration to test direct
  encrypt/decrypt, workspace seal, runtime `env run`, and multi-recipient recovery end to end with
  Shine 1.8.0, without changing the Shine repository.
- [ ] Run a multi-device compatibility and lifecycle matrix covering app and desktop restart,
  backgrounding, process death, permission denial, key invalidation, corrupt state, and upgrade.
  Single-device checks may continue, but the complete matrix is deferred until broader use.
- [x] After creating the exact ADB reverse rule, launch the Android application with one fixed,
  payload-free unwrap action so cold start and `singleTask` delivery both enter the same native USB
  unwrap controller. Do not place protocol messages, request fingerprints, caller hints, or other
  request data in shell arguments. The exact packaged Windows/Android artifacts passed cold,
  foreground, background, and repeated wake plus interruption cleanup.
- [x] Remove the normal Developer USB unwrap's manual **Approve USB** pre-step. The phone must still
  strictly verify and durably consume the signed request before presenting a fresh auth-per-use
  biometric prompt; cancellation, timeout, and tested lifecycle loss paths fail closed. The product
  and Tauri command entry points are removed; malformed physical wake validation remains tracked in
  the Alpha matrix rather than reopening the completed product-flow item.
- [ ] Conduct a limited technical-user Alpha that verifies Windows stores no reusable age private
  identity and every unwrap requires fresh phone user verification. Deferred until someone other
  than the repository owner will use the application.

## Milestone 7: production transport orchestration and platform expansion

- [x] Implement an owner-only, foreground-only Wi-Fi unwrap proof of concept over the common stream
  boundary. It requires an explicit private IPv4 endpoint and opt-in phone mode, supports no pairing,
  discovery, background wake, `auto`, fallback, race, reconnect, or silent retry, and makes no
  production transport claim. The exact `3ff2cea` Windows build and side-by-side Android PoC build
  completed a physical LAN unwrap with a fresh StrongBox biometric operation; the phone and
  independent recovery paths produced the same synthetic plaintext digest. A stale pairing-bound
  recipient and a mismatched pairing state both failed without plaintext before the successful
  fresh pairing and re-encryption.
- [x] The initial one-shot flow kept an explicit **Cancel Wi-Fi listener** control throughout the
  foreground operation. Its replacement, **Pause · Wi-Fi auto-listen**, preserves the same exact
  listener/socket/biometric cancellation and never restores or retries a consumed request.
- [x] Replace per-request **Approve · Wi-Fi** with an opt-in, persistent-off-by-default foreground
  auto-listen mode in every Android build. It serializes one request at a time, re-arms only while
  foregrounded with bounded backoff, yields an uncommitted listener to USB or local actions, and
  preserves a fresh StrongBox authorization for every consumed request. Pausing or backgrounding
  closes the exact listener, socket, or authorization without replay rollback or transport fallback.
- [x] Define one transport policy with explicit `auto`, `adb`, `ble`, `wifi`, and `qr` choices plus
  non-security capability and route hints. Availability may be checked before sending a request;
  after sending begins, do not race, switch, or silently retry on another transport. A retry creates
  a fresh protocol request. [`ADR 0019`](adr/0019-unified-transport-policy.md) resolves one route
  before protocol-session creation, centralizes CLI and standard age selection, preserves the
  Windows ADB and non-Windows QR defaults, and reserves BLE as fail-closed until its reviewed PoC.
- [ ] After the automated Developer USB flow, remaining physical matrix, independent review, and
  technical-user Alpha are complete, implement a native BLE proof of concept over the reviewed
  common transport interface, with untrusted discovery, bounded fragmentation, explicit phone
  selection, and fail-closed reconnect.
- [ ] Evaluate Wi-Fi discovery, cold-start behavior, background lifetime, interface binding, LAN
  isolation, and response routing before promoting the foreground owner PoC into a production
  transport. Wi-Fi must deliver requests to the same native authorization controller and must not
  require a weaker or cached approval path.
- [ ] Retain ADB as a development, diagnostics, and recovery transport after a production
  convenience transport is available; do not treat the technical-Alpha default as a
  general-availability commitment.
- [ ] Treat a dedicated non-ADB USB transport as an evidence-driven decision gate, not a scheduled
  implementation. Start a proof of concept only if technical-Alpha evidence shows that BLE and
  Wi-Fi cannot cover a required scenario, ADB's USB-debugging and broad-authorization prerequisites
  materially block adoption, and stock Android plus Windows can support a maintainable USB
  accessory path without OEM customization. Any proof of concept must reuse the common one-shot
  framing and the existing authenticated pairing and unwrap protocol.
- [ ] Evaluate Windows ARM64, Linux, iOS, and macOS product packages after the Windows x64 Alpha;
  platform expansion must not add a weaker key-custody fallback.
- [ ] Define signed update, vulnerability reporting, protocol migration, support lifetime, and
  deprecation policies before general availability.
