# Changelog

All notable changes to this project are documented here. This project has not frozen its wire
format; prerelease upgrades may require re-pairing and re-encrypting through an independent
recovery recipient.

## [Unreleased]

### 0.1.0-beta.1 candidate

- Explicit native tagged recipients on desktop, Android and iOS; public-only export
  and encryption without the phone plugin using age 1.3+. Default remains `phone`.
- iOS per-operation authentication deadline closes expired prompts and rejects late
  completion without resetting replay consumption.
- Valid nonmatching phone stanzas now return an ordinary identity miss, allowing reference age to
  continue to later configured phone identities while preserving fatal state and structure errors.
- Recorded signed-candidate hardware, mixed-recipient, recovery and Shine 2.0.3
  evidence; final beta artifacts and remaining physical gates are still pending.
- Alpha/Beta release-channel validation and a limited technical-user
  [closeout plan](docs/beta-readiness.md), with Windows/macOS source installation.

See the [candidate notes](docs/releases/v0.1.0-beta.1.md). Not yet published.

## [0.1.0-alpha.5] - 2026-09-10

Interim experimental release; additional macOS physical acceptance is deferred by the
[user-approved scope decision](docs/macos-release-scope-decision.md), not marked passed.

### Added

- Four separately packaged desktop crates with exact internal dependency versions.
- macOS Secure Enclave dual-key custody, protected native storage, managed/explicit
  pairing journals, setup resume and normal/orphan cleanup, delivered through source installation.
- macOS build, archive, state-continuity and native acceptance evidence and recovery guides.

### Fixed

- macOS compact IPv4 netmask parsing, interface-scoped Wi-Fi discovery and response polling.
- Android foreground discovery reception ownership and payload-free discovery diagnostics.

### Scope

- Existing records cover exact earlier candidate artifacts; no new alpha.5 physical pass is claimed.
- Valid desktop replay snapshot restoration remains an explicit Windows/macOS limitation.
- Tagged recipients are the next implementation stage and are not included in this release.

See the [release notes](docs/releases/v0.1.0-alpha.5.md) for platform and artifact boundaries.

## [0.1.0-alpha.4] - 2026-09-07

Fourth test-signed developer prerelease. Exact signed-package owner-only acceptance passed.

### Added

- Experimental iOS 17+ Secure Enclave source implementation with native QR, foreground Wi-Fi,
  fresh Face ID/Touch ID authorization, and Swift protocol tests. No signed iOS artifact or
  physical-device acceptance is included in this Windows/Android candidate.
- Payload-free Windows `wifi-doctor` discovery diagnostics and an inspectable, scoped Windows
  firewall helper, included with the Wi-Fi guide in the Windows ZIP.
- An owner-assisted minimal Windows acceptance script and an alpha.4 exact-package checklist.

### Fixed

- USB and Wi-Fi pairing show loading state and disable duplicate submissions until completion.
- Android Activity-stop cleanup dismisses pending native pairing confirmation and closes USB,
  Wi-Fi, and authentication resources; returning to the foreground permits a fresh operation.
- Wi-Fi pairing UI handoff is guarded against stale completion.

### Validation

- Earlier alpha.3 signed-package and subsequent isolated debug UI/Wi-Fi evidence remain historical.
  They do not certify the alpha.4 package pair.
- The exact alpha.4 Windows/Android pair passed minimum unwrap, manual pairing/discovery,
  alpha.3 in-place upgrade, independent recovery and final cleanup. See the
  [acceptance record](docs/windows-acceptance-2026-09-07.md). The complete public-Alpha matrix
  remains deferred; firewall evidence is limited to current-host Inspect and `-WhatIf`.

## [0.1.0-alpha.3] - 2026-09-04

Third test-signed developer prerelease.

### Added

- Added bounded Wi-Fi discovery for an existing paired phone and a one-shot foreground Wi-Fi
  pairing route. Discovery selects only a response authenticated by the paired phone key; before
  pairing it is an unauthenticated delivery hint.

### Changed

- `auto` now makes one deterministic Wi-Fi-first route decision before it creates a pairing or
  unwrap session. Explicit transport hints remain pinned, ambiguity fails closed, and failures
  never fall back in flight.

### Fixed

- Foreground Wi-Fi listeners reliably re-arm after pairing and after completed or failed unwrap
  sessions while the phone remains in the foreground.

## [0.1.0-alpha.2] - 2026-09-03

Second test-signed developer prerelease.

### Added

- Added `setup --json`, a versioned public handoff that reports the created public identity stub
  path and phone recipient for callers such as Shine while keeping interactive pairing on stderr.

### Changed

- Developer USB and Wi-Fi unwraps no longer emit informational `message` callbacks by default. Set
  `AGE_PLUGIN_PHONE_MESSAGES=1` to opt into desktop guidance; QR continues to render its one-time
  request in the terminal because that output is functional. Age clients may still present their
  own progress indicators independently of the plugin.

### Fixed

- Windows managed identity setup now stages and commits its TPM-backed desktop state
  transactionally, failing closed on interrupted or incomplete setup.

## [0.1.0-alpha.1] - 2026-09-03

First test-signed developer prerelease.

### Added

- Phone-held StrongBox P-256 identity with fresh biometric authorization for every unwrap.
- Windows 11 x64 TPM-backed desktop signing and private stanza-selection keys.
- Standard `age` and `rage` recipient/identity plugin integration.
- Developer USB, native QR, and explicit foreground-only Wi-Fi unwrap transports.
- Durable request and response replay protection, paired-desktop revocation, phone identity
  deletion, and crash-safe Windows cleanup.
- Independent recovery-recipient workflows and signed Windows/Android artifact generation.

### Validation

- Exact test-signed artifacts from commit `be1e85e` passed fresh StrongBox identity provisioning,
  full-fingerprint Developer USB pairing, a fresh-biometric Developer USB unwrap, and an
  independent-recovery decrypt of the same synthetic ciphertext.
- The same exact package pair passed an explicit foreground Wi-Fi unwrap, foreground/background
  listener termination and resume, final listener pause, and zero ADB reverse-rule residue.

### Known limitations

- Protocol version 2 is experimental and may change incompatibly.
- Windows artifacts are signed by a private test root and show an untrusted-publisher warning.
- Only one Android StrongBox device family has completed physical validation.
- BLE is unavailable; the designated Windows/Android feasibility run did not complete GATT service
  discovery.
- Foreground Wi-Fi has no discovery, background wake, authenticated route establishment, reconnect,
  or availability guarantee.
- This prerelease is for synthetic or disposable data with a separately verified independent
  recovery recipient. It is not a public-Alpha or production-secret claim.

[Unreleased]: https://github.com/biulight/age-plugin-phone/compare/v0.1.0-alpha.5...HEAD
[0.1.0-alpha.5]: https://github.com/biulight/age-plugin-phone/compare/v0.1.0-alpha.4...v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/biulight/age-plugin-phone/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/biulight/age-plugin-phone/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/biulight/age-plugin-phone/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/biulight/age-plugin-phone/releases/tag/v0.1.0-alpha.1
