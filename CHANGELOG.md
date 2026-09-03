# Changelog

All notable changes to this project are documented here. This project has not frozen its wire
format; prerelease upgrades may require re-pairing and re-encrypting through an independent
recovery recipient.

## [Unreleased]

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

[Unreleased]: https://github.com/biulight/age-plugin-phone/compare/v0.1.0-alpha.3...HEAD
[0.1.0-alpha.3]: https://github.com/biulight/age-plugin-phone/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/biulight/age-plugin-phone/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/biulight/age-plugin-phone/releases/tag/v0.1.0-alpha.1
