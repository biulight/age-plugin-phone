# Changelog

All notable changes to this project are documented here. This project has not frozen its wire
format; prerelease upgrades may require re-pairing and re-encrypting through an independent
recovery recipient.

## [Unreleased]

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

[Unreleased]: https://github.com/biulight/age-plugin-phone/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/biulight/age-plugin-phone/releases/tag/v0.1.0-alpha.1
