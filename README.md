# age-plugin-phone

Approve individual [age](https://age-encryption.org/) decryption operations on
your phone while keeping its long-term decryption key off the desktop. Works
through the standard age plugin interface and is independent of Shine.

> **Limited technical beta:** `0.1.0-beta.2` was published on September 11, 2026.
> Protocol v2 is unfrozen. Use synthetic or disposable data only, with an
> independently verified recovery recipient. Do not use it to protect real secrets.

## User manual

- [English](docs/manual/index.md)
- [简体中文](website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/index.md)
- [Support and prerequisites](docs/manual/support.md)
- [First encryption and decryption](docs/manual/quick-start.md)
- [Upgrade, revocation, and recovery](docs/manual/guides/recovery.md)

The beta provides Windows/macOS source installation, a test-signed Windows x64
ZIP, and a signed Android ARM64 APK. macOS remains experimental and iOS remains
an existing development-device cohort, without external distribution. BLE is
not implemented. Published packages do not certify every hardware combination.

See the [Beta 2 release](https://github.com/biulight/age-plugin-phone/releases/tag/v0.1.0-beta.2)
for artifacts and the [version guide](docs/manual/reference/releases.md) for known
limitations, including the pending exact-package regression repeat.

## Development and security

- [Development entry points](docs/development.md)
- [Architecture](docs/architecture.md), [protocol](docs/protocol.md), and [threat model](docs/threat-model.md)
- [Security policy](SECURITY.md)
- [Release and acceptance tracking](docs/beta-readiness.md)
- [Documentation maintenance](docs/documentation-maintenance.md)

User manuals are maintained in this repository in English and Simplified Chinese.
The Biulight blog provides the product portal. Internal design and release records
are not part of the published user manual.
