# Security policy

## Supported versions

No version is supported for production secrets. `0.1.0-beta.1` and its `0.1.0-beta.2`
maintenance update are published for limited technical testing. The
[beta checklist](docs/beta-readiness.md) tracks their evidence and compatibility limits.
Existing hardware evidence does not establish support for every device. The
[2026-10-23 package run](docs/beta2-package-acceptance-2026-10-23.md) closes the scoped Beta 2
multi-identity regression but retains a network-restoration discovery failure in those published bits.
Both Betas use protocol v2, which remains unfrozen; independent recovery is required.
Prerelease versions before protocol freeze do not promise cross-version compatibility, automatic
migration or downgrade support. Clearly announced breaking updates may require endpoint updates,
re-pairing and recovery-based re-encryption. See the [compatibility policy](docs/protocol.md#prerelease-compatibility-policy).
Unsupported state must fail closed, never become an empty replay store. Protocol freeze alone does
not establish platform support or production-secret readiness.
See the [Beta 2 release notes](docs/releases/v0.1.0-beta.2.md). The published alpha.5
snapshot retains its [experimental scope](docs/releases/v0.1.0-alpha.5.md).

Historically, `0.1.0-alpha.4` is an experimental,
test-signed developer prerelease for synthetic or disposable data with an independent recovery
recipient. Its exact Windows/Android package pair passed
[owner-only physical acceptance](docs/windows-acceptance-2026-09-07.md) and was published on
2026-09-07. The complete public-Alpha matrix remains deferred.

## Reporting a vulnerability

Use GitHub's private security-advisory flow for this repository and include the affected version,
platform, security boundary, reproduction steps, and non-sensitive impact evidence. Do not include
private keys, file keys, decrypted plaintext, raw protocol payloads, QR contents, recovery material,
device serials, or private state paths.

If private vulnerability reporting is unavailable, open a public issue containing no vulnerability
details and ask the maintainer to establish a private channel. Do not publish an exploitable report
before a private channel is available.

Reports involving key custody, authorization freshness, request/response binding, replay state,
strict parsing, or transport independence are treated as release-blocking until resolved.
