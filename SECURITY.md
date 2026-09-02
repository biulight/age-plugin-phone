# Security policy

## Supported versions

No version is supported for production secrets. `0.1.0-alpha.1` is an experimental,
test-signed developer prerelease for synthetic or disposable data with an independent recovery
recipient.

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
