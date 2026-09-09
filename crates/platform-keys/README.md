# age-plugin-phone-platform-keys

Windows TPM key custody. macOS Secure Enclave keys are not implemented.

Experimental alpha software, unsuitable for real secrets. Non-Windows desktop behavior remains a software prototype; this package does not add macOS hardware support.

An explicit `macos-key-probe` example provides isolated M0 Secure Enclave research.
It is never called by the product or ordinary tests and requires a fresh random test
scope. The original Keychain probe is blocked; a separate Cargo/CryptoKit fixture has
passed local source-install tests. Neither is a product backend. See the repository's
[`docs/macos-m0-evidence.md`](https://github.com/biulight/age-plugin-phone/blob/main/docs/macos-m0-evidence.md)
for execution, exact cleanup, and outstanding acceptance requirements.

See https://github.com/biulight/age-plugin-phone for architecture and installation.
