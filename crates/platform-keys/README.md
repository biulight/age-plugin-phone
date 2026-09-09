# age-plugin-phone-platform-keys

Windows TPM and macOS CryptoKit Secure Enclave desktop key custody.

Experimental alpha software, unsuitable for real secrets. The macOS backend is
PR 2 of the support plan; complete macOS product support remains pending storage,
setup/lifecycle, transport/caller, installation and security acceptance.

On macOS, Cargo builds the included `native/Keys.swift` into a static bridge with
`xcrun swiftc` (Xcode or Command Line Tools required). The development deployment
floor is macOS 14.0; only the current arm64 macOS 26.6.2 host has native evidence.
No publisher certificate, entitlement, helper executable or App is required on
that tested host. Other OS versions and Intel/T2 remain unverified.

`MacosSigner` and `MacosKeyAgreement` expose separate operation interfaces, generated
only through CryptoKit Secure Enclave types with `WhenUnlockedThisDeviceOnly` and
`privateKeyUsage`. They have no software fallback. Their opaque encrypted references
must be kept in protected local metadata and must not be logged. References are
not exportable private scalars. Removing a reference is local cleanup, not destruction
of all copies or phone-side revocation. Phone unwrap always needs fresh phone verification.

Ordinary tests do not generate hardware keys. The ignored native test can be run
explicitly on real hardware with `cargo test -p age-plugin-phone-platform-keys
native_roles_prehash_ecdh_and_reopen --locked -- --ignored`.
The separate `macos-key-probe` example and `scripts/macos-cargo-probe` remain M0
research tools, never product operation interfaces.

See [the repository](https://github.com/biulight/age-plugin-phone) for architecture,
installation, the macOS support plan and evidence.
