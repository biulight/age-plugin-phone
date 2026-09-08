# Frozen locator v3 encoder

`locator_v3.rs` copies the CBOR encoding sequence from `locator::encode_record`
at baseline `5da4b0bc8f3ca6f16f9be1b7430e923baad402b9` (`0.1.0-alpha.4`), adapting
only its input fields and infallible test error handling. It calls no new locator
code and needs no old checkout or user state.

The archived golden output was produced by that encoder with desktop ID `[1;16]`,
identity ID `[2;16]`, fingerprint `[3;32]`, desktop path `/baseline/desktop.key`,
replay path `/baseline/replay.cbor`, and transport `auto`.
SHA-256 of `locator-v3.cbor`:
`347f48e34f87d7cb1c6d48c15e47b3deb412e4f1594567ff263c4cabd98ddb05`.

The test first verifies that exact output, then uses the frozen encoder with the
temporary directory's absolute paths and synthetic stub. The new implementation
must open it unchanged, resolve paths, and reject a wrong transcript binding.
