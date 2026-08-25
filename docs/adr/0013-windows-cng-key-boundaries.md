# ADR 0013: Windows CNG key-operation boundaries

- Status: implemented and TPM-validated; not integrated with the experimental wire protocol
- Date: 2026-08-25
- Scope: desktop signing and private-selection key custody on Windows 11 x64

## Context

The version 1 pairing state uses one software P-256 signing scalar for both request signatures and
version 2 stanza selection. Milestone 3 requires two role-separated, non-exportable TPM keys and a
new pairing transcript that binds their public keys independently. The protocol and recipient
implementations previously accepted concrete RustCrypto private-key types, which made a hardware
implementation impossible without exporting its scalar.

## Decision

Protocol signing accepts a `P256Signer` operation boundary. The protocol hashes the exact existing
domain-separated canonical input with SHA-256, and an implementation signs that digest and returns
a fixed-width low-S IEEE P1363 signature. Private stanza selection accepts a separate
`P256KeyAgreement` boundary that returns only the raw, big-endian P-256 ECDH x-coordinate. Public
parsing, HKDF, AEAD, selector authentication, and constant-time identity comparison remain in the
portable Rust crates.

The `age-plugin-phone-windows-cng` crate is the only desktop CNG FFI boundary. It:

- opens only `Microsoft Platform Crypto Provider`, with no software-provider or DPAPI fallback;
- creates separate current-user `ECDSA_P256` signing and `ECDH_P256` selection keys;
- never overwrites an existing key and fails closed if only one role exists;
- requires an export policy of zero and rejects a key if private ECC blob export succeeds;
- validates exact P-256 public blobs before converting them to canonical compressed SEC1 points;
- normalizes TPM ECDSA output to low-S and zeroizes transient signature and ECDH buffers; and
- reverses CNG's documented little-endian raw-secret result before returning the protocol's
  big-endian ECDH value.

Key names contain only the desktop identifier and fixed role suffixes. Caller labels and protocol
payloads never enter a key name, Windows property, file, shell argument, or log.

The existing version 1 desktop state is not migrated. The CNG key set is deliberately not wired to
pairing or unwrap until the new transcript, public stub, paired recipient, locator, and replay state
all bind both public roles and reject version 1 state atomically. Existing Windows pairing remains
fail-closed rather than falling back to a file private key.

## Consequences

- CNG implementation details and unsafe FFI are isolated from crates that forbid unsafe code.
- Deterministic vectors can continue using software keys through the same operation boundaries.
- A TPM-backed signer cannot accidentally be used for private selection because CNG provisions
  different algorithm-specific handles.
- This slice does not yet make Windows pairing usable and does not change the wire version.
- Partial provisioning requires explicit cleanup or repair work; it is never silently completed on
  a later open.

## Validation

Portable workspace tests cover the unchanged deterministic signatures, pairing, requests,
responses, and v2 stanza selection through the new boundaries. The Windows crate cross-compiles,
including its native test target, for `x86_64-pc-windows-msvc` with warnings denied.

The native test passed on Windows 11 x64 build 22631 with an enabled and ready TPM. It provisioned
two uniquely named keys through Microsoft Platform Crypto Provider, verified distinct public
points, verified a TPM signature with RustCrypto, compared TPM ECDH with the reciprocal software
calculation, reopened both persisted keys, and deleted only those test keys. A provider enumeration
afterward found no remaining `age-plugin-phone-` test key.
