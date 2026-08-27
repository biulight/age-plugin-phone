# ADR 0013: Windows CNG key-operation boundaries

- Status: implemented, TPM-validated, and integrated with desktop protocol version 2
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

- requires a Windows 11-or-later x64 client and rejects Windows Server;
- obtains the TPM version directly with `Tbsi_GetDeviceInfo` and accepts only `TPM_VERSION_20`;
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

The existing version 1 desktop state is not migrated. On Windows, production pairing, private v2
stanza selection, and request signing now use this operation boundary. The only desktop key file is
an ACL-protected `APTM2` record containing the random desktop identifier used to locate the two CNG
keys; it contains no scalar. Opening an existing pairing never provisions missing TPM keys. A
missing, partial, wrong, exportable, or unavailable key set fails closed without a software or
DPAPI fallback.

The capability check is read-only: it reads the actual kernel Windows version, queries TPM Base
Services, and opens then closes the Platform Crypto Provider. It does not create or open persisted
keys. Pairing, explicit unwrap, and standard age `identity-v1` entry enforce it before protocol
work. The `status` command reports each coarse capability separately so an unsupported host is
diagnosable without exposing key names or other private state.

## Consequences

- CNG implementation details and unsafe FFI are isolated from crates that forbid unsafe code.
- Deterministic vectors can continue using software keys through the same operation boundaries.
- A TPM-backed signer cannot accidentally be used for private selection because CNG provisions
  different algorithm-specific handles.
- The same portable software implementation remains available only on non-Windows prototypes,
  deterministic vectors, and tests; Windows production paths cannot select it.
- Partial provisioning requires explicit cleanup or repair work; it is never silently completed on
  a later open.

## Validation

Portable workspace tests cover the unchanged deterministic signatures, pairing, requests,
responses, and v2 stanza selection through the new boundaries. The Windows crate cross-compiles,
including its native test target, for `x86_64-pc-windows-msvc` with warnings denied.

Pure policy tests reject non-x64 builds, pre-Windows-11 builds, Windows Server, missing TPM 2.0,
and an unavailable Platform Crypto Provider independently, and accept later Windows versions.

The native test passed on Windows 11 x64 build 22631 with an enabled and ready TPM. It provisioned
two uniquely named keys through Microsoft Platform Crypto Provider, verified distinct public
points, verified a TPM signature with RustCrypto, compared TPM ECDH with the reciprocal software
calculation, reopened both persisted keys, and deleted only those test keys. A provider enumeration
afterward found no remaining `age-plugin-phone-` test key.

On the same Windows 11 x64 build 22631 host, the read-only status probe reported client edition,
x64, TPM 2.0, and Microsoft Platform Crypto Provider as available. The restricted build sandbox
could not access TPM or the provider and therefore reported the platform as unsupported, while the
same binary run in the native user context reported it as supported; both outcomes failed closed
without creating a persisted key.
