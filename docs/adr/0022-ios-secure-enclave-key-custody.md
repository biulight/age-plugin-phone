# ADR 0022: iOS Secure Enclave key custody

Status: accepted for experimental iOS 17+ implementation

## Decision

The iOS application provisions two independent, compact-representable Secure Enclave P-256 keys.
The identity key is ECDH-only and protected by `privateKeyUsage` plus `biometryCurrentSet`. The
phone-signing key is ECDSA-only and protected by `privateKeyUsage`. Their wrapped Secure Enclave
references use `WhenUnlockedThisDeviceOnly`; public metadata uses complete file protection in an
excluded-from-backup Application Support directory.

Every unwrap constructs a new `LAContext`, sets the Touch ID reuse duration to zero, and invalidates
the context on success, cancellation, failure, or backgrounding. The signing key does not inherit
or cache identity authorization. There is no software-key, exportable-key, wrong-curve, or desktop
identity fallback.

Keychain account names contain only a fixed versioned role prefix and a random 128-bit identity ID.
Metadata binds the identity ID, both compressed public keys, recipient, version, and journal state.
Opening re-derives and compares every public value. Provisioning and deletion use `preparing`,
`committed`, and `deleting` states so interruption cannot silently create a replacement identity or
empty replay scope.

## Consequences

- Changing the enrolled biometric set invalidates the identity key; the app must not substitute a
  new key.
- Simulator builds cover UI, compilation, and non-hardware tests only.
- Recovery requires an independently generated recipient.
- Doctor output must not contain key references, protocol messages, stanzas, QR contents, or file
  keys.
