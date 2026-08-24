# ADR 0007: Android production key custody

## Status

Accepted for the bidirectional QR prototype.

## Context

The disposable StrongBox probe proves that an authentication-per-use P-256 ECDH operation works on
the target Android device. Pairing cannot reuse that probe: its alias is tracked in preferences, its
lifetime is deliberately disposable, and its protocol signing key currently exists only in memory.
Creating a pairing response before both persistent phone key roles exist would produce pairing state
that cannot be used after process death.

## Decision

Android owns two independent, non-exportable P-256 keys in `AndroidKeyStore`:

- the age identity key has only `PURPOSE_AGREE_KEY`, is StrongBox-backed, requires
  `BIOMETRIC_STRONG` for every operation, and is invalidated by biometric enrollment changes;
- the phone authentication key has only `PURPOSE_SIGN`, uses SHA-256, is StrongBox-backed, and does
  not cache or require user authentication. It signs already-authorized protocol statements and is
  never accepted as an age identity key.

There is no TEE or software fallback. Key inspection rejects the wrong security level, origin,
purpose, authentication policy, curve, or exportability.

The app stores only a random 128-bit identity identifier, the tagged public recipient, and the two
compressed public keys. Private keys remain in StrongBox. Aliases are strictly derived from the
identifier and a role-specific versioned prefix; caller-provided labels never enter an alias.

Public metadata lives under `Context.noBackupFilesDir` with private permissions. Provisioning first
atomically commits a canonical CBOR `preparing` journal containing the identifier, generates and
inspects both keys, and then atomically replaces the journal with canonical `committed` metadata.
An interrupted `preparing` state is recoverable only by deleting the two exact derived aliases before
retrying. A committed or malformed state fails closed and is never overwritten. Metadata is accepted
only when it exactly matches both live Keystore certificates and the tagged recipient.

Doctor validation uses separate storage and alias namespaces and removes all of its artifacts. It
must cover reopen, duplicate creation, interrupted-creation recovery, public-metadata binding, role
separation, and cleanup.

## Consequences

Pairing-response generation can now be wired to stable key handles without ever exporting private
material. Loss or invalidation of either key makes the identity unusable; recovery and replacement
remain explicit future protocol work. Android devices without the required StrongBox and strong
biometric capabilities cannot provision this identity type.
