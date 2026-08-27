# Milestone 6 Alpha release and evidence

Status: repository implementation is in progress; physical, interoperability, signing, review, and
technical-user gates remain open.

## Implemented product surface

The Android release application registers the native identity plugin and uses a product-first UI.
It displays only the public recipient, coarse identity state, untrusted desktop display labels,
transcript fingerprints, and opaque management handles. Pairing and unwrap remain native one-shot
USB or QR operations. Doctor controls are visible only when Rust debug assertions are enabled, and
Doctor commands reject release-build calls.

Desktop revocation is confirmed in an Android native dialog. Storage atomically renames the exact
pairing record to a deletion-pending journal before deletion, so request lookup fails immediately.
An interrupted journal is reported but is never treated as an empty replay scope. Identity deletion
is separately confirmed and first commits an identity-wide deletion phase, then revokes all
pairings, deletes the two exact StrongBox aliases, verifies their absence, and finally removes the
public metadata. Re-running deletion resumes the same identity; provisioning cannot bypass it.

## CI and reproducible inputs

`.github/workflows/ci.yml` gates locked Rust formatting, Clippy, tests, and deterministic vectors on
Linux and Windows; a Windows release-binary smoke test; a locked Bun/TypeScript production build;
Kotlin vectors and negative tests; and committed Cargo, Bun, and Gradle wrapper inputs. The Gradle
distribution SHA-256 is pinned.

The CI smoke test proves only that the packaged executable starts. TPM/StrongBox behavior must be
tested on the physical Alpha matrix and cannot be waived by a hosted runner.

## Signed artifacts

`.github/workflows/alpha-release.yml` is manually dispatched and fail closed. It requires:

- `WINDOWS_CERTIFICATE_BASE64` and `WINDOWS_CERTIFICATE_PASSWORD`;
- `ANDROID_KEYSTORE_BASE64`, `ANDROID_STORE_PASSWORD`, `ANDROID_KEY_ALIAS`, and
  `ANDROID_KEY_PASSWORD`.

The workflow never publishes an unsigned substitute when a credential is absent. Signing files
exist only in runner-temporary storage. Evidence must record artifact SHA-256, immutable commit,
workflow run, certificate identity, and verification result without exposing credentials.

## Remaining external gates

Do not mark Milestone 6 complete until signed artifacts pass every required row in
`alpha-matrix.md`. These gates require external software, physical devices, or people:

- actual Windows and Android signing and signature verification;
- released reference age and rage interoperability with multiple phones and files;
- Shine encrypt, decrypt, seal, and recovery using its existing configuration only;
- physical lifecycle, invalidation, wrong-device, replay, upgrade, and recovery matrices;
- independent cryptographic and implementation review with findings resolved; and
- a limited technical-user Alpha proving Windows has no reusable age identity and every unwrap
  caused a fresh phone biometric operation.

Reports must follow `alpha-matrix.md`: never record raw protocol messages, QR contents, stanza
bodies, file keys, plaintext, private paths, key aliases, or device serials.
