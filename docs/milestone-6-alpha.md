# Milestone 6 Alpha release and evidence

Status: repository implementation is in progress. Active private-root test-signed candidate
`be1e85e` has independently verified packages and passed the minimal exact-package regression for
the first developer prerelease. The preceding `18a94c8` candidate passed broader one-phone age,
rage, Shine, and negative-path work, but those results do not transfer to the new artifact pair.
QR/replay, packaged lifecycle/invalidation, multi-phone, public-trust Windows signing, and
technical-user gates remain open. The independent source review is complete, with native/physical
evidence tracked separately.

The current application posture is the owner-only technical preview defined in
[`owner-only-preview.md`](owner-only-preview.md). External-device, public-signing, and
technical-user gates below are intentionally deferred while no other user receives the
application; they remain mandatory before a broader or public Alpha claim.

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

Windows local cleanup is separately explicit and fingerprint-confirmed. It validates the public
stub, private locator, replay scope, TPM metadata, and both TPM public keys before committing a
private cleanup journal. The journal blocks the target pairing and resumes exact replay, metadata,
locator, public-stub, and role-separated CNG-key deletion after interruption without changing an
unrelated pairing. Local success is not represented as phone-side revocation.

## CI and reproducible inputs

`.github/workflows/ci.yml` gates locked Rust formatting, Clippy, tests, and deterministic vectors on
Linux and Windows; a Windows release-binary smoke test; a locked Bun/TypeScript production build;
Kotlin vectors and negative tests; and committed Cargo, Bun, and Gradle wrapper inputs. It also
downloads checksum-pinned reference age 1.3.1 and rage 0.12.1 release binaries, then exercises the
production plugin executable with three public phone recipients, both stanza versions, three
synthetic files, and an independent recovery identity in both cross-client directions. Malformed
phone recipients must fail without a non-empty ciphertext. The Gradle distribution SHA-256 is
pinned.

The CI smoke test proves only that the packaged executable starts. TPM/StrongBox behavior must be
tested on the physical Alpha matrix and cannot be waived by a hosted runner.

## Signed artifacts

`.github/workflows/alpha-release.yml` is manually dispatched and fail closed. It requires:

- a protected GitHub `alpha-release` environment with required reviewers;
- a separate protected `alpha-release-publish` environment with the same reviewer protection but
  no signing credentials; and
- a Windows test-root public certificate, a test-root-issued code-signing PFX, its password, and
  separately registered leaf and root certificate SHA-256 fingerprints; and
- `ANDROID_KEYSTORE_BASE64`, `ANDROID_STORE_PASSWORD`, `ANDROID_KEY_ALIAS`,
  `ANDROID_KEY_PASSWORD`, and the pre-registered `ANDROID_CERTIFICATE_SHA256`.

The Windows job authenticates the restored leaf and root certificates against their registered
fingerprints, validates their exact chain in memory without changing a Windows trust store, signs
by certificate thumbprint, and records that the result is test-trusted rather than publicly
trusted. The Android job authenticates the restored PKCS#12 certificate against the registered
fingerprint before building, then requires exactly one APK signer with that same fingerprint. The
workflow never publishes an unsigned or unexpectedly signed substitute when configuration is
absent or mismatched. All third-party Actions in the signing workflow are pinned to resolved
commits.

It runs Authenticode verification on the exact Windows executable before packaging and
`apksigner verify` on the exact Android APK, then uploads signature-verification evidence and
SHA-256 records beside the packages. Restored signing files exist only in runner-temporary storage
and are removed by unconditional cleanup steps. Evidence records artifact SHA-256, immutable
commit, workflow run and attempt, certificate identity, trust scope, and verification result
without exposing credentials. Provisioning, RC0 dispatch, and the later free SignPath Foundation
migration are documented in [`release-signing.md`](release-signing.md).

The workflow is dispatched with the full candidate SHA rather than by a final-tag trigger. The
publish job remains paused at `alpha-release-publish` while reviewers download artifacts from that
same run and complete the exact-package physical matrix. Approval causes the job to stage and
revalidate six versioned assets, create the annotated tag and a draft prerelease, verify remote
asset hashes, and finally expose the prerelease. Final tags, releases, assets, and cross-run
evidence are never managed by hand.

The private-root Windows result does not close a public-trust release gate. It is an explicit RC
pipeline test until the project qualifies for and is accepted into a public code-signing program.

The first RC0 execution completed both signing jobs and independent artifact verification. The
later candidate from commit `18a94c8` completed the historical physical rows recorded in
[`alpha-evidence-candidate.md`](alpha-evidence-candidate.md). Active candidate `be1e85e` completed
both signing jobs and independent package verification in workflow `33671049489`, attempt 1, then
passed the documented minimal Developer USB, independent-recovery, foreground Wi-Fi, and lifecycle
publication regression. Broader historical rows still require an exact-candidate rerun. None of
these results make the private Windows test root publicly trusted.

## Remaining external gates

Do not mark Milestone 6 complete until signed artifacts pass every required row in
`alpha-matrix.md`. These gates require external software, physical devices, or people:

- the remaining physical rows for the exact signed candidate and its recorded digests, including a
  fresh candidate pairing, camera-based QR/replay, lifecycle, and invalidation;
- publicly trusted Windows signing before claiming a publicly trusted Windows Alpha;
- physical reference age and rage interoperability through multiple phones, including a wrong
  paired phone and a second capability-qualified StrongBox family;
- physical lifecycle, invalidation, wrong-device, replay, upgrade, and fresh-pair migration
  matrices;
- a limited technical-user Alpha proving Windows has no reusable age identity and every unwrap
  caused a fresh phone biometric operation.

Reports must follow `alpha-matrix.md`: never record raw protocol messages, QR contents, stanza
bodies, file keys, plaintext, private paths, key aliases, or device serials.
