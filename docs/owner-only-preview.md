# Owner-only technical preview scope

Status: active deployment posture from 2026-08-31. The application is currently operated only by
its repository owner. This is not a public Alpha, a multi-user trial, or approval for production
secrets.

## Current operating profile

- One known Windows 11 x64 desktop with TPM 2.0 and Microsoft Platform Crypto Provider.
- One capability-qualified Android StrongBox phone with fresh auth-per-use biometric authorization.
- Developer USB remains the independently exercised recovery and diagnostics transport.
- Foreground Wi-Fi discovery, unwrap, and explicit one-shot pairing are implemented in source.
  Recorded single-device passes support continued owner testing, but the remaining adverse-condition
  matrix prevents a production transport claim and no background-wake support is claimed.
- One independently verified private-root test-signed Windows/Android artifact pair at a time.
- Synthetic or otherwise disposable data with a separately verified independent recovery recipient.

The `v0.1.0-alpha.1` pair from commit `be1e85e` passed the owner-preview publication regression on
the recorded single-device setup: fresh exact-package pairing, Developer USB unwrap, independent
recovery, foreground Wi-Fi unwrap, foreground/background listener lifecycle, final listener pause,
and zero ADB reverse residue. This supports publication of the developer prerelease only; it does
not mark any deferred public-Alpha gate as passed.

As of 2026-10-27, the latest published release is `v0.1.0-beta.2` from `e08d631`.
Its exact-commit CI, four-crate publication and Windows/Android signing workflows passed.
The [2026-10-23 exact-package run](beta2-package-acceptance-2026-10-23.md) subsequently
recorded the scoped `phone` multi-identity, failure/recovery and foreground Wi-Fi cases.
It also reproduced automatic-discovery failure after network restoration. That failure
remains attached to the published Beta 2 bits; the overall P1 matrix is not marked passed.

The [Android recovery repair](android-wifi-network-recovery.md) is merged at `196943f`
and passed scoped tests on separately identified, unpublished same-signer APKs. The first
fix's first-discovery result does not transfer to final R2, whose replay relay used a
direct endpoint before discovery recovery. Final-pair first discovery, separate `phone`
and `tag` acceptance, and cancelled-request replay after app restart remain open in the
[execution plan](roadmap.md). Existing pairing reuse is not fresh-pairing acceptance, and
an in-place update is not the complete upgrade/invalidation matrix.

P1 synthetic regressions and archive checks are now configured in the CI workflow;
CI success verifies tooling and recorded evidence, never a new physical phone operation.
Neither the scoped package results, merged repair nor CI integration expands this
owner-only operating profile or establishes production-secret support.

QR framing, native camera transport, private multi-phone stanza selection, lifecycle controls, and
strict wrong-device/replay rejection remain implemented capabilities. Their presence does not mean
that the active artifact pair has passed the corresponding physical matrix.

## Deferred capability evidence

The following work is recorded but deferred while the application remains owner-only:

- rerun exact-candidate QR fallback plus captured-response replay with the attached Windows UVC
  camera; the owner-only exploratory run is recorded in `alpha-evidence-candidate.md` but does not
  transfer to an exact candidate;
- test a wrong paired physical phone, multiple physical phones, and a second independently
  capability-qualified StrongBox device family;
- complete the remaining multi-device lifecycle, invalidation, upgrade, and migration matrix;
- move Windows distribution signing from the private test root to a publicly trusted open-source
  signing program; and
- conduct a limited technical-user Alpha with people other than the repository owner.

These are deferred gates, not passed gates. Historical evidence from another commit or artifact
pair never transfers to the active candidate.

## Re-entry gate for broader use

Before giving the application or protected data workflow to another user, claiming a public Alpha,
or selecting a production convenience transport, reactivate every deferred item above against one
exact signed artifact pair. The public-Alpha decision still requires the complete matrix in
[`alpha-matrix.md`](alpha-matrix.md), a frozen compatibility policy, and the documented public
signing and technical-user gates.

Owner-only use does not relax any protocol or custody invariant: Windows stores no reusable age
private identity, every unwrap requires fresh phone user verification, failures remain fail closed,
transport properties provide no authentication, and an independent recovery recipient remains
required. Protocol v2 is still experimental and must not protect real secrets.
