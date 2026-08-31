# Owner-only technical preview scope

Status: active deployment posture from 2026-08-31. The application is currently operated only by
its repository owner. This is not a public Alpha, a multi-user trial, or approval for production
secrets.

## Current operating profile

- One known Windows 11 x64 desktop with TPM 2.0 and Microsoft Platform Crypto Provider.
- One capability-qualified Android StrongBox phone with fresh auth-per-use biometric authorization.
- Developer USB through one explicitly selected ADB device as the normal transport.
- Optional, default-off foreground Wi-Fi auto-listen experimentation through one explicit private
  IPv4 route; no discovery, background wake, pairing, fallback, or production transport claim.
- One independently verified private-root test-signed Windows/Android artifact pair at a time.
- Synthetic or otherwise disposable data with a separately verified independent recovery recipient.

QR framing, native camera transport, private multi-phone stanza selection, lifecycle controls, and
strict wrong-device/replay rejection remain implemented capabilities. Their presence does not mean
that the active artifact pair has passed the corresponding physical matrix.

## Deferred capability evidence

The following work is recorded but deferred while the application remains owner-only:

- attach a Windows UVC camera and rerun exact-candidate QR fallback plus captured-response replay;
- test a wrong paired physical phone, multiple phone identities, and a second independently
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
