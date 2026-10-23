# Android foreground Wi-Fi network recovery candidate

Status: implemented, built, signed and installed in place; **scoped fixed-package
physical regression passed** on the recorded Windows/Android combination.
The original published Beta 2 failure remains preserved; this is an unpublished fix.
No commit, push, publication, phone data reset or replacement-signature installation
was performed to obtain this candidate.

The [Beta 2 record](beta2-package-acceptance-2026-10-23.md) reproduced automatic
discovery failure after disabling and re-enabling phone Wi-Fi. An explicit-address
request worked, then automatic discovery worked after that session rebuilt the listener.
The old Android implementation rebuilt discovery on foreground/session transitions,
but did not observe network changes and did not require an IPv4 Wi-Fi network before
starting a listener. Thus listener and multicast-reception resources could be created
while disconnected and survive restoration. The precise stale socket/OS reception
failure was not individually instrumented; the missing lifecycle invalidation is
confirmed by source inspection.

The candidate observes Wi-Fi networks while foregrounded, including local-only
networks without internet validation. Network loss, IPv4 removal and link-address
changes invalidate the current Wi-Fi resources and pending Wi-Fi authorization.
Listener/discovery creation waits for IPv4 availability. Reconnection with the same
address still invalidates the old generation; duplicate notifications do not interrupt
a current request. Background/destroy unregister the observer, and queued notifications
from the previous observer cannot restart listening. The normal `ACCESS_NETWORK_STATE`
permission provides network observation only, not key access or unwrap authorization.
Existing cancellation, durable replay consumption and fresh native verification remain
the security boundary. No desktop retry or fallback was added.

Validation completed:

- All 78 Android plugin JVM tests passed, including three new network-state tests and
  existing cancellation, malformed message, replay and key-boundary cases.
- The ARM64 release APK built successfully. The original signing backup was located
  through the historical credential-setup record and used on its existing Windows
  host without exporting the private key. The actual certificate and signed APK
  both matched the published Beta 2 signer. The APK was installed with `install -r`
  after verifying the installed baseline, then pulled back and hash-checked; no
  uninstall or data clear occurred. See [signing](evidence/android-wifi-network-fix-signing-2026-10-23.json)
  and [installation](evidence/android-wifi-network-fix-install-2026-10-23.json) evidence.
- Windows P1 checked-ADB/failure regression fixtures passed. This does not count as
  Windows-to-phone validation of the new APK.
- [Candidate metadata](evidence/android-wifi-network-fix-2026-10-23.json) binds source
  files and the unsigned APK by SHA-256.

The [physical evidence archive](evidence/android-wifi-network-fix-2026-10-23/README.md)
records ten owner-observed requests and two checked Wi-Fi cycles. Both idle and
pending-authorization network loss/restoration passed on the **first automatic-discovery
request**, with fresh native verification and no direct-address workaround or manual
listener toggle. The interrupted request failed without output after the desktop's
bounded read timeout. Cancellation/background and fresh recovery also passed. Both
exact signed-request replays were closed without response or new phone prompt while
290+ seconds remained before expiry; a fresh direct Wi-Fi request then succeeded.

The owner paused auto-listen and confirmed usable controls at completion. Disposable
synthetic inputs and recovery key were removed, and the checked reverse-rule audit
passed. The signed installed APK SHA-256 is
`87a9262a724aaf2d3fad191fca8ba697e03ea39b34608a22eca09458c9caa95f`.
This does not establish roaming to another AP/subnet, another phone family, or replay
persistence across restart. The precise original OS socket/multicast failure remains
unproven; the reproduced recovery symptom no longer occurred in these fixed-package cases.

The repository's signing workflow normally restores its keystore from the protected
`alpha-release` GitHub environment. Historical setup also retained an original
password-encrypted keystore and a user-bound DPAPI password backup on the signing
host. This run used that existing backup locally; no CI dispatch, commit or push
was needed. Backup paths, aliases and credentials are deliberately absent here.

## Review follow-up, 2026-10-24

A second unpublished candidate fixes the observation-registration failure path.
Registration retries use 1–30 second capped backoff while foregrounded. Closing the
observer invalidates both queued notifications and retries before unregistering it.
The retry affects only network observation, never a signed unwrap request.

The plugin now uses a small shared ownership component for request publication,
response handoff and cancellation. Tests exercise that production component rather
than duplicating token comparisons in test-only code. The 87 JVM tests pass, including
old observer delivery after stop/start, failed registration recovery, failed unregister,
old worker publication, late biometric/timeout/disconnect callbacks, cancellation after
response handoff, and durable rejection of the exact network-cancelled request.

The [second candidate archive](evidence/android-wifi-network-r2-2026-10-24/README.md)
records the Git base commit/tree, a complete scoped source inventory, changed-source
snapshots, build command/toolchain, and the unsigned → signed → installed APK hash chain.
The previous candidate's limited provenance remains historical; it is not retroactively
upgraded to this stronger record. Windows checked-ADB and replay-assertion regressions
passed. The second candidate also passed five owner-observed Windows/Android cases:
automatic-discovery baseline, network cancellation and exact replay rejection, fresh
automatic-discovery recovery, background cancellation and foreground recovery. Both
network-cancelled replays were rejected with more than 180 seconds left before expiry.
The relay uses an explicit endpoint; this is not a repeat of the previous candidate's
first-discovery-before-any-direct-connection test. An earlier attempt that expired
before network switching was excluded. Synthetic inputs were removed and reverse-rule
audit passed. The owner confirmed auto-listen paused and page controls operational
at completion.

The subsequent P2 tooling review replaced removable Python assertions in the replay
probe with explicit validation and added actual-driver subprocess regressions in normal
and optimized modes. The evidence checker now validates accepted/excluded summaries
against report hashes, machine results and owner observations, including rehashed
contradictory archives. Both macOS and Windows regressions passed. The second candidate
archive keeps the original physical drivers and records these later tools separately
under `p2-review/`; this follow-up neither rebuilt the APK nor repeated phone requests.

The final tooling follow-up also requires network-cycle timestamps to fall within the
request interval and covers manual/automatic network cancellation in all three Python
modes. Both hosts passed 66 actual-driver fixture combinations. Six complete suite
records, including per-child details and source snapshots, are archived in
[p2-time-review](evidence/android-wifi-network-r2-2026-10-24/p2-time-review/README.md).
No additional physical request or APK change was made for this validation-only work.
