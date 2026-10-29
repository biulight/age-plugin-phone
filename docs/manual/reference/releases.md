---
title: "Versions and known limitations"
sidebar_position: 2
---

# Versions and known limitations

This manual targets **0.1.0-beta.2**, a limited technical beta published on September 11, 2026. Use disposable or synthetic data only. Protocol v2 remains unfrozen; publication does not expand hardware acceptance or authorize production-secret use.

## Compatibility before protocol freeze

Beta 1 and Beta 2 both use protocol v2 and remain limited technical-test releases. Prerelease
versions before protocol freeze do not promise cross-version compatibility, automatic state
migration or downgrade support. A clearly announced breaking update may require updating both
endpoints, re-pairing and recovery-based re-encryption. Read the affected versions, update order
and retained-file consequences in the release notes before upgrading; follow the
[recovery guide](../guides/recovery.md). Sharing the protocol number does not guarantee all features
work with an older phone app.

Stable compatibility commitments will start at an explicitly declared freeze baseline, without
retroactively covering earlier prereleases. Protocol freeze alone will not establish support for
additional devices or production-secret use.

## Beta 2

The [GitHub release](https://github.com/biulight/age-plugin-phone/releases/tag/v0.1.0-beta.2) provides a signed Android ARM64 APK, a test-signed Windows x64 ZIP, checksums, and signature-verification records. Windows and macOS can install the pinned CLI from crates.io with their platform build prerequisites. There is no external iOS distribution.

Beta 2 fixes continuation past a nonmatching valid v2 phone identity in standard age multi-identity configurations. It does not change protocol v2, recipient encodings, key custody, or the pairing format; upgrading from Beta 1 does not itself require re-pairing. Corrupt state and malformed supported stanzas remain fatal; failure after selection does not switch pairings.

The immutable tag/release body retains pre-publication candidate wording. The published assets and current repository release record establish publication; that wording is not a promise of additional support.

## Retained limitations

- Every unwrap requires fresh native phone verification. No cached authorization or unattended mode exists.
- The Windows ZIP uses a private test root, not publicly trusted signing. Do not add that root to a system trust store.
- The exact published Windows/Android pair passed the scoped Beta 2 multi-identity regression on October 23, 2026. That run also reproduced automatic-discovery failure after network restoration. Later unpublished Android repair results do not certify the published packages or a future release.
- macOS acceptance is restricted to recorded hardware. Other OS versions, Intel/T2, GUI callers, and broader lifecycle/device combinations remain unverified.
- Wi-Fi is foreground-only and experimental. BLE is unavailable. QR/tag physical coverage and broader multi-phone coverage remain incomplete.
- Windows/macOS do not guarantee detection of older valid desktop replay snapshots. Do not restore replay state as recovery.
- Phone/desktop replacement needs independent recovery and re-encryption; a new pairing cannot recover old phone v2 ciphertext. A surviving phone identity may access old tag ciphertext through a newly confirmed pairing; it cannot restore lost keys.

## Earlier releases

Beta 1 introduced explicit native tagged recipients; Beta 2 retains `phone` as default. Alpha guides and acceptance records describe historical scope. Use this stable-route manual for current operations, [recipient choices](../guides/recipients.md) for compatibility, and [recovery](../guides/recovery.md) before changing state. Deferred checks remain deferred, not passed.
