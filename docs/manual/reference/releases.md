---
title: "Versions and known limitations"
sidebar_position: 2
---

# Versions and known limitations

This manual targets **0.1.0-beta.2**, a limited technical beta published on September 11, 2026. Use disposable or synthetic data only. Protocol v2 remains unfrozen; publication does not expand hardware acceptance or authorize production-secret use.

## Beta 2

The [GitHub release](https://github.com/biulight/age-plugin-phone/releases/tag/v0.1.0-beta.2) provides a signed Android ARM64 APK, a test-signed Windows x64 ZIP, checksums, and signature-verification records. Windows and macOS can install the pinned CLI from crates.io with their platform build prerequisites. There is no external iOS distribution.

Beta 2 fixes continuation past a nonmatching valid v2 phone identity in standard age multi-identity configurations. It does not change protocol v2, recipient encodings, key custody, or the pairing format; upgrading from Beta 1 does not itself require re-pairing. Corrupt state and malformed supported stanzas remain fatal; failure after selection does not switch pairings.

The immutable tag/release body retains pre-publication candidate wording. The published assets and current repository release record establish publication; that wording is not a promise of additional support.

## Retained limitations

- Every unwrap requires fresh native phone verification. No cached authorization or unattended mode exists.
- The Windows ZIP uses a private test root, not publicly trusted signing. Do not add that root to a system trust store.
- Physical source acceptance does not certify the exact published Windows/Android pair. Its Beta 2 multi-identity regression repeat remains open.
- macOS acceptance is restricted to recorded hardware. Other OS versions, Intel/T2, GUI callers, and broader lifecycle/device combinations remain unverified.
- Wi-Fi is foreground-only and experimental. BLE is unavailable. QR/tag physical coverage and broader multi-phone coverage remain incomplete.
- Windows/macOS do not guarantee detection of older valid desktop replay snapshots. Do not restore replay state as recovery.
- Phone/desktop replacement needs independent recovery and re-encryption; a new pairing cannot recover old v2 ciphertext.

## Earlier releases

Beta 1 introduced explicit native tagged recipients; Beta 2 retains `phone` as default. Alpha guides and acceptance records describe historical scope. Use this stable-route manual for current operations, [recipient choices](../guides/recipients.md) for compatibility, and [recovery](../guides/recovery.md) before changing state. Deferred checks remain deferred, not passed.
