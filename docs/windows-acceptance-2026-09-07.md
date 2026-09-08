# alpha.4 signed-package acceptance and publication — 2026-09-07

Status: **owner-only physical acceptance passed and developer prerelease published**.
All required owner-only rows passed; the complete public-Alpha matrix remains deferred.

## Release binding

- Immutable commit: `5da4b0bc8f3ca6f16f9be1b7430e923baad402b9`.
- Exact-SHA [CI 34110138123](https://github.com/biulight/age-plugin-phone/actions/runs/34110138123): passed.
- [Signing and publication run 34110640981](https://github.com/biulight/age-plugin-phone/actions/runs/34110640981), attempt 1: succeeded.
- [v0.1.0-alpha.4 prerelease](https://github.com/biulight/age-plugin-phone/releases/tag/v0.1.0-alpha.4): published at 2026-09-07 14:40:15 UTC with six same-run assets.
- The annotated tag resolves to the accepted commit. That commit was fast-forwarded into `main`;
  [main CI 34134592279](https://github.com/biulight/age-plugin-phone/actions/runs/34134592279) passed all seven jobs.

| Artifact | SHA-256 |
| --- | --- |
| Windows EXE | `b742eb1e5552d2d22f021f378217e4c8103d3f69bd5bf488f49b49e8b58d87e3` |
| Windows ZIP | `20c64b9791174125190902b43bea9725a005126d9ccb22c491703e430694a710` |
| Android normal APK | `6e77ada9917673f0a5a392bb9a4327dd2275f9ff403d15015a6280da190d4f62` |

## Physical results

| Gate | Result |
| --- | --- |
| Minimum unwrap | All 11 rows passed, including independent recovery, two fresh USB approvals, cancellation and fresh retry, foreground Wi-Fi, background interruption and recovery, paused listener and final audit. |
| Manual pairing/discovery | Required rows passed cumulatively across preserved attempts and continuations: USB/Wi-Fi loading, native cancellation/background, listener timeout, fresh operations and discovery transitions. |
| Exact alpha.3 upgrade | In-place upgrade to the exact normal alpha.4 APK passed with retained identity/pairing, independent recovery and distinct fresh biometric operations. |
| Final cleanup | All eight known test pairings cleaned; zero test stubs, non-lock test state, candidate processes and ADB reverse rules. Phone identity and unrelated pairings retained; Wi-Fi paused and controls enabled. |
| Firewall helper | Current-host Inspect and Enable `-WhatIf` passed without mutation. No clean-VM or firewall-rule-change acceptance claim. |

Environment: Windows 11 build 22631 x64, ready TPM 2.0 and Platform Crypto Provider;
Android SM-F9660, Android 16 / SDK 36, security patch 2026-07-05, validated StrongBox dual keys;
age 1.3.1 and ADB 1.0.41, one ADB device.

## Original evidence and history

The [original sanitized physical evidence](alpha.4-physical-acceptance-evidence.json) is preserved
byte-for-byte with SHA-256
`ab72443acb2b829097f3ca7e373ceabe6885f9779fc4b0813d80954286aff218`.
It was generated at 2026-09-07 14:35:09 UTC, before publication approval, so its pending-publication
fields describe that historical checkpoint. The completed publication above supersedes those fields;
the original evidence has not been rewritten. It includes row results, source-report hashes,
certificate identities, environment facts and preserved failure classifications.

Earlier failed/incomplete minimum and manual attempts remain failures in that record. The manual
sequence retained an omitted auto-listen precondition and owner interruption, followed by official
cleanup and completed continuations. Two upgrade precondition failures used stale desktop stubs
whose phone pairings had already been revoked; the fresh exact upgrade subsequently passed.
The superseded `dd5ad4350fe333822a66714374dc9aac9f2cbcf9` candidate failed its terminal-input
harness gate and was never published; run `34022913877` was cancelled. Its evidence is not used
as acceptance of the final artifact pair.

This document synchronizes the completed acceptance and publication history on 2026-09-09.
The signed ZIP and public release body retain their original preparation wording; their immutable
artifacts have not been replaced. The [checklist](alpha.4-acceptance-checklist.md) now records completion.

## Limits

This is an owner-only developer prerelease for synthetic or disposable data with independently
verified recovery. Windows uses a private test root: signature and in-memory custom-root chain
validation passed, but ordinary Windows installations do not trust it. No trust root was installed
as part of acceptance. Protocol v2 remains experimental and unfrozen.

The complete public-Alpha matrix, second-device-family and multi-phone coverage, full QR/replay
and lifecycle/invalidation coverage, public Windows signing and external-user gates remain deferred.
iOS source/compile checks do not establish signed distribution or physical acceptance.
The historical sporadic discovery failure remains unexplained; this report does not turn it into a
pass or claim availability in a default environment or clean VM.
