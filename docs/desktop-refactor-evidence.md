# Desktop refactor candidate evidence — 2026-09-08

Status: **重构验收完成** for the candidate hashes and import-only amendment recorded below.
The owner resumed interactive phone upgrade checks after automated verification.
No package was uploaded to crates.io and no support claim was expanded.

## Candidate and baseline

- Baseline commit: `5da4b0bc8f3ca6f16f9be1b7430e923baad402b9`, version `0.1.0-alpha.4`.
- Candidate: the four-crate source tree accompanying this report.
  The archived source/resource hashes below identify the tested content. A future
  release must identify its own immutable commit and repeat relevant checks if it changes.
- Cargo/rustc: 1.88.0. Workspace version and all third-party Cargo.lock entries
  (including checksums and dependency lists) were preserved.
- Before migration, the macOS workspace baseline passed 103 tests. The cached
  pre-migration macOS executable was retained with SHA-256
  `30c46acb6d55bdcf1cff55ff71725fb7822d48dae5784dbc2fda6468a540fdfa`;
  its build provenance is not assumed for upgrade acceptance.
- A fresh Windows baseline executable was independently built from a `git archive`
  of the exact baseline commit in an isolated directory. SHA-256:
  `e832b98c1f41ec7d784a6be1f73fad75d38989a822739cfe27eda3d3e2c6f6bf`.
  This exact executable established the owner-confirmed synthetic Android pairing
  and successfully decrypted the synthetic fixture before the candidate upgrade.
- Fixed replay bytes were generated using the old implementation before migration.
  Their inputs, generation command and hashes are in
  [core fixtures](../crates/core/tests/fixtures/README.md). The independent old
  locator encoder and golden output are in
  [desktop fixtures](../crates/desktop/tests/fixtures/README.md).

## Automated outcomes

| Check | Outcome and scope |
| --- | --- |
| Format, lint, source tests | PASS: Cargo 1.88 `fmt --all --check`, workspace/all-target Clippy with `-D warnings`, locked workspace tests on macOS and Windows. macOS: 106 tests; Windows: 93 tests, with no native TPM skips in this host run. |
| Package contract | PASS: exactly four crates.io-only packages, two non-publishable mobile packages, exact internal versions, dependency directions, lint boundaries, required archive files and mobile manifest versions. |
| Public vectors | PASS: all four JSON SHA-256 digests unchanged. Kotlin resources point at core; Swift's four protocol/framing tests retain their existing embedded expected values, with no vector regeneration. |
| Cargo 1.88 mechanism | PASS: the two-package minimal registry rehearsal before migration on macOS; also passed on Windows and Linux. Cargo 1.88's unstable `package --registry` flag was not used in the passing mechanism. |
| Actual four-package archives | PASS on macOS arm64, Linux arm64 and Windows x64: sequential package verification, detached archive tests, registry installation, `--help`, `setup --help`. |
| Registry/source audit | PASS on all three systems: manifest rewrite whitelist, exact locked package names/versions, permitted lock metadata, no path/Git dependencies in normalized manifests, archive contents equal final source/resources. Windows archive tests use the seven existing TPM skips; those skips are not counted as passes. |
| Unix cross-version state | PASS on macOS and Linux, both from packaged tests: old request/response consumption rejects at clock 110 before expiry 200, clock 109 rejects specifically as rollback, later consumption at 120 persists and survives reopening. Frozen locator encoder matches golden output, then new code opens its temporary absolute paths and rejects wrong transcript binding. |
| Unix storage edge cases | PASS: existing locking/missing/corrupt/failed-write/poisoning tests retained. Extracted bounded reads also reject unrepresentable limits, oversized data and widened permissions. Normal caller limits and filesystem operation order are unchanged. |
| Windows hardware/storage source tests | PASS on the supplied Windows 11 x64 build 22631 host: TPM dual-role non-exportable keys, reopening, partial-key refusal, private ACL/reparse/hard-link/locking checks, native exact-pairing cleanup and orphan-cleanup tests. |
| age/rage and recovery | PASS using final macOS registry-installed plugin, age 1.3.2 and rage 0.12.1: 12 independent recoveries, 2 expected rejections. CI retains its pinned age 1.3.1/rage 0.12.1 job and now consumes the registry-installed Linux artifact. That future CI run is not claimed here. |
| Android | PASS: 70 Kotlin vector/negative tests, zero failures/errors/skips; frontend TypeScript/Vite production build. |
| iOS | PASS: 4 Swift protocol/framing tests, Cargo 1.88 iOS-device Rust/native-plugin build, unsigned arm64 simulator application build. |
| Repository checks | PASS: release-version script, both existing Alpha release-script fixture suites, actionlint and `git diff --check`. |

Linux ran in the local disposable `rust:1.88-bookworm` arm64 container, image digest
`sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0`.
Its detached PC archives build without Tauri, Android or iOS tools. Windows runs
used a separate candidate directory; the existing checkout and pairing state were
not repurposed. Hardware tests created and cleaned only their own synthetic state.

Initial environment failures were retained and resolved: sandboxed sccache/loopback
access, early Python 3.11 archive API compatibility, macOS AppleDouble transfer
metadata, missing Rust 1.88 iOS targets, and an existing non-empty simulator output
directory. The latter outputs were moved aside before the successful build. No
protocol, authorization, hardware requirement or replay check was weakened to pass.

## Preserved archive audit

Each inventory maps every archived file to SHA-256, including generated manifests
and locks. Metadata reports retain the exact before/after temporary manifest text.
Their localhost registry URLs are ephemeral test sources, not publication targets.
All non-generated source/resource hashes in all three inventories were compared
again with the checkout after the runs. The subsequent pre-commit amendment below
is the only packaged source difference from those preserved inventories.

Pre-commit amendment: a fresh macOS Clippy run found `items_after_statements` in
`platform-storage/src/unix/private_file.rs`. Moving the existing `use std::io::Read
as _;` immediately before the `read_limit` statement fixes the lint without changing
any executable statement, type or import scope. The file SHA-256 changed from
`453bd678e53904b568405ce8006ec391ec4b676f13f8cda691c01627e09a695d`
to `591a1b8bb6437f4e148f901810f719a4f8cd26455f7e9b7c9fa918fca010e424`.
Cargo 1.88 formatting, full workspace Clippy and locked workspace tests were rerun
on this amended source. The historical archive inventories are retained unchanged;
they are not claimed to contain the amendment. Windows does not compile this Unix
module, so the tested Windows implementation and hardware evidence are unchanged.
The staged diff reports an inherited trailing blank line in each new package
LICENSE copy. These copies intentionally remain byte-identical to the repository
LICENSE and the tested archives; the package contract enforces that equality.
The staged whitespace check passes with only `blank-at-eof` excluded.

| System | File inventory and content digests | Whitelisted manifest differences |
| --- | --- | --- |
| macOS | [macos-archives.json](refactor-evidence/macos-archives.json) | [macos-metadata.json](refactor-evidence/macos-metadata.json) |
| Linux | [linux-archives.json](refactor-evidence/linux-archives.json) | [linux-metadata.json](refactor-evidence/linux-metadata.json) |
| Windows | [windows-archives.json](refactor-evidence/windows-archives.json) | [windows-metadata.json](refactor-evidence/windows-metadata.json) |

Reproduce with [the manual release/preflight procedure](crates-io-release.md).
These alternate-registry archives must never be uploaded to crates.io.

## Owner-assisted hardware acceptance

Executed on the Windows TPM host above with the normal Android application,
version `0.1.0-alpha.4`, over USB/ADB. The final registry-installed candidate
executable SHA-256 was
`3681f58271e279fb016b6ac597773fbf9dc9105711bf75b8d38f5fd13ab53a78`.
The owner compared all 64 hexadecimal characters of the pairing fingerprint on
both endpoints. The synthetic fixture was encrypted to the phone recipient and
an independently generated disposable recovery recipient; only file digest
comparisons and coarse outcomes were reported.

| PRD hardware requirement | Outcome and scope |
| --- | --- |
| Pair with exact old executable and compare the complete fingerprint on both endpoints | PASS: owner compared the complete fingerprint and confirmed it on the phone before desktop confirmation and persistence. |
| Consume an old request, then use the new executable with the same pairing and state | PASS: baseline and final registry-installed Windows candidate decrypted the same synthetic age ciphertext with the original pairing. Independent recovery also matched. |
| Fresh native phone approval and successful decryption without re-pairing | PASS: owner explicitly confirmed separate fresh native biometric prompts for baseline and candidate. Both plaintext file digests matched the synthetic fixture without displaying plaintext. |
| Old consumed-record rejection across the actual Windows/phone upgrade | PASS at the stored test clock: candidate probe opened the actual baseline-consumed desktop response store, obtained exact Replay and ClockRollback errors, and verified unchanged bytes. This is not a wall-clock replay of a live signed response. |
| Cancellation preserves consumed phone requests across that upgrade | PASS: a fresh owner-confirmed cancellation returned no response; identical unexpired request was promptly rejected after a new connection. On the repeated observed run, owner confirmed no second native biometric prompt and normal phone operation. A subsequent fresh candidate decrypt matched the synthetic fixture with unchanged pairing metadata; owner confirmed a new native prompt and approval. |
| Existing TPM names, locator and dual-role binding preserved for that pairing | PASS: stub, locator and TPM metadata hashes remained unchanged across old/new decrypts; candidate reopened existing signing and selection keys and matched both public roles to the stub. |
| Exact upgraded-pairing native cleanup | PASS: owner revoked only the new test pairing on the phone, confirmed the original pairing remained, and supplied the complete fingerprint to the candidate's native desktop cleanup command. Command exited successfully; only the zero-byte lifecycle lock remained in the test config root and ADB reverse list was empty. Native key deletion and exact-target isolation are also covered by the passing Windows source tests. |

The first two baseline USB pairing attempts timed out before connection and rolled
back without committed pairing state. A later attempt connected through the normal
Android application's USB pairing entry and completed the owner's full fingerprint
comparison. One cancellation attempt was accidentally approved with a fingerprint;
the probe failed explicitly with `cancel_returned_response`, and that attempt is
excluded from cancellation evidence. Every retry uses a fresh signed request; no
replay store was reset. The [separate in-memory replay probe](refactor-evidence/hardware-probe/README.md)
keeps signed request bytes only in memory and requires owner observations.
The first correctly cancelled run lacked the owner's replay UI observation and was
not counted as a complete observed pass. The owner requested and observed a fresh
repeat, including explicit cancellation and confirmation that replay did not prompt.

No fingerprint comparison, native approval or destructive confirmation was
automated or inferred. The hardware results above belong to this candidate and
its freshly created baseline pairing, rather than historical Alpha evidence. Production
crates.io dry-runs for dependent packages remain pending until prerequisites are
actually published, and upload remains a separate authorized release action.
