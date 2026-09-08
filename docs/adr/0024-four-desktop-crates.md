# ADR 0024: Four desktop publication packages

Date: 2026-09-08. Status: implementation candidate; hardware acceptance pending.

The baseline is `5da4b0bc8f3ca6f16f9be1b7430e923baad402b9`, version
`0.1.0-alpha.4`. This decision changes internal Rust source APIs, not protocol
bytes, CLI interfaces, state encodings, key names, or supported hardware.

The desktop package absorbs transport. `age-plugin-phone-core` exposes separate
`recipient` and `protocol` modules from the former recipient-p256 and protocol
packages. Signing and key-agreement operation traits remain in those modules.
`age-plugin-phone-platform-keys::windows` contains the existing CNG implementation.
`age-plugin-phone-platform-storage` exposes explicit Windows and Unix boundaries.
The Windows IPv4 enumeration helper is `windows::network`, outside the file API.

Dependencies point desktop → core/keys/storage, keys → core, core → storage.
Storage has no project dependency. Mobile Rust depends on core, never keys.
Windows third-party FFI dependencies are target conditional. Desktop and core
retain `unsafe_code = "forbid"`; platform FFI retains
`unsafe_op_in_unsafe_fn = "deny"`.

Unix filesystem operations are extracted mechanically. The replay path retains
its existing permissions, flock, temporary-file, hard-link creation, rename and
parent-sync sequence. The locator path retains its additional single-link check,
distinct errors and direct exclusive create. `unix::private_file` preserves that
distinction. Business layers still own path layout, lock suffix, byte limits,
canonical encoding, capacity, clock, scope and failure poisoning. This is not a
new cross-platform storage abstraction or an authorization policy change.

The four JSON vectors now live only in `crates/core/test-vectors`, with unchanged
SHA-256 hashes. Frozen old replay bytes and a separate old locator encoder are
packaged with their tests. Historical ADR package names describe their original
implementation; the mapping above supersedes their source locations, not their
security claims or recorded evidence.

All four packages retain the current version and Rust 1.88. Publication is manual,
storage → core → keys → desktop. The mobile shell and Tauri plugin cannot publish.
The alternate-registry rehearsal changes only temporary registry metadata and
permitted lock sources/checksums, and tests detached archives using Cargo 1.88.
It never substitutes a fake crates.io source, skips package verification, or uploads.

Future macOS hardware keys belong in the same keys package, after separate design
and native acceptance. No empty backend, hardware claim, or software fallback is
introduced. See the [PRD](../desktop-crates-refactor-prd.md),
[release procedure](../crates-io-release.md) and
[candidate evidence](../desktop-refactor-evidence.md).
