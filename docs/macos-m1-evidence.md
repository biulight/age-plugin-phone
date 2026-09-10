# macOS PR 2 / M1 implementation and evidence

Date: 2026-09-09. Scope: the second PR (M1) in
[the macOS support plan](macos-support-plan.md). Implementation and current-host
native checks completed; this does not declare complete macOS product support.

## Implemented boundary

- `platform-keys::macos` owns the synchronous C ABI and statically compiled Swift
  bridge. Cargo includes `build.rs` and `native/Keys.swift`. Only macOS invokes
  `xcrun swiftc`; Windows source and protocol v2 are unchanged.
- Separate `MacosSigner` and `MacosKeyAgreement` wrappers create independent
  CryptoKit Secure Enclave keys. Generation uses `WhenUnlockedThisDeviceOnly` and
  `privateKeyUsage`, without Touch ID/user-presence requirements or software fallback.
  Reopening uses Secure Enclave reconstruction APIs and checks the expected public
  key. CryptoKit hardware reconstruction/private operations establish usability;
  metadata is not an independent hardware attestation or an OS-enforced role policy.
- The signer consumes the supplied SHA-256 digest through a Swift `Digest` adapter
  without hashing it again. Rust validates the signature encoding and normalizes
  it to fixed 64-byte low-S form. Public keys are canonical 33-byte SEC1. ECDH
  accepts a validated peer and copies the raw 32-byte result directly into Rust
  `Zeroizing` storage. Swift retains no borrowed FFI buffers; errors return a coarse
  status without native error strings. Hardware private scalars have no export API.
- Desktop owns `APSE2` metadata: suite, desktop ID, distinct role public keys, bounded
  role references and a domain-separated signature binding the entire record.
  Parsing rejects truncation, trailing fields, unknown versions/suites, zero or
  excessive reference lengths, identical roles and signature/binding changes.
  Opening also proves signing and agreement usability and never generates keys.
- Creation reserves a create-only private file before generating either role.
  Failure leaves unavailable state; a later open does not silently complete or
  replace it. Existing files are never overwritten. The record contains encrypted
  hardware references, not exportable software private scalars.
- The normal macOS desktop build uses this backend and rejects `APDK2`. Software
  state on macOS exists only under `cfg(test)` for existing protocol/transport
  fixtures. No runtime switch or Cargo feature enables software fallback. Tests
  of actual macOS metadata name its concrete hardware implementation explicitly.

## Verification run

On the existing M0 host (MacBookPro18,3, arm64, macOS 26.6.2 / 25G83):

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo test --workspace --locked` | Passed; two hardware tests deliberately ignored in this ordinary suite |
| Platform-key ignored native test | Passed separately: independent roles, reopen, prehash signature verification by Rust, wrong digest/public binding, ECDH interoperability, invalid peer and corrupted reference rejection |
| Desktop ignored native test | Passed separately: create, duplicate rejection, same-public-key reopen, child-process reopen, truncated/missing state rejection and concurrent create-only winner |
| Ordinary metadata negative tests | Passed: every-byte mutation/truncation, extra fields, software format, missing/partial state preserved without repair |
| `cargo package -p age-plugin-phone-platform-keys --list --allow-dirty --locked --offline` | Passed; includes build script, Swift source and Rust backend |
| `git diff --check` | Passed |

The native commands were:

```console
cargo test -p age-plugin-phone-platform-keys native_roles_prehash_ecdh_and_reopen --locked -- --ignored
cargo test -p age-plugin-phone native_metadata_lifecycle --locked -- --ignored
```

All runs used `RUSTC_WRAPPER=` because the configured sccache wrapper could not
run within this sandbox. The first sandboxed native attempt failed to access the
macOS security service; the identical test passed outside the sandbox. The first
sandboxed workspace suite failed existing socket/process-group tests with permission
errors; the complete suite passed outside the sandbox. These failures were not
counted as passes or hidden by skipping tests. No real phone pairing or phone
verification was performed. Native fixtures used only isolated transient keys and
temporary metadata, removed on successful completion. No private material was logged.

Existing pairing/unwrap negatives for cancellation, replay, wrong desktop, timeout
and malformed messages and the public protocol/recipient vectors remain enabled
and passed. The dependency `block 0.1.6` still emits its existing future-Rust
compatibility notice; current Clippy passes with warnings denied.

## Remaining gates

- PR 3 still owns descriptor-relative storage, UID/ACL/race checks, APFS full-sync,
  backup exclusion and same-Mac replay rollback. This PR deliberately uses the
  existing Unix private-file reader and file/directory sync semantics; it does not
  certify those semantics against the complete planned storage adversary.
- PR 4/5 still own setup/resume/cleanup, deletion journal and recovery integration.
  Signed metadata detects alteration but cannot prevent a same-user caller with
  working hardware references from signing again. Paired public keys/transcript
  and replay state remain separate authority boundaries.
- Reference deletion is local cleanup, not irreversible hardware destruction.
  Other same-Mac copies may remain usable; phone revocation remains authoritative.
- Wrong-Mac copying remains deferred under the user-approved current-host M0
  baseline. No other Mac model, Intel/T2, older OS, pre-login environment or full
  phone/transport/caller matrix inherits this native test result.
- Package listing confirms included build inputs, not an extracted-archive build,
  clean-machine install, production upgrade or Windows runtime regression. Those
  acceptance runs remain in the later delivery matrix. Windows implementation was
  not modified; its native tests were not run on this Mac.
- Old software identities are never imported. Recover through an existing usable
  path or an independent recipient already in the ciphertext, then re-encrypt
  for a new pairing; do not overwrite or silently erase old state.
