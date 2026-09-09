# M0 CryptoKit source-install fixture

This unpublished, standalone Cargo package validates a candidate for `cargo install`.
It is not a fifth product crate and does not enable macOS pairing or identity unwrap.
It creates only synthetic Secure Enclave signing and selection keys, persists opaque
hardware-wrapped references in an explicitly supplied isolated directory, and prints
public verification material. Never use production state or real data with it.

`build.rs` uses Xcode/Command Line Tools `xcrun swiftc` to build `native/Probe.swift`
as a static library. The Rust launcher passes only three borrowed argument strings
through one synchronous C ABI call. No keys, blobs or shared secrets cross that ABI.
The installed executable links to system Swift/CryptoKit/Security libraries; there
is no runtime helper executable, App bundle, provisioning profile, added entitlement,
Developer ID identity, network download or software-key fallback. Swift `-Onone` and
`-O` builds provide independent code hashes for upgrade tests (`M0_SWIFT_OPT`).

Requirements tested: Apple Silicon, macOS 26.6.2, Xcode 26.6, Swift 6.3.3 and Rust
1.96.0 and 1.88.0. An additional run selected the installed Command Line Tools
with Swift 6.3.3 and Rust 1.88.0. Set `MACOSX_DEPLOYMENT_TARGET=14.0` when building; the Swift target is also
14.0. This is not macOS 14.x runtime acceptance or a clean-machine test without
Xcode installed.

From the repository root, build the public Rust verifier, then explicitly run the
native experiment in a logged-in user session:

```sh
cargo build --locked -p age-plugin-phone-platform-keys --example macos-cryptokit-verify
python3 -B scripts/test-macos-cryptokit-probe.py \
  --fixture scripts/macos-cargo-probe \
  --rust-verifier target/debug/examples/macos-cryptokit-verify
```

The runner installs twice into a temporary Cargo root, uses different build hashes,
checks no Team ID or entitlements, validates cross-process crypto with Rust, exercises
parallel operations, a minimal noninteractive environment and abnormal holder exit, runs
malformed/partial/swapped/link/permission tests, and exercises uninstall/reinstall.
Only explicit execution touches hardware. The root workspace does not run it.

For an in-person lock/reboot experiment, `scripts/macos-m0-session.py` prepares
durable isolated state and records fresh-process `observe` calls alongside a
`hold` process that opened both handles before locking. These modes return only
public-key digests and coarse per-role outcomes. The runner never performs the
screen or boot transition itself and never creates keys on `watch` or `resume`.

Ordinary failures and Ctrl-C clean the runner's private temporary directory.
SIGKILL or shutdown can leave test files; remove only that known test directory.
**Removing reference files is not hardware key destruction.** Restoring a copied
reference on the same Mac was observed to restore key operations. Phone revocation
remains authoritative; no experiment here changes that product boundary.

This fixture's descriptor-relative file checks and `fsync` are only a bounded test
harness, not PR 3 storage/replay durability acceptance. A local physical session run
observed delayed denial after screen lock, recovery on unlock, and original-key
reopening after reboot and login. Cross-device copying, pre-first-unlock access,
same-Mac replay rollback, and the final product FFI/state format remain unverified. Do not infer arbitrary-app exclusion from the executable signature:
independent ad-hoc builds with access to the blobs can use them on this Mac.
