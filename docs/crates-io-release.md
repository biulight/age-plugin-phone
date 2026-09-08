# Manual crates.io release

These packages remain experimental alpha software, unsuitable for real secrets.
This procedure does not claim that any version has been uploaded. Consult
[candidate evidence](desktop-refactor-evidence.md) for actual validation status.

## Installation after publication

Install an explicitly published prerelease:

```console
cargo install age-plugin-phone --version <published-version> --locked
```

Only the CLI is installed; Cargo builds its three library dependencies. Rust 1.88
or later, a native C/C++ compiler and platform SDK are needed. Windows requires
the MSVC Rust toolchain and Visual Studio C++ Build Tools/Windows SDK. Hardware
desktop use currently requires Windows 11+ x64, TPM 2.0 and Microsoft Platform
Crypto Provider, plus a compatible phone and fresh native verification per unwrap.
The Windows support probe must succeed before pairing.

Linux builds need a C toolchain, Clang/libclang and the Video4Linux headers for
camera support. macOS builds need Xcode command-line tools and the macOS SDK.
Non-Windows desktop behavior remains experimental software-key prototype behavior;
macOS Secure Enclave/Keychain desktop keys are not implemented. A successful build
does not establish hardware-key protection or native-device acceptance. The PC
archive builds independently of Tauri, Android and iOS tooling.

## Preflight

Use Python 3.11+ and Cargo 1.88.0. Output directories must not exist and should be
outside the checkout. The script uses an isolated Cargo home and a localhost-only
sparse registry, including fresh downloads of locked third-party dependencies.

```console
scripts/check-release-version.sh
python3 scripts/check-package-layout.py --archives
cargo +1.88.0 fmt --all --check
cargo +1.88.0 clippy --workspace --all-targets --locked -- -D warnings
cargo +1.88.0 test --workspace --locked
python3 scripts/registry-preflight.py --minimal --output /tmp/phone-minimal
python3 scripts/registry-preflight.py --output /tmp/phone-packages
```

Windows portable CI retains the seven native TPM skips listed in
`scripts/windows-portable-test-skips.txt`. Skipped hardware tests are not passes.
Run native tests and the PRD upgrade/phone/cancellation checks separately on the
designated hardware. Linux and macOS run the fixed old Unix state tests.

The script rewrites only temporary package publish registries and the explicit
internal dependency registry, keeping exact versions and third-party crates.io
sources. Cargo 1.88 `package --registry` is unstable; the script instead uses each
temporary manifest's sole `publish` registry. It does not use nightly or bypass
verification. Normalized archives must have no path/Git dependencies. The script
checks source hashes, archived dependency versions, manifest differences, and
workspace lock changes, then builds/tests detached archives and installs from the
temporary registry. It records file inventories/digests in `archive-evidence.json`
and metadata changes in `manifest-differences.json`.

Run `scripts/interoperability-smoke.sh AGE AGE_KEYGEN RAGE RAGE_KEYGEN PLUGIN`
against the registry-installed binary. The CI uses pinned released clients and
also checks independent recovery. Preserve evidence for the final candidate;
temporary preflight archives contain alternate-registry metadata and must never
be uploaded to crates.io.

## Publish separately

Confirm package-name ownership, publisher account, upload credentials and the
intended version separately. Update the workspace version, all three exact
internal constraints and both mobile versions together. Re-run preflight.

From the unmodified production manifests, publish in this fixed order:

1. `cargo publish --locked -p age-plugin-phone-platform-storage --dry-run`, then
   the same command without `--dry-run` when publication is authorized.
2. Confirm the exact storage version resolves from crates.io in a fresh Cargo
   home. Dry-run and publish `age-plugin-phone-core`.
3. Confirm core resolves. Dry-run and publish `age-plugin-phone-platform-keys`.
4. Confirm keys resolves. Dry-run and publish `age-plugin-phone`.

At each step wait for the registry to resolve the exact prerequisite version;
successful HTTP upload alone is insufficient. On partial failure, stop and record
which package versions were published. Never overwrite or attempt to re-upload
the same version. Correct unreleased packages or choose a separately approved new
coordinated version and repeat the checks. No automatic upload workflow is added.
Production registry dry-runs for dependent packages remain pending until their
prerequisites exist on crates.io; local registry success does not replace them.
