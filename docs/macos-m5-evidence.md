# macOS M5 source installation and rebuild evidence

Date: 2026-09-09. Product source: `5a75ee2`, version `0.1.0-alpha.4`.
This records isolated source installation and synthetic state continuity on the
existing MacBookPro18,3 / arm64 / macOS 26.6.2 (25G83) baseline. It does not close
the real-phone, caller-permission, released-version upgrade or M2 rollback gates.

## Archive and installation checks

`scripts/registry-preflight.py` passed for all four desktop crates using Rust
1.88.0 (`6b00bc388`), Xcode 26.6 (17F113), and Apple Swift 6.3.3. Each archive was
extracted outside the repository workspace, tested with locked dependencies,
served through an isolated local sparse registry, and used for
`cargo +1.88.0 install --locked`. The platform-keys archive includes `build.rs`
and `native/Keys.swift`. No registry upload, signing certificate or preinstalled
phone application was used. Native hardware tests are explicitly invoked
separately; their ignored archive-test rows are not hardware passes.

The rehearsal used a new Cargo home, target and install root on this existing
development Mac. This is not a freshly installed physical OS. An initial attempt
inside the repository's target directory inherited the enclosing workspace and
failed; the successful run used `/private/tmp/age-phone-macos-m5-registry-20260909`.
The runner needs Python 3.11+; the host's default Python 3.10 is insufficient.

## Rebuild, uninstall and reinstall

The explicitly built `macos-install-acceptance` example creates one isolated
synthetic pairing with two real Secure Enclave roles and an already-consumed
synthetic replay digest. It never contacts a phone or processes real pairing
material. `scripts/macos-install-lifecycle.py` checks each installed executable
can open both hardware roles before rejecting a deliberately malformed stanza;
the check stops before creating a request or opening a camera. The helper also
reopens the same roles and requires rejection of the consumed digest. File
content hashes and permissions must remain identical throughout.

| Phase | Result | Installed executable SHA-256 |
| --- | --- | --- |
| Initial registry install | Passed: hardware reopens, replay rejected, state unchanged | `965a0147dd3d1b9d474bd82e002a393cec402de7ebd0438ccbeb1d4d73fd2587` |
| Offline locked `cargo install --force`, different optimization | Passed: changed binary, original hardware/replay preserved | `38dacb5ce5478b6891458d96035163aa0f9b1cab34577a0b6b8c82a08970911f` |
| `cargo uninstall` from isolated root | Passed: binary removed, state unchanged | — |
| Offline locked reinstall | Passed: original hardware/replay preserved | `965a0147dd3d1b9d474bd82e002a393cec402de7ebd0438ccbeb1d4d73fd2587` |

The changed optimization setting proves continuity across a changed executable
hash at the same source version. It does **not** simulate an actual published
version upgrade or prove downgrade compatibility. All installs target the
temporary root, leaving the user's installed CLI untouched. Uninstall deletes
the executable, not pairing metadata, hardware references or replay state.
Deleting hardware references remains different from irreversible key destruction.

Machine-readable outcomes and archive hashes are retained in
[macos-m5-acceptance-results.json](macos-m5-acceptance-results.json). The acceptance
helper and runner were added after the product snapshot; the archive evidence
identifies exactly which product bytes were tested. Subsequent product changes
require fresh exact-artifact validation before a support claim.

## Reproduction and remaining acceptance

```console
python3.13 scripts/registry-preflight.py --output /private/tmp/NEW-registry-output
cargo build -p age-plugin-phone --example macos-install-acceptance --locked
python3.13 scripts/macos-install-lifecycle.py \
  --registry-output /private/tmp/NEW-registry-output \
  --helper "$PWD/target/debug/examples/macos-install-acceptance" \
  --fixture /private/tmp/NEW-synthetic-fixture
python3.13 scripts/test-macos-install-lifecycle.py
```

The fixture and output paths must be new. Hardware service access is required;
absence or failure is an error, never a passing skip. Four runner guardrail tests
cover unexpected file changes, permissions, symlinks, helper failures and the
installed binary's required failure boundary. Rust formatting, all-target Clippy
and the locked workspace suite pass with the helper included.

Still unverified: released-version upgrade/downgrade, fresh-OS install and first
real setup, PATH discovery through age/rage and GUI callers, real Android
verification, other Mac hardware/OS, Intel/T2, and iPhone. M2 same-Mac replay
snapshot rollback remains an observed counterexample, not an installation pass.

The later [M6 record](macos-m6-evidence.md) repeats the full installation lifecycle
on candidate `cc7e120`, including explicit-pair journaling, and checks continuity
against this original M5 fixture. The earlier hashes above remain historical.
