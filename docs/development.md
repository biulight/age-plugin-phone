# Development entry points

User installation, daily operation and recovery are documented in the
[English manual](manual/index.md) and
[Simplified Chinese manual](../website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/index.md).
Read `AGENTS.md` before changing security behavior. Architecture, protocol, threat
model, ADRs and acceptance evidence stay outside the published user manual.

## Repository layout

- `crates/desktop`: the CLI, age entry point and bounded one-shot transport module.
- `crates/core`: separate public `recipient` and `protocol` modules and public test vectors.
- `crates/platform-keys`: Windows TPM and experimental macOS Secure Enclave key custody.
- `crates/platform-storage`: explicit Windows, macOS and other Unix filesystem boundaries.
- `apps/mobile`: Tauri 2 mobile application with a deliberately non-sensitive TypeScript UI.
- `docs`: architecture, protocol, threat model, and roadmap.

The [desktop four-crate PRD](desktop-crates-refactor-prd.md) defines acceptance criteria.
See [ADR 0024](adr/0024-four-desktop-crates.md) for the package boundaries and
[candidate evidence](desktop-refactor-evidence.md) for completed validation.
The original refactor did not add macOS hardware-key support or upload packages.
The later [macOS implementation plan](macos-support-plan.md) now includes dual
Secure Enclave roles, native storage, setup and cleanup. Remaining physical acceptance
is deferred for the interim experimental release by the
[release-scope decision](macos-release-scope-decision.md), not marked passed.
Windows and macOS do not guarantee detection of older valid desktop replay
snapshots; stronger protection is deferred. See the [macOS source quick start](macos-quickstart.md).
After a version is published, install it with
`cargo install age-plugin-phone --version <published-version> --locked`;
[build requirements and the manual release procedure](crates-io-release.md) apply.


## Mobile development

The Android build runs on Temurin JDK 17. Install the project JDK with [mise](https://mise.jdx.dev/)
from the repository root:

```console
mise install
mise exec -- java -version
```

With `mise activate` configured for your shell, entering the repository sets `JAVA_HOME`
automatically. For scripts and non-interactive shells, run commands through `mise exec --`.

```console
cargo run -p age-plugin-phone -- status
cargo run -p age-plugin-phone -- setup --help
cargo run -p age-plugin-phone -- setup --label "Work laptop" --json
cargo run -p age-plugin-phone -- pair --help
cargo run -p age-plugin-phone -- unwrap --help
cargo run -p age-plugin-phone -- qr-capture-probe
cargo run -p age-plugin-phone -- remove-desktop-state --help
cargo run -p age-plugin-phone -- remove-orphaned-desktop-state --help
cargo test --workspace

cd apps/mobile
bun install
bun run tauri android init
bun run tauri ios init
```

The experimental iOS target requires Xcode and iOS 17 or later. After `tauri ios init`, an unsigned
simulator compile can be checked with:

```console
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
bun run tauri ios build --debug --target aarch64-sim --no-sign --ci
```

For a paired, unlocked physical iPhone, use `bun run tauri ios dev` and select the device in the
Tauri prompt or generated Xcode project. Local development signing may be selected in Xcode, but
Team IDs, certificates, provisioning profiles, archives, and TestFlight/App Store configuration
must not be committed. The simulator cannot validate Secure Enclave custody or fresh Face ID/Touch
ID authorization.


## Design and verification

Start with the [Android StrongBox PoC](android-strongbox-poc.md), then read
[the architecture](architecture.md), [experimental P-256 recipient ADR](adr/0001-experimental-p256-recipient.md),
[offline-envelope ADR](adr/0002-experimental-offline-envelope.md),
[persistent replay-state ADR](adr/0003-persistent-replay-state.md),
[Android pairing-state ADR](adr/0004-android-pairing-state.md),
[QR framing ADR](adr/0005-qr-framing.md),
[native QR capture ADR](adr/0006-native-qr-capture.md),
[Android production key-custody ADR](adr/0007-android-production-key-custody.md),
[bidirectional pairing ADR](adr/0008-bidirectional-pairing.md),
[one-shot unwrap ADR](adr/0009-one-shot-qr-unwrap.md),
[reference age integration ADR](adr/0010-reference-age-state-machines.md),
[desktop-native scanner ADR](adr/0011-desktop-native-qr-scanner.md),
[private stanza selection ADR](adr/0012-private-stanza-selection.md),
[Windows CNG boundary ADR](adr/0013-windows-cng-key-boundaries.md),
[split desktop-key protocol ADR](adr/0014-split-desktop-key-protocol-v2.md),
[Windows private storage ADR](adr/0015-windows-private-storage.md),
[common transport and ADB Alpha ADR](adr/0016-common-transport-and-adb-alpha.md),
[iOS Secure Enclave custody ADR](adr/0022-ios-secure-enclave-key-custody.md),
[iOS pairing and replay lifecycle ADR](adr/0023-ios-pairing-replay-lifecycle.md),
[identity lifecycle and recovery ADR](adr/0017-lifecycle-and-recovery.md),
[owner-only technical preview scope](owner-only-preview.md),
[Windows and Android Alpha matrix](alpha-matrix.md),
[independent security review package](security-review-package.md),
[protocol draft](protocol.md), and [threat model](threat-model.md) before implementing a
transport or cryptographic backend.

## Why Tauri

Tauri 2 provides one mobile application shell while keeping protocol logic in Rust and allowing the
hardware-key boundary to be implemented as a small native Swift/Kotlin plugin. The WebView is UI
only: long-term keys, unwrapped file keys, raw signed requests, and hardware-key commands must not
cross into JavaScript. The generic Tauri biometric plugin is not a substitute for binding user
authentication to the actual Secure Enclave or Android Keystore private-key operation.

[age]: https://age-encryption.org/

### crates.io release maintenance

The independent [crates.io release pipeline](crates-io-release.md) supports
manual-dispatch preflight (default) and protected OIDC publishing of the four
crates in dependency order. First crate creation needs a separately authorized
manual bootstrap. See that guide for exact-SHA CI gates, Environment configuration
and partial-release recovery. Signed binary prereleases keep their existing workflow;
registry installation checks do not expand platform or real-device support.
