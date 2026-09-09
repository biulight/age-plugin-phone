# ADR 0025: macOS desktop Secure Enclave and storage boundary (M0)

Date: 2026-09-09. Status: **current-host M0 feasibility verified; product backend design remains draft; expanded hardware/OS matrix deferred**.
Scope: PR 1 of the [macOS support plan](../macos-support-plan.md). This does not
enable macOS product pairing or change protocol v2, Windows, or phone authorization.

## Decisions and proposed contract

- Current M0 validation is scoped by the user to `MacBookPro18,3`, arm64, macOS
  26.6.2 / 25G83. A second Mac is unavailable; cross-device copying is deferred,
  not marked passed, and does not block local M0 progress or subsequent implementation.
- Apple Silicon is the first hardware batch; Intel + T2 is a separate second batch.
  Android and iPhone acceptance records remain independent. No Intel, VM, Rosetta,
  or phone combination inherits another row's acceptance.
- Set macOS 14.0 as the **provisional development/deployment floor**. It is not a
  supported-OS claim: 14.x and every advertised newer release require source-built native
  evidence. Only macOS 26.6.2 arm64 was available for this M0 attempt. The final
  minimum supported OS decision remains open until those measurements exist.
- Retain the original Rust/Security.framework probe as a failed Data Protection
  Keychain experiment. For the source-install candidate, use CryptoKit through a
  small statically linked Swift C ABI. The isolated Cargo fixture proved that this
  builds and installs without an App, entitlement or publisher certificate. It is
  not yet `platform-keys::macos` product code. A future production bridge stays in
  the platform package; core/desktop still forbid unsafe code.
- Generate two independent P-256 Secure Enclave keys. Signing consumes a SHA-256
  digest, normalizes DER ECDSA to fixed 64-byte low-S form, and selection uses raw
  32-byte ECDH. Role enforcement belongs in separate Rust operation wrappers and
  bound metadata. Do not infer OS-enforced ECDSA-only/ECDH-only usage: the probe
  intentionally tries ECDH in both directions to measure native capability.
- Candidate custody: CryptoKit Secure Enclave encrypted `dataRepresentation`
  references in protected local files, with `WhenUnlockedThisDeviceOnly` and
  `privateKeyUsage`. The successful experiment does not persist Keychain items,
  enable synchronization, or use an application access group. There is no
  `userPresence`, biometric flag, authentication reuse or software-key fallback.
  Desktop Touch ID is not required by these key attributes. A physical lock/unlock
  run observed delayed native denial and recovery after unlocking; UI lock is not
  an instantaneous key-access cutoff or a product authorization timer. Every identity unwrap needs fresh phone verification.
- Product metadata will contain version, separate role references, both public keys,
  and local binding, never software private scalars. Reopening must check these
  attributes and bindings, reject ambiguity/partial state, and never repair by
  generating keys. Both probes' reference formats and pre-create existence checks
  are research mechanisms, **not** the concurrent create-only product design.

## Source installation and rebuild contract to validate

The current delivery target is **`cargo install` only**, as clarified by the user.
No `.app`, PKG, Developer ID distribution identity, notarization or stapling is
required for this phase. The earlier proposal to require a release-team access
group and a signed PKG is superseded. GUI applications may still invoke the CLI
through age; a GUI caller does not mean this project ships an App.

The Data Protection Keychain probe returned `errSecMissingEntitlement` in its
linker-ad-hoc build. This is evidence about that specific custody configuration,
not proof that all Secure Enclave CLI designs require a Developer ID certificate.
Re-evaluate the native persistence design against ordinary source installations
before selecting the production backend. Do not simply wait for release credentials.

The CryptoKit candidate has now passed local native tests. Apple's documentation
explains that its Secure Enclave representation is encrypted data restorable by
that same enclave, rather than a raw private scalar. The fixture uses only those
hardware types for persistent roles; the software P-256 peer is a fixed synthetic
ECDH test input. Native signing and ECDH are independently verified with the same
Rust `p256` library used by core. A physical wrong-Mac copy test remains open.

`scripts/macos-cargo-probe` is an unpublished, separate research package with all
Swift sources and its build script included in the Cargo archive. `build.rs` invokes
`xcrun swiftc` to make a static library; one synchronous C ABI takes borrowed CLI
arguments and returns a status. No native key handle, private representation or
shared secret crosses it. The installed Rust executable has no helper or App bundle.
This selects a practical bridge for the demonstrated CryptoKit APIs, not a claim
that every alternative pure-Rust implementation is impossible. A production bridge
needs operation-specific APIs, ownership/error/zeroization review and platform-package
integration in PR 2; do not reuse the probe's report-emitting ABI for unwrap.

Two independent `cargo install --locked --offline --force` builds with different
code hashes, linker ad-hoc signatures, no Team ID and no entitlements reopened the
same two keys. Uninstall/reinstall also preserved access. The same lifecycle was
run from an extracted Cargo archive, so the fixture does not depend on omitted
repository build inputs. No manual signing was needed in the tested environment.
This proves the fixture's key continuity, not replay or production-plugin upgrade
compatibility. Xcode 26.6 is the tested native toolchain; the fixture archive lifecycle also
passed on Rust 1.88.0. A subsequent full run selected installed Command Line Tools
using `DEVELOPER_DIR` and also passed on Rust 1.88. No global toolchain setting was
changed; this is not a clean-machine test or a new whole-workspace MSRV result.

Possession of the wrapped references by another ad-hoc build on this Mac permits
key operations. Do not promise application-signature isolation. Removing files made
normal opening fail, but restoring previously copied references restored operations:
**local cleanup is not irreversible hardware destruction**. As already specified
in ADR 0017, phone-side revocation is authoritative; desktop cleanup cannot revoke
an offline phone. The candidate must describe removal of its exact local references,
not destruction of every copy, and must not reset replay state when old files return.
Same-Mac replay rollback and deletion-pending restoration still require PR 3/5 review.
No automatic backend fallback or weakening of phone verification is introduced.

Terminal → probe, Terminal → age → plugin, and GUI → age → plugin need independent
evidence under the actual source-install build. This research executable is not an
age plugin; its success cannot certify either age call chain. Verify unlocked,
locked, post-login, post-reboot and logged-out/SSH behavior. Native denial remains
terminal; no authentication cache, software private key or broadened global ACL
may be used to make an experiment pass.

## Storage and migration contract for PR 3

Use protected direct children of `~/Library/Application Support/age-plugin-phone`.
Metadata, locators and replay remain business-layer formats. Audit descriptor-relative
operations, owner/type/link/ACL checks, replacement, exclusive locking and directory
sync on APFS; measure `F_FULLFSYNC` requirements before accepting durability claims.
The research harness creates no production metadata, locator, replay or journal.

Exclude private state from backups and never restore hardware keys onto a new Mac.
This does not prove protection against same-Mac replay rollback after restoring an
old snapshot. That guarantee and its threat-model boundary are still unresolved;
PR 3 must address it explicitly. A missing/corrupt/uncertain replay scope stays
unavailable, including after cancellation or failed writes.

Old `APDK2` software keys cannot be imported into Secure Enclave. Keep old state
intact: recover plaintext through a still-usable old path or an independent recovery
recipient already present in the ciphertext, create a fresh hardware pairing, and
re-encrypt to its new recipient (including independent recovery). Verify recovery
before revoking the old pairing. A new pairing cannot decrypt old v2 ciphertext.
No migration switch or silent software fallback is planned.

## Evidence and exit gate

See [M0 native record and runbook](../macos-m0-evidence.md). The original Keychain
creation failed; the CryptoKit source-install candidate now passes dual-key creation,
reopening, signature/ECDH interoperability, rebuild continuity and local-reference
failure/cleanup tests. Wrong-device copying, pre-first-unlock/logged-out behavior, final minimum OS,
production storage/replay and phone/caller combinations remain unverified.
The same-host follow-up also passed 16 native verifications dispatched by four
workers, a minimal-environment piped call, and reopening after SIGKILL of a holder
process. These tests do not certify concurrent provisioning or replay serialization.
The [physical session run](../macos-m0-session-evidence.md) also passed reopening
the original keys after an actual reboot and user login, with a changed boot ID
and unchanged binary/reference digests. This does not cover pre-first-unlock access.
PR 2/3 have a tested native feasibility input under the user-selected single-host
baseline. The original multi-host/multi-OS matrix is now a deferred expansion gate,
not a prerequisite for continuing this baseline. It remains unverified. Hardware-key destruction must not be claimed from the file-cleanup test.

The probe does not process requests, pairing transcripts or file keys. Cancellation,
replay, wrong-device, timeout and malformed protocol negative tests remain required
when later PRs change those behaviors. Here malformed CLI input is tested without
Keychain access; the explicit runner covers duplicate creation, missing roles,
reopening, cleanup and optional two-build continuity when hardware works.

## Primary references

- [Apple: Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple: TN3137, On Mac keychains](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- [Apple: Sharing access to keychain items](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
- [Apple: Storing CryptoKit keys, encrypted Secure Enclave representations](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain)
- [Apple: Secure Enclave key reconstruction](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement/privatekey/init%28datarepresentation%3A%29)
- Future distribution only: [Apple: Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Apple: Hardware security overview](https://support.apple.com/guide/security/hardware-security-overview-secf020d1074/web)

These describe platform facilities; they do not replace this project's measurements.
