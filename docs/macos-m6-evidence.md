# macOS M6 review and acceptance status

Date: 2026-09-09. Status: **in progress; no full macOS support claim**.
Implementation snapshot `cc7e120` includes M1/M2 storage and keys, M3 managed/explicit
pairing and cleanup, M4 directed discovery and status, and M5 installation harnesses.
This record separates automated checks from the required human/device evidence.

## Focused implementation review

The review covers native FFI ownership, two separate hardware roles, metadata
binding, descriptor-relative storage, pending markers, cleanup scope, setup stages,
transport preflight and installed executable continuity. Core and desktop remain
unsafe-free. The Swift/Rust bridge implements prehashed ECDSA and ECDH through
platform-keys; hardware failures do not enter a software fallback. The public wire
protocol and mobile authentication implementation were not changed for this port.

The following findings were addressed during implementation:

- Multihomed send failures could be hidden by a successful send on another interface.
  Every send error/short send now terminates discovery; tests cover mixed outcomes.
- Cleanup needed native ownership and lock checks, exact temporary attribution,
  and protection against paths shared with another pairing. The native boundary
  and negative tests now cover those cases and interrupted teardown.
- Explicit pairing created hardware state before transport preflight and lacked a
  durable record for partial caller-selected state. It now uses the same confirmed
  setup state machine, with a separate strict version 3 explicit-path journal.
- A lost phone response could suppress the phone-revocation reminder. Attempts that
  reached Pairing now retain that reminder even without a persisted candidate.

The [M2 rollback counterexample](macos-m2-evidence.md) remains unresolved. A new
synthetic regression restores pre-consumption response-store bytes and verifies
that a previously successful response is rejected by a fresh session, then cannot
be retried in that session. This tests an independent cryptographic binding; it
does not establish store freshness or close the M2 gate. The
[scope decision](macos-replay-decision.md) is pending, with no weakening approved.
This local review does not replace the project's independent external security review.

## Current host and artifact observations

| Item | Evidence |
| --- | --- |
| Mac baseline | MacBookPro18,3 / arm64 / macOS 26.6.2 (25G83), logged-in session |
| Desktop source installation | Four detached crates tested and registry-installed at `cc7e120` with Rust 1.88; all final archived inputs verified |
| Installation lifecycle | [M5](macos-m5-evidence.md): initial install, changed executable hash, uninstall and reinstall preserve synthetic hardware/replay state |
| Native journal modes | Explicitly invoked synthetic Secure Enclave test passes managed and explicit paths, reopens both roles and exercises exact CLI cleanup |
| Attached Android | Samsung SM-F9660, Android 16; one authorized USB device observed |
| Installed Android package | `io.github.biulight.age_plugin_phone`, version `0.1.0-alpha.4`, versionCode 1000 |
| Installed APK SHA-256 | `6e77ada9917673f0a5a392bb9a4327dd2275f9ff403d15015a6280da190d4f62` — matches the recorded alpha.4 signed artifact |
| New Mac/Android pairing | User-operated ADB setup succeeded; exit 0 and identity reference created |
| Windows regression | Native Windows 11 / Rust 1.96 four-crate fmt, all-target Clippy and 96 tests pass after two platform lint annotations; TPM creation/reopen and read-only status pass |

The APK digest was calculated on the installed public APK, without reading app
private data. It identifies the mobile artifact; historical Windows/Android
acceptance does not count as a new macOS pass. No phone identity was replaced,
pairing revoked, phone verification automated or real plaintext processed.

## Required remaining rows

| Gate | Status |
| --- | --- |
| M2 same-Mac valid-state rollback | Open; retain original requirement until solution/reviewed decision |
| Exact final archive and installed digest | Passed for `cc7e120`; digest below |
| Terminal → age/rage → installed plugin | Public synthetic matrix passes; Ghostty → age 1.3.2 / rage 0.12.1 → Android ADB and iPhone Wi-Fi pass, including fresh native approvals and cancellation |
| GUI application → age → installed plugin | Pending; Terminal permissions do not establish GUI permissions |
| Android ADB pairing and two separate successful unwraps | User-operated setup and two independent decryptions pass; user confirms fresh native verification for every approval |
| Cancellation and subsequent success | Android ADB cancellation returns failure without plaintext; subsequent fresh approval succeeds |
| Timeout, unplug, daemon/process interruption | New Mac/Android physical evidence pending |
| Wi-Fi multihoming, interface changes, ambiguity and permission errors | Logic tests pass; applicable physical combinations pending |
| Built-in/UVC cameras; first allow, deny, revoke and occupied camera | Pending caller-specific physical tests |
| Revocation, interrupted cleanup and independent recovery drill | Synthetic cleanup passes; human/native endpoint-loss drill pending |
| Published-version upgrade/downgrade | Not tested by same-source rebuild or commit-to-commit continuity |
| iPhone | iPhone 15 Pro / iOS 26.6.1; debug build 0.1.0.4 Wi-Fi pairing and four data checks pass; three fresh Face ID approvals and deliberate cancellation confirmed by user; QR untested |
| Wrong Mac, other OS, Intel/T2 | Deferred/unverified; not part of the current host/Android acceptance claim |

The [source quick start](macos-quickstart.md) provides the human-operated path.
Record each tested transport/caller and exact artifact separately. Do not turn an
unavailable device, a pending answer, an ignored test or a historical pass into a
completed row. The user must compare the entire fingerprint and perform every
native phone verification and destructive confirmation personally.

## Final automated artifact results

The `cc7e1208811c296d53921b22f755504716e6ab2f` source candidate completed the final
four-crate Rust 1.88 rehearsal. The installed executable SHA-256 is
`cd45e6e6a45004ea7e4c298aed1aedd7578fdd45506408d2ad068c42e11560d7`.
A changed-optimization rebuild produced
`1f2c82fee7c2dad1176f499635221d41d45c74c4c68ed2419931ebd57f565873`;
subsequent uninstall/reinstall restored the original executable hash. Both builds
reopened the same synthetic hardware roles and rejected the consumed replay digest;
file content hashes and permissions stayed identical throughout.

The final installed binary also reopened the original M5 fixture created with
`5a75ee2`, preserving all original state hashes and replay consumption. This adds
commit-to-commit continuity evidence; it is not a published-version upgrade test.
The final native setup test passed both managed and explicit layouts. macOS x86_64
all-target checking and Windows x64 core/keys/storage all-target checking pass;
these are compile-only observations, not Intel/T2 or Windows runtime acceptance.

The installed binary passed `interoperability-smoke.sh` with age 1.3.2 and rage
0.12.1: 12 independent recoveries and 2 expected recipient rejections, without a
phone or real data. The test discovers this exact plugin through PATH. Temporary
synthetic encryption/recovery files are removed by the existing test harness.
This establishes public plugin/client interoperability, not phone-backed decryption.

See [machine-readable evidence](macos-m6-acceptance-results.json) for archive file
hashes, executable hashes, the lifecycle phases and explicit open gates. The
retained installed executable is:

```text
/private/tmp/age-phone-macos-final-registry-20260909/install/bin/age-plugin-phone
```

## Native Windows regression

With explicit user authorization, the exact 4,300,800-byte `cc7e120` source archive
was copied to a fresh Windows temporary directory and its SHA-256 verified before
extraction. The existing Windows checkout was not used. Windows 11 build 22631,
Rust/Cargo 1.96 and an isolated Cargo target directory ran the four desktop crates.

Native Clippy found two platform-only warnings: `validate_layout` is infallible
outside macOS, and the unsupported explicit-root validator does not use `self`.
Narrow lint annotations retain the shared platform interface without changing
runtime behavior. The user separately authorized transferring those two updated
files. Their hashes are recorded in the machine-readable evidence.

After the annotations, fmt, all-target locked Clippy with warnings denied, and all
96 tests passed (60 desktop, 25 core, 2 public vectors, 4 platform keys, 5 platform
storage; no ignored tests). The key tests exercised actual TPM creation and reopen.
The read-only CLI status reported TPM 2.0 and Microsoft Platform Crypto Provider
support. The executable SHA-256 was
`67e19d13f46f3b09f0c19a993c2b0da84c0c60506b0aadd958f83f562f6fe63c`.
No Windows/phone integration was performed. Mac workspace fmt, Clippy and tests
also passed after these annotation changes; the previously installed Mac candidate
and its historical archive evidence remain identified separately above.

## iPhone application preparation

The paired iPhone 15 Pro (user-reported iOS 26.6.1) previously had build `0.1.0.3`.
Source `7d02d74` built an arm64 debug IPA using the existing local Apple Development
identity. The signing team was supplied only through the environment; credentials
and provisioning configuration are not committed. The IPA SHA-256 is
`e74c0761839b4c2ed10afb8bca3ff839a00bed0d58b95080e561ebe7b50bf09c`.

`codesign --verify --deep --strict` passed with access to the host trust service
(the sandbox-only attempt could not establish trust). CoreDevice installed the app
in place, reported version `0.1.0` / build `0.1.0.4`, and successfully launched it.
There was no uninstall, identity replacement or automated native authorization.
This establishes local development installation only; it is not distribution,
Secure Enclave identity use, pairing, Wi-Fi/QR or Face ID acceptance evidence.

## Android ADB pairing and native unwrap acceptance

The user ran the installed `cc7e120` candidate in Ghostty against the recorded
StrongBox Android APK. Setup exited zero and created the public identity reference.
The age 1.3.2 harness encrypted 128 random disposable bytes using setup's `recipient`
with `-r`, then used `identity_path` with `-i` for four separate decryptions:

| Operation | Client result | Data check |
| --- | --- | --- |
| First native approval | Exit 0 | Exact round trip |
| Second native approval | Exit 0 | Exact round trip |
| Phone cancellation | Exit 1 | No plaintext output |
| New approval after cancellation | Exit 0 | Exact round trip |

The user explicitly confirmed a new native biometric prompt was completed for all
three approvals. The cancellation's generic client error (`phone response unavailable
or malformed`) was expected by this negative test. After the flow, the selected
phone had no ADB reverse rules, and the harness retained no temporary plaintext
directory. Machine-readable evidence binds the script, results, installed plugin
and APK hashes; it contains no phone keys, protocol payloads or plaintext.

Two acceptance-script errors were corrected before this successful run: its PATH
initially omitted Android SDK platform-tools, and encryption incorrectly supplied
the identity file to `-R`. Those failed before pairing state creation and before
unwrap respectively; neither is counted as a successful protocol test.
This row does not establish Wi-Fi, QR, GUI caller, timeout, unplug or replay-rollback
acceptance. Those gates remain separate.

## iPhone Wi-Fi pairing and unwrap acceptance

The user completed Wi-Fi pairing from Ghostty with the installed `cc7e120`
Mac candidate and iPhone development build `0.1.0.4`. Setup exited zero and
created the identity reference. With foreground Wi-Fi auto-listen, age 1.3.2
passed two independent decryptions, rejected a cancelled request with exit 1
and no plaintext output, then successfully decrypted on a new request.
All successful outputs matched the random disposable input. No temporary
plaintext directory remained. Script and result hashes are recorded separately
from the Android ADB run.

The user explicitly confirmed three new Face ID verifications and deliberate
cancellation of the third test. The four client/data checks and this human/native
observation pass. QR, background operation, camera/network permission cases and
other callers are not established by this foreground Wi-Fi run.

## rage caller acceptance on both phones

The same installed Mac candidate completed the four-operation matrix with rage
0.12.1 on Android ADB and separately on iPhone foreground Wi-Fi. Each run passed
two independent decryptions, a deliberately cancelled operation (exit 1 and no
plaintext), and a successful new request after cancellation. The user confirmed
new native verification for all six approvals and personally cancelling both
negative tests. Each successful output matched its random disposable input;
no temporary plaintext directories remained. Per-phone harness/result hashes
and client/transport metadata are recorded in the JSON evidence. This covers
these two transport/caller combinations, not Android Wi-Fi or either phone's QR.

## Android Wi-Fi initial attempt — incomplete

A second, distinct desktop pairing with the Android phone completed over Wi-Fi;
the original USB identity reference remained. age passed all four data checks.
rage passed its first approval, then failed before stream exchange with the
coarse discovery error `phone Wi-Fi discovery failed or was ambiguous`.
The user could not recall foreground/listener/network state or confirm native
observations for this run. This is an open failure, not a passed Android Wi-Fi
acceptance row. A later retry must retain this observation and cannot by itself
establish the cause of this failure.

## Reproduced Android Wi-Fi failure and discovery diagnostics

A separate rage retry reproduced first approval success followed by second-request
discovery failure. The user observed only the first fingerprint prompt; the second
operation stopped before an unwrap request could be sent. This does not establish
cached authorization. Later, three independent authenticated discovery queries
per phone each found one listener. These later observations do not explain the
failure or close the Android Wi-Fi gate.

The identity adapter now preserves the coarse `WifiError` classification instead
of conflating no listener, multiple listeners and local network failure. Routing,
deadlines and fail-closed behavior are unchanged. The `wifi-discovery-probe` example
runs three fresh authenticated queries using only a public identity reference;
it opens no stream, performs no identity operation, and outputs no addresses,
identifiers or protocol payloads. Mac fmt, all-target workspace Clippy and locked
workspace tests passed for the diagnostic change.
