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
| New Mac/Android pairing | **Not performed**; APK/version inspection is read-only |
| Windows regression | Three Windows libraries pass cross-check; full desktop cross-check stops in mozjpeg-sys (`-fPIC` unsupported). Windows host/toolchain are reachable, but source transfer awaits explicit authorization after auto-review rejection |

The APK digest was calculated on the installed public APK, without reading app
private data. It identifies the mobile artifact; historical Windows/Android
acceptance does not count as a new macOS pass. No phone identity was replaced,
pairing revoked, phone verification automated or real plaintext processed.

## Required remaining rows

| Gate | Status |
| --- | --- |
| M2 same-Mac valid-state rollback | Open; retain original requirement until solution/reviewed decision |
| Exact final archive and installed digest | Passed for `cc7e120`; digest below |
| Terminal → age/rage → installed plugin | 12 public synthetic recoveries and 2 malformed-recipient rejections pass; real phone flow pending |
| GUI application → age → installed plugin | Pending; Terminal permissions do not establish GUI permissions |
| Android ADB pairing and two separate successful unwraps | Pending full human fingerprint comparison and fresh native verification |
| Cancellation, failure then success, timeout, unplug, daemon/process interruption | New Mac/Android physical evidence pending |
| Wi-Fi multihoming, interface changes, ambiguity and permission errors | Logic tests pass; applicable physical combinations pending |
| Built-in/UVC cameras; first allow, deny, revoke and occupied camera | Pending caller-specific physical tests |
| Revocation, interrupted cleanup and independent recovery drill | Synthetic cleanup passes; human/native endpoint-loss drill pending |
| Published-version upgrade/downgrade | Not tested by same-source rebuild or commit-to-commit continuity |
| Wrong Mac, other OS, Intel/T2, iPhone | Deferred/unverified; not part of the current host/Android acceptance claim |

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

Windows native verification was prepared for `nuc.win.local`, which returned host
name `biulight`, Windows 11 build 22631 and Rust/Cargo 1.96. The automatic approval
review rejected sending the source archive because the payload/destination lacked
explicit authorization. A local 4,300,800-byte archive and manifest are prepared;
no archive was sent and no remote checkout was changed. This permission dependency
is separate from product test success or failure.
