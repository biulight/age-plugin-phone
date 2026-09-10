# macOS M6 review and acceptance status

Current scope note (2026-09-10): the user approved the common Windows/macOS
[desktop replay restore boundary](desktop-replay-rollback-poc.md). Stronger snapshot
freshness is deferred to a later POC, not fixed or passed. Earlier statements below
that rollback alone blocks Mac acceptance describe the pre-decision scope. All
measured counterexamples and other outstanding acceptance gates remain valid.

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
| Desktop valid-state rollback | User-approved common Windows/macOS limitation; stronger protection deferred to later POC, not passed |
| Exact final archive and installed digest | Network-corrected archive/install passed; installed digest `078d3f1d…f42f12cd`, full evidence below |
| Terminal → age/rage → installed plugin | Current installed artifact: Android and iPhone Wi-Fi each pass all eight cases; current Android USB also passes eight cases with reverse cleanup; both phones also pass current-artifact QR success; older QR negative evidence retained separately |
| GUI application → age → installed plugin | Deferred by user on 2026-09-10; outside current CLI acceptance, not passed |
| Android ADB pairing and two separate successful unwraps | User-operated setup and two independent decryptions pass; user confirms fresh native verification for every approval |
| Cancellation and subsequent success | Android ADB cancellation returns failure without plaintext; subsequent fresh approval succeeds |
| Android USB unplug/reconnect | Pending approval interrupted, no plaintext; rules empty on reconnect; fresh approval succeeds |
| Android USB natural timeout | 60.383-second automatic failure, no plaintext, clean rules and new verification afterward pass |
| Caller/plugin process-tree termination | SIGKILL while approval pending passes no-plaintext, prompt-close, cleanup and fresh retry checks |
| ADB service restart | Ordered restart passes no-plaintext, prompt-close, cleanup and fresh retry; initial immediate-start error retained below |
| Android USB cold app launch | Current installed artifact: age/rage both pass process-absent start, automatic app launch, fresh fingerprint and empty reverse rules |
| Wi-Fi phone background and lock | Both phones pass pending-request failure without plaintext and fresh verification after foreground/unlock |
| Wi-Fi phone process termination | Both phones pass process absence and no-plaintext failure; Android automatic relaunch and iPhone separate manual relaunch recover with new verification |
| Android Wi-Fi loss/reconnect | Radio disable confirmed, same app process, no-plaintext failure and fresh recovery pass; exact failure latency not measured |
| Android QR native cancellation and recovery | age/rage cancellation and natural timeout without plaintext pass; fresh fingerprint recovery passes, age recovery used a separate run/new ciphertext |
| iPhone QR native cancellation and recovery | age/rage: user cancellation, natural scan timeout without plaintext, fresh Face ID recovery pass |
| Wi-Fi multihoming, interface changes, ambiguity and permission errors | Logic tests pass; applicable physical combinations pending |
| Camera permission denial/revocation | Deferred by user for current version on 2026-09-10; QR is not the primary flow, not passed |
| Other camera coverage | Built-in QR success passed; first-permission grant, occupancy and external UVC remain separate unverified rows |
| Independent recovery drill | Six age/rage cases pass with the phone plugin and desktop state unavailable |
| Revocation and normal cleanup | Android QR pairing revoked; old ciphertext rejected without biometrics, recovery and original USB pairing pass; desktop cleanup preserves 21 other file hashes |
| Interrupted and orphan cleanup | Synthetic tests pass; physical lifecycle cases remain pending |
| Published-version upgrade/downgrade | Not tested by same-source rebuild or commit-to-commit continuity |
| iPhone | iPhone 15 Pro / iOS 26.6.1; debug build 0.1.0.4 Wi-Fi pairing and four data checks pass; Wi-Fi approvals/cancellation and age/rage QR approvals pass with fresh Face ID confirmed |
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
and client/transport metadata are recorded in the JSON evidence. This section covers
these two transport/caller combinations; later QR observations are recorded separately.

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

## Diagnostic-build comparison

A separate debug build at `1b8041c` (SHA-256
`b24b3b224eee1082ffcce6bfd6bb4dfc1d8af75395b31dbd490670ec969163eb`)
passed two consecutive rage/Android Wi-Fi decryptions. The user confirmed a new
native fingerprint verification for each. This build changes only discovery error
reporting and adds the independent probe; no listener fix was implemented.
Its success therefore does not close the intermittent failure on the original
installed `cc7e120` release artifact. The original candidate remains unchanged.

The original installed candidate comparison again passed the first rage unwrap and
failed the second during discovery. Immediate follow-up probes found no matching
listener twice, then one authenticated listener on the third query window. This
establishes a transient discovery outage after the failure, without identifying
whether listener re-arming, phone lifecycle, signing or network delivery caused it.
Later read-only Android inspection found both fixed listening ports and the app
foregrounded. The socket inspection also reports a permission warning, so missing
port visibility alone must not be treated as definitive proof of a closed socket.

## Successful sampled run and independent recovery

The original candidate passed two rage/Android Wi-Fi requests during coarse ADB
status sampling. All 14 samples reported the app foregrounded. Listening ports
were visible at 6.966 seconds, about 0.160 seconds after the first client exit;
the next request began 2.253 seconds after that exit. Port presence sampling is
not continuous and has a permission warning. This successful, instrumented run
does not diagnose prior failures; sampling itself may affect timing. Native prompt
observation for this particular run has not been separately confirmed.

Six independent recovery cases passed: age 1.3.2 and rage 0.12.1 each encrypted
0, 128 and 65,537 disposable bytes to both existing phone recipients plus a newly
generated independent test recovery recipient. Recovery used only that test
identity, with unavailable desktop state and a guard executable that would fail
and record any phone-plugin invocation. No guard was invoked; every recovered
output matched exactly. Temporary recovery keys, plaintext and ciphertext were
removed. This simulates unavailable primary endpoints without deleting user keys;
it does not establish revocation, native destructive cleanup or re-encryption
through a replacement pairing. Empty output was captured to a file by the harness
because rage may not create an `-o` file for an empty plaintext.

## Android QR initial run — native observation open

The user completed QR pairing with the original installed Mac candidate; setup
exited zero and saved its identity reference. Separate age and rage QR decryptions
both exited zero and recovered the disposable input exactly. No temporary plaintext
directory remained. The user could not recall whether fresh fingerprint prompts
appeared. Camera selection was not confirmed. Therefore these are successful
QR data checks, not completed fresh-native-verification or built-in-camera rows.
Subsequent human-operated harnesses should record each native observation
immediately after that operation, before proceeding to another request.

## Android QR per-operation native observation

A separate observed run passed QR decryption with age and rage on the original
installed candidate. Immediately after each operation, the user explicitly recorded
a fresh fingerprint verification in the harness. Both outputs matched the disposable
input. This closes the successful Android QR/native-approval cases for these callers;
the user identified the Mac built-in camera. Cancellation/timeout, external cameras
and permission cases remain separate.
The earlier unconfirmed run remains preserved rather than relabeled.

## iPhone QR per-operation Face ID observation

QR setup with the original installed candidate exited zero and created its
identity reference; the user confirmed pairing completion. age and rage then each
successfully decrypted a disposable file over explicitly selected QR. Immediately
after each operation, the user recorded a new Face ID verification. Outputs matched
exactly and no temporary plaintext directories remained. The harness instructed
use of the Mac built-in camera; camera attribution for this iPhone run was not
separately confirmed. QR cancellation/timeout and camera permission negatives
remain untested. No QR images or payloads are retained in the evidence.

## Android single-pairing revocation and isolation

The user revoked only the Android QR test pairing in the native phone UI. An old
ciphertext for that pairing was then tested through explicit ADB, separating
revocation enforcement from QR availability. The client exited 1 with no plaintext;
the user immediately confirmed no biometric prompt appeared. An independent test
recovery identity decrypted the same ciphertext successfully. The original Android
USB pairing still decrypted its own ciphertext, with the user immediately confirming
fresh fingerprint verification. Desktop state for the revoked pairing remained
present throughout this test; normal desktop cleanup is the next separate step.

## Native desktop cleanup after phone revocation

The user ran the original installed candidate's `remove-desktop-state` for the
revoked Android QR pairing and personally entered its exact full fingerprint.
The command exited zero. The identity reference was absent afterward, no files
named for that desktop identifier remained, and content hashes of all 21 other
regular files in the private state directory were unchanged. This establishes
normal removal and file-level isolation for this exact target, not interrupted
or orphan cleanup. The temporary recovery key, ciphertext fixtures and their
manifest were then removed; coarse acceptance results were retained.

## Android USB interruption and reconnect

While the original installed candidate awaited fresh phone verification, the user
unplugged the Android USB cable without approving. ADB sampling observed the device
disconnect; age exited 1 and produced no plaintext. The user immediately confirmed
unplugging at the pending prompt and its subsequent automatic closure. After the
user reconnected, the reverse-rule list was empty. The retained pairing then
successfully decrypted with a new fingerprint verification confirmed by the user;
its reverse-rule list was again empty. No temporary plaintext directory remained.
This establishes unplug/reconnect behavior; daemon restart, process termination and
natural authentication timeout are separate cases.

## Android natural authentication timeout

With USB connected, the user left the native fingerprint prompt unapproved and
did not cancel it. age failed after 60.383 seconds with exit 1 and no plaintext;
the user confirmed automatic prompt closure. The reverse-rule list was empty.
A subsequent new request decrypted successfully with a fresh fingerprint
verification confirmed immediately by the user; rules were again empty. Temporary
plaintext was removed. This is actual native timeout evidence, not a harness-killed
process or an inferred cancellation result.

## Android pending request interrupted by process termination

After the user confirmed the phone verification prompt was pending and unapproved,
the harness sent SIGKILL only to its newly created age/plugin process group.
The client exited with signal 9, no plaintext was present, the user confirmed
that the phone prompt closed automatically, and the reverse-rule list became
empty. A new request then decrypted successfully with a fresh fingerprint
verification confirmed by the user; its rules were also cleaned. The independent
cleanup guardian was outside the killed group. This tests caller/plugin tree
termination, not ADB service restart. Temporary plaintext was removed.

## Android ADB service restart: incomplete initial attempt

The user confirmed a pending, unapproved fingerprint prompt before the harness
stopped and immediately restarted the local ADB server. `kill-server` exited 0,
but `start-server` exited 255. The old age request exited 1 with no plaintext;
the user confirmed automatic prompt closure and the reverse-rule list was empty.
The harness correctly stopped before its fresh-approval recovery case. A later
connection check reported the selected device online. The startup error was not
retained by the initial harness, so its cause is undetermined; concurrent cleanup
is only a hypothesis. This attempt does not pass the service-restart gate.

## Android ADB service restart: ordered retry

The retry stopped the local ADB server while verification was pending, waited for
the old client to exit and finish cleanup, then explicitly started the server.
Both service commands exited 0. The old request exited 1 without plaintext, the
user confirmed automatic prompt closure, and reverse rules were empty. A new
request decrypted successfully with fresh fingerprint verification confirmed
immediately by the user; reverse rules were again empty. No temporary plaintext
directory remained. This passes the ordered restart and recovery case for the
original installed candidate. It does not explain the initial immediate-start
exit 255 or establish that concurrent server startups always succeed.

## iPhone QR native cancellation, scan timeout and recovery

On 2026-09-10, the user repeated an interrupted QR cancellation test with a
separate result file and the original installed candidate. The user immediately
confirmed cancelling native Face ID without a phone response QR. age 1.3.2 exited
1 after 300.138 seconds without plaintext; the harness did not terminate it.
The elapsed time is consistent with the desktop scanner's five-minute deadline.
A new QR request then recovered the exact temporary input, and the user confirmed
fresh Face ID immediately. No temporary plaintext directory remained. This is
phone cancellation followed by desktop timeout, not immediate cancellation
signalling over QR. The earlier interrupted attempt produced no result file and
is not counted as a pass. Other callers and QR permission/lifecycle cases remain
separate gates.

The same iPhone QR cancellation/recovery sequence also passed with rage 0.12.1.
The user immediately confirmed native cancellation without a response QR; rage
exited 1 after 300.080 seconds with no plaintext and no harness termination. The
next request recovered the exact temporary input with new Face ID confirmed by
the user. Temporary plaintext was removed. Both reference callers now have this
negative QR case on the original installed candidate; permission and other
lifecycle cases remain open.

## Android QR native cancellation and recovery

On 2026-09-10, the original installed candidate used the retained Android USB
pairing with QR explicitly selected. The revoked/deleted Android QR pairing was
not reused. With age 1.3.2, the user confirmed native fingerprint cancellation
without a response QR; the client exited 1 after 300.091 seconds without plaintext
or harness termination. The user then interrupted the harness. A separate recovery
run generated new disposable ciphertext and decrypted it successfully with a fresh
fingerprint confirmed immediately. This establishes a later new request succeeds,
not same-ciphertext recovery in the interrupted age run.

With rage 0.12.1, native cancellation likewise produced no plaintext and a natural
client failure after 300.096 seconds. The subsequent request in that same run
recovered the exact input with fresh fingerprint verification confirmed by the
user. No temporary plaintext directories remained. These are QR cancellation and
scan-deadline results; permission and other lifecycle gates remain open.

## Passive Android Wi-Fi failure reproduced without unwrap

On 2026-09-10, ADB confirmed the Android device online and the app foregrounded.
The existing Rust discovery-only probe first returned no matching listener twice,
then one authenticated listener; its next three queries all succeeded. TCP 47140
and UDP 47141 were visible before both batches, with the known socket inspection
permission warning. No TCP stream, unwrap request or biometric operation was
started. This reproduces a discovery outage without an immediately preceding
unwrap, so post-unwrap listener re-arming alone cannot explain every occurrence.
Port visibility before a batch does not prove listener health throughout it.

A separate temporary Python diagnostic compared broadcast with unicast to the
ADB-observed phone Wi-Fi address. It checked exact nonce-bound response prefixes,
length, low-S P-256 signatures and the discovery signature domain; only timings
and counts were retained. All six queries received valid responses within
0.202–0.534 seconds. Two broadcast queries also had local send errors. Unlike the
production client, this diagnostic counted those errors and kept observing, so
receiving a signature in those runs is not a production success. A follow-up
with UP/RUNNING/BROADCAST interface flags was recorded separately. The initial
comparison did not require RUNNING and must not be equated with production
interface selection. These diagnostic runs do not establish the outage cause,
change route selection, or justify relaxed deadlines or authentication checks.

The active-interface follow-up received authenticated responses in all four
queries (0.178–0.326 seconds), but its last broadcast query counted one
EHOSTUNREACH and twelve EHOSTDOWN send errors. These are local route failures,
not evidence of a phone signature failure; the affected route is not yet
identified. Synthetic checks of the temporary diagnostic verifier accepted a
valid response and rejected truncation, a different query, high-S and a wrong
signing key. No product code or timeout was changed.

## Virtual-network route attribution

The user reported Surge with system proxy enabled and ZeroTier virtual networking
on the Mac. Read-only inspection confirmed HTTP, HTTPS and SOCKS proxy flags; it
does not establish TUN interception. Network settings were not changed.
A route-attributed discovery-only diagnostic observed the broadcast target derived
from en13 routing through en0 (Wi-Fi), while the phone unicast, Wi-Fi subnet
broadcast and limited broadcast also used en0. Another subnet target routed through
feth4032. The run recorded one broadcast query with no authenticated response and
no send errors, followed by successful phone unicast at 0.320 seconds. A later
broadcast received a valid response at 0.276 seconds but counted EHOSTUNREACH once
and EHOSTDOWN three times, all for the en13-derived target; the next unicast
succeeded at 0.271 seconds. These are distinct observations: route errors do not
by themselves explain the no-response run.

The ZeroTier CLI was available but its read-only network query exited 2; en13
ownership is therefore not confirmed. A controlled comparison with ZeroTier
paused and Surge unchanged remains pending. No addresses, network identifiers,
credentials or discovery payloads were retained in the evidence. The diagnostic
continues counting send errors and is not a product routing or fallback change.

The user requested a direct retry with ZeroTier and Surge left enabled; no pause
comparison was performed. The first diagnostic broadcast again received no
response, while unicast succeeded at 0.285 seconds. The next broadcast received a
signature at 0.329 seconds but counted one EHOSTUNREACH and thirteen EHOSTDOWN
errors on the en13-derived target. The next unicast succeeded at 0.277 seconds.
A subsequent run of the existing Rust discovery probe succeeded on all three
queries. This records intermittent behavior under unchanged networking, not a
fix or proof that either network application is the cause. No unwrap or biometric
operation was requested.

The user subsequently identified the ZeroTier network as using 10.x addresses.
A read-only interface classification found feth4032 in 10/8, Wi-Fi en0 in
192.168/16, and en13 using an IPv4 link-local address outside RFC1918. Thus the
recorded en13-derived send errors were on a different address class from the
user-identified ZeroTier network. This does not independently prove which process
owns either interface, or explain the no-response broadcast queries. Production
`private_route` explicitly includes link-local addresses, so en13 eligibility is
not merely an artifact of Python's address classification. Network settings
remain unchanged; full addresses were not retained.

## Compact macOS netmask and interface-scoped discovery correction

The user identified a shared private Wi-Fi subnet and requested that ZeroTier and
Surge remain enabled. Native structure inspection then found the primary code
defect: Darwin returned full interface addresses but compact netmasks with
`sa_len` 6–7. The original parser required a full 16-byte `sockaddr_in` for both,
so it dropped every eligible interface on this host. The original product fell
back to limited broadcast only. Earlier Python diagnostics enumerated interfaces
independently; their en13 send errors were not proof the original Rust product
sent to en13. Those historical observations remain retained with this correction.

The new parser copies only the advertised mask bytes and zero-extends the omitted
suffix. Automatic discovery now targets RFC1918 interfaces, excludes self-assigned
link-local interfaces, and retains virtual private interfaces. Every interface
uses its own source-address UDP socket; both directed and limited broadcasts use
`IP_BOUND_IF` for that interface. Reception rotates among sockets. An enumeration,
binding or send error remains terminal; no unscoped fallback, timeout extension,
phone authorization cache or protocol change was added. Explicit link-local routes
remain valid. No concrete host subnet is hardcoded as a supported network.

Intermediate candidates are retained separately: interface scoping without the
mask fix failed immediately because no routes remained; fixing the mask while
sharing one unbound-source socket still yielded six no-response queries. Separate
source-address sockets then passed six consecutive authenticated Android discovery
queries with the existing VPN/proxy settings. The final receive-rotation change
requires its own final artifact record and human unwrap acceptance; earlier
candidate successes are not a substitute for that acceptance.

The final receive-rotation candidate subsequently passed six more authenticated
Android discovery queries with ZeroTier and Surge retained. Its exact debug binary
and probe digests, source-file hashes and automated check results are recorded in
`macos-m6-acceptance-results.json` under `macos_wifi_interface_fix`. The full locked
workspace test suite, all-target Clippy with warnings denied and formatting check
passed. Native hardware-only tests retain their declared ignored status; the real
loopback interface-binding test ran successfully. Existing `block 0.1.6` future
compatibility and cached Xcode build-script warnings remain. This new candidate
has not yet completed user-operated age/rage unwrap acceptance or archive-install
revalidation; the original installed candidate's earlier passes are not transferred.

Documentation review for this correction compared the working tree with `9506563`
and updated only this product repository's architecture, discovery ADR, quick start,
M4/M6 evidence and plan. The nearby documentation registry has no entry for this
product and no migrated bilingual manual mapping; no other repository was changed.

## Residual Android discovery failure and reception candidate

With Mac commit `c9c2a3f` and ZeroTier/Surge unchanged, the user completed two age unwraps,
confirming a new native fingerprint immediately after each. The next intended cancellation
failed in discovery before any native prompt; the user answered `n`. It is a failed acceptance
case, not successful native cancellation. Recovery and rage cases were not reached.

Afterwards, the Android app was foregrounded with TCP/UDP sockets visible (socket inspection
also emitted a permission warning), and three authenticated probes succeeded. Three additional
probes succeeded while recorded APF broadcast/multicast counters stayed unchanged. These
system counters include unrelated traffic and do not prove the failed request was filtered.

The Android candidate now scopes multicast reception ownership to each foreground discovery
responder, including release on startup failure and concurrent close. JDK 17 Gradle
`:tauri-plugin-phone-identity:testDebugUnitTest` and `:tauri-plugin-phone-identity:assembleRelease`
passed: 73 JVM tests, zero failures/errors/skips. The release AAR build is not a signed APK
or physical acceptance. Existing cancellation, replay, wrong-device, timeout and malformed
message tests remain passing. Gradle deprecation notices remain.

The installed APK is not debug-signed; signing configuration names were found in GitHub's
`alpha-release` environment without retrieving secret values. A same-certificate APK update
is required to preserve the installed StrongBox identity and pairings. No uninstall, debug
overwrite or phone identity reset has been performed. Full age/rage physical acceptance
and final Mac archive-install verification remain open.

### Signed reception candidate installed

The user approved the existing signing environment. Actions run
[34384436759](https://github.com/biulight/age-plugin-phone/actions/runs/34384436759)
built commit `6a0cf142258a25a73bbf10fa106a2aa7cac93cda`; metadata and Android passed,
Windows and publication were skipped. Both old and new APK signatures verified and their
signer certificate SHA-256 matched. The downloaded checksum and package identity matched,
and the new normal multicast permission was present. `adb install -r` succeeded; a readback
of the installed APK matched the CI artifact digest recorded in the JSON evidence.

After opening the updated app, three authenticated discovery queries using the existing
Android Wi-Fi pairing passed without requesting native verification. This establishes
post-update discovery with the original pairing, not unwrap stability. A separate human
age/rage harness is prepared; the earlier failure record is retained. Fresh fingerprint,
native cancellation and recovery acceptance on this exact mobile artifact remain pending.

### Android Wi-Fi native roundtrip matrix passed after update

The user completed the reception-update harness in Ghostty using the recorded Mac debug
candidate and same-signed Android APK from run `34384436759`. Both age 1.3.2 and rage 0.12.1
passed first approval, second fresh approval, native cancellation without plaintext, and
approval after cancellation. All six approvals were immediately confirmed with `y` for new
native fingerprint verification; both cancellations were confirmed as intentional. All eight
cases and exact artifact/harness digests are recorded in the JSON evidence. No harness
temporary plaintext directory remains. ZeroTier and Surge stayed enabled.

This closes this artifact pair's foreground Wi-Fi unwrap matrix. Earlier failures remain
recorded; the result does not establish the cause of every historical loss or cover interface
changes, GUI permissions, background operation, other devices, or the new Cargo-installed
release artifact. The M2 rollback gate remains open.

### Cargo installation revalidated after network correction

The four detached crate archives passed their locked tests and isolated sparse-registry
`cargo +1.88.0 install --locked` completed. Archive source bytes and locked dependency versions
were checked by the rehearsal. Source provenance binds the current `a78a8cd` inputs; desktop
crate implementation is unchanged since `c9c2a3f`. The installed binary SHA-256 is
`078d3f1dbd040390bd83e0ea6a33aefd87c9f3e6ce833b7e95bb3ce9f42f12cd`.

It reopened both original M5 and previous-final synthetic hardware fixtures, rejected their
consumed replay digest, and preserved all fixture file hashes/modes. The public age/rage
interoperability harness passed 12 independent recoveries and two expected recipient
rejections. This is commit-to-commit continuity, not a published-version upgrade or a repeat
of the full uninstall/reinstall lifecycle. Native-only ignored tests are not counted as passes.
The exact installed artifact still needs user-operated phone acceptance; the debug candidate's
eight successful Wi-Fi cases are recorded separately.

### Installed Mac artifact: Android Wi-Fi matrix passed

The user completed all eight Android Wi-Fi cases with the exact Cargo-installed binary
`078d3f1dbd040390bd83e0ea6a33aefd87c9f3e6ce833b7e95bb3ce9f42f12cd` and the recorded
same-signed reception-update APK. age and rage each passed two separate approvals, native
cancellation without plaintext, and approval after cancellation. All six fresh fingerprint
observations and both intentional cancellations were recorded immediately as `y`. The
retained result and harness hashes are in the JSON evidence; no temporary plaintext
directories remain. ZeroTier and Surge stayed enabled.

This establishes the installed artifact's Android foreground Wi-Fi matrix. It does not
transfer the earlier artifact's iPhone or GUI/camera acceptance, or close M2 rollback.

### Installed Mac artifact: iPhone Wi-Fi matrix passed

The same Cargo-installed Mac artifact completed all eight iPhone Wi-Fi cases in Ghostty
with age and rage: two fresh approvals, native cancellation without plaintext, and fresh
approval after cancellation for each client. All six new Face ID observations and both
intentional cancellations were immediately recorded as `y`; the user confirmed completion.
The existing iPhone pairing was reused and no iPhone update occurred in this stage. Result
and harness digests are retained in the JSON evidence, and no temporary plaintext directory
remains. Surge and ZeroTier stayed enabled. This closes the installed artifact's two-phone
foreground Wi-Fi roundtrip matrices; GUI permissions, other transport rows and M2 remain
separate open gates.

### GUI caller acceptance deferred by user

On 2026-09-10 the user explicitly deferred GUI testing because there is no current GUI
use case. This includes GUI caller network, camera and hardware-key access attribution.
It is outside the current terminal CLI acceptance scope, not a passing result or a GUI
support claim. No GUI harness was created or run. Shine was inspected read-only: it is a
CLI that invokes age, so running it from a terminal does not itself establish a GUI caller.
The deferral does not weaken M2 rollback requirements or remaining terminal safety gates.

### Follow-up after the approved replay boundary decision

Commit `a51df0f` is the current user-approved scope: stronger Windows/macOS desktop
restore freshness is deferred as a POC proposal, not an implemented enhancement. No
privileged service or protocol revision is required for this acceptance stage. The
remaining transport and lifecycle matrix continues under the preserved native verification,
session binding, durable consumption and fail-closed requirements.

An isolated harness is prepared for the current Cargo-installed binary and updated
Android APK over Developer USB, reusing the existing USB pairing. Its eight age/rage
cases require immediate native observations and also check that reverse rules are empty
after each operation. Read-only preflight found the device connected and no reverse rules.
No identity operation was performed by this preparation; its physical results are pending.

### Installed Mac artifact: updated Android USB matrix passed

The exact installed binary and same-signed Android reception-update APK passed all
eight age/rage Developer USB cases using the retained original USB pairing. Six
approvals each have an immediate fresh-fingerprint confirmation; two native
cancellations have immediate intentional-cancellation confirmation and no plaintext.
Both cancellation recovery operations succeeded with new native verification. The
harness checked empty ADB reverse rules after every case, and no temporary plaintext
directory remains. This adds current-artifact USB roundtrip/cleanup evidence; it does
not replace the distinct multiple-device, authorization or cold-start lifecycle rows.

### Installed artifact: QR success on both phones

Android and iPhone each passed age and rage QR unwraps with the exact installed
Mac artifact. Both Android operations have immediate fresh-fingerprint confirmation,
and both iPhone operations have immediate fresh-Face-ID confirmation. The user
selected the Mac built-in camera for both runs. The Android run used the retained
active USB pairing with explicit QR transport, not the previously revoked QR pairing.
All four plaintext equality checks passed and no harness temporary plaintext
directories remain. This closes current-artifact QR success; camera permission
negatives, external UVC and remaining lifecycle cases stay distinct.

### Wi-Fi background lifecycle: Android passed, iPhone retry pending

On the installed artifact, Android backgrounding while native verification was pending
ended with nonzero exit and no plaintext; the user confirmed the background transition
and prompt closure. Returning to foreground allowed a fresh request to succeed with
new fingerprint verification. Both cases passed and the user confirmed completion.

iPhone's original record reports background interruption without plaintext, followed
by failed recovery (exit 1, native confirmation not reached). The user reported an
input mistake, so the original rows remain evidence but are not counted as a complete
iPhone lifecycle pass. A separate iPhone-only two-case retry is prepared, leaving the
Android result and original failed run intact. No temporary plaintext directories remain.

### iPhone background lifecycle retry passed

The separate iPhone retry passed both cases on the same installed artifact.
Backgrounding before Face ID succeeded ended the request with exit 1 and no plaintext;
the user confirmed the transition and prompt closure. After returning to foreground,
a fresh request decrypted correctly and the user immediately confirmed new Face ID.
No retry plaintext directory remains. Together with the previous Android pass this
closes the two-phone Wi-Fi background/foreground case; the original failed iPhone
recovery remains retained and is not relabeled. Lock-screen and process-termination
scenarios are separate lifecycle cases.

### Installed artifact: both phones' lock-screen lifecycle passed

On Wi-Fi through age, Android and iPhone each terminated a pending verification
request after user-operated screen lock, returning failure without plaintext. The
user immediately confirmed locking before authorization and closure of the old
prompt. After unlock and foreground return, each phone decrypted a fresh request
and the user confirmed new fingerprint/Face ID verification. All four cases passed
on the recorded installed binary; no harness plaintext directories remain. This
row covers screen locking, separately from backgrounding and process termination.

### Android process termination and restart passed

After the user confirmed pending, unapproved native fingerprint verification, the
harness force-stopped only the Android application. The command succeeded and a
subsequent PID check confirmed process absence. The Wi-Fi request failed without
plaintext and the user confirmed prompt closure. Relaunching the same app preserved
the pairing; a new request decrypted correctly with an immediately confirmed fresh
fingerprint. Both cases passed on the installed artifact and no temporary plaintext
directory remains. No app uninstall, data reset or replay restoration occurred.

### iPhone process termination passed; developer relaunch failed

The user confirmed pending, unapproved Face ID before the harness terminated the
uniquely matched test app process with SIGKILL. The termination command succeeded,
process absence was confirmed, and the old Wi-Fi request failed without plaintext.
The user confirmed Face ID prompt closure. This negative case passed.

CoreDevice's subsequent app launch returned nonzero before the recovery request
started. The error does not establish a plugin recovery failure or a recovery pass.
The original result and failed launch report are retained. A separate fresh-ciphertext
recovery check will use user-operated app launch; no repeat termination is required.
No temporary plaintext directory remains.

### iPhone manual relaunch recovery passed

After the developer-tool relaunch failure, the user manually opened the iPhone
app. A separate age request using newly generated disposable ciphertext decrypted
correctly on the same installed artifact, and the user immediately confirmed new
Face ID. The original interrupted harness had already cleaned its plaintext. The
separate recovery harness also left no temporary plaintext directory. This completes
the process-termination/new-verification recovery evidence using manual relaunch;
it does not relabel the failed CoreDevice launch or claim a same-run recovery.

### Camera permission negative tests deferred for current version

The user explicitly deferred the proposed camera permission denial/revocation
acceptance because QR is not the current primary flow. No permission switch was
changed and no TCC reset occurred. These cases are not counted as passed. Existing
built-in QR success and historical cancellation/timeout evidence remain valid at
their recorded artifact scope. This decision does not implicitly waive other QR,
Wi-Fi, USB, durability or cleanup requirements. External UVC availability remains
unconfirmed; that separate scope has not been decided by this instruction.

### Android Wi-Fi disable/reconnect passed, with delayed failure

After immediate user confirmation of pending, unapproved fingerprint verification,
the harness disabled Android Wi-Fi over USB and confirmed the radio was disabled.
The same app process remained alive; the user confirmed foreground operation and
old prompt closure without approval. The age request failed without plaintext.
The harness restored Wi-Fi, and after reconnection a fresh request decrypted with
immediately confirmed new fingerprint verification. Both cases passed; Mac network
settings were unchanged and no temporary plaintext directory remains.

The user observed a noticeable wait after disconnect. The desktop sets a 90-second
socket read timeout and Android a 60-second native-authentication timeout. A lost
network need not deliver immediate EOF/reset to a waiting reader; bounded timeout
behavior is a plausible explanation, not a measured cause. The recorded 104.601
seconds includes the later PID check and the user's answer because the harness
sampled its end timestamp too late. It is retained with this caveat and must not
be quoted as network failure latency. Functional failure/recovery passes remain
valid; immediate disconnect detection and precise latency are not established.
A separate future harness fixes the timing boundary and prints waiting progress,
without changing product deadlines or requiring this successful run to be repeated.

### USB cold app launch passed for both age clients

Before each operation the harness force-stopped the Android test app and confirmed
that its process was absent. The ordinary plugin Developer USB route then opened
the app. The user immediately confirmed automatic launch without manual opening
and fresh fingerprint verification for both age and rage. Both plaintext equality
checks passed; reverse rules were empty after each operation and no temporary
plaintext directory remains. This covers app-process cold start on an already
USB-authorized, unlocked phone, not OS reboot, initial USB authorization or multiple
Android-device selection.
