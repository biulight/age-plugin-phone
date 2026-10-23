# Wi-Fi network recovery review follow-up (2026-10-24)

Status: automated tests and scoped Windows/Android physical regression passed.
The owner confirmed auto-listen paused and page controls operational at completion.

This unpublished candidate adds bounded observation-registration retry and tests the
production observation queue and unwrap ownership transitions. The published Beta 2
and first local fix archives remain unchanged. No commit or push was performed.

`build/build-source.json` records the baseline commit/tree, 300 source hashes, and
all changed/new build-source snapshots in `build/delta/`. Reconstruct sources from
the baseline plus these snapshots and listed deletions. The original unrelated Apple
project change and generated Tauri schemas are excluded from Android inputs.
`build/build-result.json` verifies the source inventory remained unchanged during
the ARM64 build and binds the unsigned APK. `signing.json` and `installation.json`
bind that APK to the original signer and the pulled-back installed APK.
Toolchain versions, dependency-lock hashes and the build invocation are recorded.
This is source traceability, not a claim of independently reproducible APK bytes.

The 87 JVM tests include queued callbacks across foreground generations, registration
failure/retry and unregister failure, stale worker publication, late authorization /
timeout / disconnect callbacks, response handoff cancellation, and exact request
rejection after network cancellation and durable store reopening. The queue, ownership
and store are production components; Android's OS callback scheduling and hardware
biometric operation still require physical evidence.

Physical observations will bind to each attempt's case and start timestamp.
Only synthetic data is used. Signed requests remain in relay memory, never in the archive.

## Physical results

Five owner-observed cases passed: baseline automatic discovery and unwrap; network
cancellation plus two exact replays; a fresh automatically discovered request after
replay; foreground loss cancellation; and a fresh request after foreground restoration.
The network switch was performed from Windows 10 seconds after forwarding the request,
with checked Wi-Fi disable, IPv4 removal and restoration. The original request failed
without output. Both the identical frame and a fresh outer session carrying the exact
same signed request were closed without response, with 186 and 185 seconds remaining
before expiry. The owner saw one initial prompt, its dismissal on network switching,
and no replay prompts, without interacting with the phone.

The relay retains signed bytes only in memory and uses an explicit endpoint. Its fresh
recovery test uses authenticated discovery. This campaign does not claim that recovery
occurred before any direct connection after network restoration; the previous candidate
archive separately records that case. Registration exceptions and forced callback queue
interleavings are covered by JVM tests, not injected into the Android OS.

One earlier attempt ended before a network switch could be performed. The script failed
closed and performed no replay. It is explicitly excluded, with its original driver
snapshot retained; it is not treated as a product network-recovery failure or a pass.

`accepted-summary.json` binds the accepted and excluded cases to exact report hashes.
`review-followup.json` preserves owner observations by case and UTC start timestamp.
The final machine audit confirms restored Wi-Fi, zero reverse rules and removal of
synthetic inputs. Real identity, pairing and consumed-request state were not reset.

## Acceptance-tool P2 follow-up

The original physical reports and driver snapshots above remain unchanged. The tools
in `p2-review/scripts/` are a later validation-only revision, not the drivers used for
those phone requests. All replay acceptance assertions are now explicit checks that
remain active under Python optimization. A subprocess fixture executes the actual
driver with synthetic socket/process boundaries in normal, `-O`, and `PYTHONOPTIMIZE=1`
modes. Each mode checks a valid baseline and six rejection cases; 21 combinations
passed on both macOS and Windows.

The archive checker now cross-checks accepted/excluded summary entries against report
hashes, identities, machine outcomes and complete, unique owner observations. Eleven
negative summary mutations are rejected even after the outer manifest is regenerated.
Current historical acceptance entries also pass the stronger cross-check. No new
physical test is claimed by this tooling-only follow-up. See `p2-review/validation.json`.

## Network-cancellation timing and complete run records

The later [timing follow-up](p2-time-review/README.md) constrains each network cycle to
the accepted request's UTC interval and exercises the actual network-cancel branches
in normal and optimized Python. Both hosts passed 66 driver combinations and evidence
checks in normal and optimized modes. Six complete suite records include commands,
Python versions, UTC times, exit codes, output and source hashes, plus per-child driver
records. Earlier validation summaries remain historical; the detailed runs are new
executions of the separately snapshotted timing revision.
