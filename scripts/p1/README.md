# Owner-operated Beta 2 follow-up probes

These are synthetic-data acceptance tools, not product transport implementations.
Run on the Windows test host with the exact Beta 2 package extracted to
`$env:TEMP/phone-beta2-p1-20261023/package`. Keep `common.ps1` beside the probes and
`windows-minimal-acceptance.ps1` in the parent directory. Require exactly one authorized
USB phone. Do not run concurrent probes or approve a phone prompt automatically.

`step-regression.ps1 -Case prepare -PhonePublicRecipient <public-recipient>` selects
existing public stubs for the owner-supplied phone recipient and creates disposable
synthetic inputs plus an independent recovery key. It refuses to overwrite prepared
inputs. Existing product pairing, keys and replay state are never reset.

For network diagnosis:

1. Keep the phone foreground with Wi-Fi auto-listen enabled. Start
   `step-regression.ps1 -Case wifi-network` and wait for the owner to confirm a fresh
   native prompt is awaiting verification.
2. Run `switch-wifi.ps1`. It verifies successful ADB queries, disabled Wi-Fi and
   disappearance of wlan0 IPv4, then restores Wi-Fi even after a failed check.
   Confirm prompt dismissal without phone interaction. Let the original age process
   exit; a harness timeout is a failure, never an expected negative result.
3. Run `step-regression.ps1 -Case wifi-after-network`. Preserve every failure.
   If discovery fails, compare a **new** request using `-DirectWifi`, then a new
   automatic-discovery request. Each success needs a fresh owner-confirmed prompt.
   A direct-address retry is an explicit separate attempt, not product fallback.

Machine reports remain `automated-checks-passed-awaiting-observation` until correlated
with an explicit owner observation by case and `started_utc`. Record every input source
hash. Raw stderr is classified in memory using fixed public diagnostics; do not save
raw stderr, protocol bytes, private paths, plaintext or keys as evidence.

`replay-probe.py` temporarily relays the real plugin's signed request and response in
memory. After the owner verifies the first request, it replays identical signed bytes
with identical and fresh outer frame IDs before expiry. Follow with a fresh normal
request and explicit no-new-prompt observations. Never infer replay persistence across
restart from this test. `hostile-first.ps1` sends only an invalid fixed header;
`disconnect-current.ps1` terminates only the exact child process of the marked test.

For the separate app-restart boundary, use `replay-probe.py --network-cancel --auto-cycle
--restart-after-cancel` only after the owner agrees to observe without authenticating.
The script requires the original pending connection to remain open before cycling Wi-Fi,
checks the cancelled request produced no output, then force-stops only
`io.github.biulight.age_plugin_phone` and opens its main activity without clearing data.
It verifies the old process disappeared and a different process started before either replay.
Both replays must still be within expiry, rejected without response and without a new native
prompt. Follow with a new verified request. Process-query, stop, launch or expiry failure is
not a pass. This tests application restart, not device reboot or replay-store rollback.

After all cases, remove only the disposable `synthetic` directory and `local-inputs.json`
under the test root, check reverse rules successfully, and ask the owner to pause
auto-listen. Retain sanitized reports and hash-bound sources. See
`docs/evidence/beta2-2026-10-23` for the archived run and its limitations.

Run regressions with `pwsh -NoProfile -File scripts/test-p1-acceptance.ps1` and
`python scripts/test-p1-evidence.py`. These require no phone and make no network changes.

### Review hardening (2026-10-29)

The first-discovery checker rejects any other recorded phone request overlapping the network-cycle
start through the claimed first recovery, including requests begun during the cycle and completed
after restoration. Only the exact original pending request is exempt. This proves ordering within the
archived campaign, not the absence of unrecorded external traffic.

The maintenance candidate checker cross-checks Android and Windows preflight status, artifact hashes,
versions and signer chains against the published Beta 2 and R2 sibling archives. It verifies the
recorded build-source hash, inventory count and equality declaration; it does not rebuild the APK or
independently rerun the historical Git inventory comparison. Keep both sibling archives when checking
the candidate. Regression tests generate their own synthetic archives and do not read physical evidence.

`step-regression.ps1 prepare` now requires the exported recipient prefix to match the requested mode
and binds subsequent operations to the prepared ciphertext SHA-256. Old temporary indexes lacking a
mode or ciphertext hash must be regenerated; do not repair them by hand. The mode fixture executes
actual preparation control flow for both modes, wrong-mode export rejection, and ciphertext-replacement
rejection. Its mocked product/age processes do not constitute cryptographic or physical acceptance.

The replay probe records request-forward and early-peer timestamps and distinguishes an early byte,
EOF and reset. All are failures before the automatic network switch, never successful cancellation
or replay evidence. No protocol bytes are retained.

Candidate campaigns require `first-discovery-summary.json`; its absence is a failure rather than a
legacy skip. The additional physical run is bound by `p2-followup/device/request-binding.json` to
its preflight, diagnostic wrapper, exact accepted replay/recovery requests and cleanup. Checks require
matching candidate APK/EXE hashes, successful preflight/cleanup, archived diagnostic sources, ordered
UTC times and complete accepted-request coverage of that recorded interval. This links existing
observations; it does not claim a new physical run or independently authenticate a self-reported hash.

Tool-validation records bind the test/driver source hashes, including the synthetic evidence generator.
Full per-run output belongs in CI artifacts or local diagnostic files. Commit only a compact final
validation summary alongside physical evidence; do not append intermediate run logs to the archive.
