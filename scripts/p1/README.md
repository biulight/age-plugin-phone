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

After all cases, remove only the disposable `synthetic` directory and `local-inputs.json`
under the test root, check reverse rules successfully, and ask the owner to pause
auto-listen. Retain sanitized reports and hash-bound sources. See
`docs/evidence/beta2-2026-10-23` for the archived run and its limitations.

Run regressions with `pwsh -NoProfile -File scripts/test-p1-acceptance.ps1` and
`python scripts/test-p1-evidence.py`. These require no phone and make no network changes.
