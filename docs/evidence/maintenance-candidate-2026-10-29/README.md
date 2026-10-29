# Maintenance candidate acceptance — 2026-10-29

**29 scoped owner-observed cases passed; 2 attempts excluded.** This report covers the published
Windows Beta 2 executable with the unpublished Android R2 APK. It does not certify a new release,
a complete device matrix, or use with production secrets.

## Fixed package pair and provenance

- Main `be46c547922cdd3c5d33c41cf69f1e979b5292dd` passed all 11 jobs in
  [CI run 40851959029](https://github.com/biulight/age-plugin-phone/actions/runs/40851959029).
- Windows is the exact published Beta 2 executable, SHA-256
  `62d8f3836598dd1ab287c3b2ac432539870bfb0cbe7bdfd547d08cf3be373e2b`.
  Its fixed signer and private test-root chain were reverified in memory. The root is not publicly trusted;
  no certificate-store change occurred. The four desktop crates are unchanged from the release source.
- Android is the existing unpublished R2 APK, installed SHA-256
  `cd28c3a7a19e1a4a92910c151551cec853169fa5e653815421c6386d825ee37a`.
  The installed APK signature, version and hash were rechecked without installing or clearing data.
- `candidate-source-binding.json` compares the complete 300-file scoped R2 build inventory with
  immutable main, including additions/deletions; all input bytes match. The existing
  [R2 build/signing/install chain](../android-wifi-network-r2-2026-10-24/README.md) remains authoritative.
  Apple project files and generated Tauri schemas remain explicitly outside this Android inventory.

## Accepted scope

`accepted-summary.json` binds every accepted/excluded attempt to its exact report hash and owner
observation in `review-followup.json`. Machine-only awaiting-observation reports are not passes by themselves.
`first-discovery-summary.json` separately binds the idle and pending-request cycles to their first
successful automatic-discovery requests. The checker rejects a prior intervening request, a direct route,
wrong hashes, overlapping idle work and out-of-order network/request times.

- Idle Wi-Fi loss/restoration: first automatic discovery succeeded with fresh verification.
- Pending-verification Wi-Fi loss/restoration: prompt dismissed, original request failed without output,
  then first automatic discovery succeeded without direct connection, listener toggle or app restart.
- Cancelled signed request after app restart: verified old-process disappearance and a different new
  process; identical-frame and fresh-outer-session replays rejected without response or new prompt,
  with 183/182 seconds remaining. A new automatic-discovery request then succeeded with fresh verification.
- `phone` and `tag`, separately: independent recovery before phone operations, valid nonmatch rejection
  without prompt, nonmatch-then-match success, explicit cancellation without output, and fresh recovery.
- Wi-Fi cancellation, authentication timeout, invalid first connection and peer disconnect, each followed
  by successful fresh verification. Successful-request exact replays were rejected within expiry,
  followed by fresh automatic-discovery recovery.
- Paused Wi-Fi with USB connected: explicit Wi-Fi failed without output/prompt; a distinct explicit USB
  request succeeded with fresh verification. No within-request fallback is claimed or permitted.
- Background/foreground recovery has separate evidence on the **same APK and Windows executable** in
  the [R2 archive](../android-wifi-network-r2-2026-10-24/README.md); it was not repeated in this session.

All decrypt assertions checked empty stdout; negative requests checked no plaintext output. Final
checked audit found zero ADB reverse rules. The owner confirmed listening paused and controls normal.
Only this campaign's synthetic inputs, recovery keys and local input indexes were removed. Existing
pairings and replay stores were never manually edited/reset; ordinary request consumption is expected.

## Interpretation and exclusions

- The first idle-recovery attempt lacked owner observation and is excluded; no timeout cause is inferred.
- One recovery attempt followed an accidental Pause and is excluded from unassisted discovery evidence.
- The original published Beta 2 failure remains in its [original archive](../beta2-2026-10-23/README.md).
  R2 passes do not change that result or certify future release bytes.
- Earlier USB reports label `route_mode` incorrectly; their `transport=adb` and exact archived drivers
  establish explicit USB use. Report bytes are unchanged.
- During the additional network-cancel/restart run, the relay reached its bounded read timeout without
  response before terminating the original desktop request. This is not an immediate peer-EOF claim.
  Both replays were rejected with 186/185 seconds remaining; the owner observed no new prompts.
  A fresh automatic-discovery request then succeeded with fresh verification.

## Evidence and reproducibility

| Material | Purpose |
| --- | --- |
| Package preflights and `candidate-source-binding.json` | Identify exact binaries, signatures and the existing R2 build chain |
| `attempts/`, `accepted-summary.json`, `review-followup.json` | Bind machine outcomes to owner observations, including the two exclusions |
| `first-discovery-summary.json` | Bind idle/pending network cycles to their first discovery requests |
| `p2-followup/device/request-binding.json` | Bind the additional preflight, replay/recovery requests, diagnostic and cleanup |
| `sources/` | Unique historical execution sources referenced by retained physical records; these revisions were not all committed as product scripts |
| `manifest.json` | Detect missing, changed or unlisted archive files |
| [Validation summary](../maintenance-candidate-validation-2026-10-29.json) | Final cross-platform commands, versions, times, exits and source hashes |

Run `python -B scripts/check-p1-evidence.py docs/evidence/maintenance-candidate-2026-10-29`.
Keep the published Beta 2 and R2 sibling archives for the build/signing cross-check. The checker requires
first-discovery and device bindings, checks complete recorded request coverage and chronological order,
and rejects contradictory preflights even if the manifest is rebuilt. It checks recorded source equality
and archive linkage; it does not independently reproduce the build or authenticate self-reported hashes.
Unrecorded external traffic and transient states between diagnostic samples are outside its scope.

Regression tests use small synthetic archives generated by `scripts/p1/evidence_fixture.py`, independent
of these physical records. Normal/optimized evidence tests and 90 replay-driver scenarios per host run
through `record-tool-validation.py`; PowerShell fixtures check preparation/mode/ciphertext binding and
checked ADB failures. CI uploads full execution output as artifacts. Repeated local run logs and
intermediate tool-source snapshots are intentionally omitted from Git; the final summary is sufficient
for reviewing which revision was tested. CI/tool passes are not new phone acceptance.

## Final tooling verification

| Host | Runtime | Verified scope | Result |
| --- | --- | --- | --- |
| macOS | Python 3.13.17; PowerShell 7.4.6 | 10 evidence tests in normal and optimized modes; 90 replay-driver scenarios; 12 mode/preparation scenarios; ADB failure fixtures | Passed |
| Windows | Python 3.11.2; PowerShell 7.6.9 | Same scope, executed natively in a directory without physical evidence | Passed |

The scripts and synthetic fixture are identified by hashes in the validation summary. Full output is
local/CI diagnostic material, not a repository requirement. The original Beta 2, first-fix, R2 and this
candidate archive are also checked separately in normal and optimized modes on both hosts.

## Remaining release gates

Choose an immutable maintenance version, build/sign its actual release pair and run exact-artifact smoke
before publication. AP/subnet roaming, device reboot, storage fault/rollback, fresh pairing, second
StrongBox family, wrong/multiple physical phones, complete lifecycle/upgrade, QR response replay,
public signing and external-user readiness remain unverified or separately deferred.
