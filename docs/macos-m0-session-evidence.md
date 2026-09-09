# M0 lock and reboot run — 2026-09-09

Status: local lock/unlock and post-reboot-login verification completed; test references cleaned up.

The user explicitly authorized locking and restarting this Mac and confirmed that
work was saved. Unlock/login is performed by the user, never by the test runner.
Only synthetic desktop-role keys are used. No phone, pairing, replay or real data.

## Durable isolated state and resumption

The completed run's non-sensitive evidence and fixed test binaries are retained under
the git-ignored directory:

`target/macos-m0-session-1b6df429f651`

It retains the fixed `probe`, public Rust `verifier`, `manifest.json` with public
binding and integrity/boot metadata, fsynced `observations.jsonl`, and `cleanup.json`.
The two opaque references and their local binding file have been removed after
verification. Do not commit this generated directory. A fresh test requires a new
run directory; do not recreate keys in this completed run.

After the user restarted and logged in, the following command was executed from
the repository and passed (it cannot be rerun successfully after the cleanup below):

```sh
python3 -B scripts/macos-m0-session.py resume \
  --root "$PWD/target/macos-m0-session-1b6df429f651"
```

The command must run in the logged-in native user context with access to Secure
Enclave and `ioreg`/`sysctl` (the Codex filesystem sandbox alone is insufficient).
It rejects an unchanged boot session, changed binary/reference bytes, changed public
keys, or failed native/Rust crypto. It does **not** create or repair keys. Passing
this command proves post-reboot access after user login, not pre-first-unlock access.

## Measurement design

- `prepare`: create once while unlocked; preserve a boot-session ID, two public-key
  digests, combined binding, fixed binary digests and reference integrity digests.
- `watch`: open held native handles before locking; sample both independent roles
  through these handles and through a new process every five seconds. Record
  `IOConsoleLocked` before and after each sample. A transition during sampling is
  marked unstable rather than labeled a locked/unlocked result.
- `resume`: require a different kernel boot-session ID, the same original state,
  an unlocked session, successful signing/ECDH, and independent Rust verification.

`IOConsoleLocked` is an OS diagnostic observation, not a product authorization API.
Physical user-controlled screen transitions corroborate it. Locking the screen is
not assumed to immediately lock every keybag. The test records actual operation
outcomes, including success while the UI is locked, without classifying them as a
phone-authorization result. Product unwrap still requires fresh phone verification.

The runner never locks, unlocks, reboots, changes authentication settings, installs
a launch agent/daemon, or starts before user login. It retains test state until
results are recorded and explicit local test cleanup can remove the exact run.

## Results

- Baseline: original dual keys created; native operations and Rust public verification
  succeeded while unlocked.
- Lock: system Control–Command–Q invoked; samples corroborated with
  `IOConsoleLocked=true` before and after both fresh-process and held-handle tests.
  At 0.0 and 5.2 seconds relative to the first stable locked sample, both signing
  and ECDH still succeeded through both paths. From the 10.3-second sample onward,
  both roles and both paths returned `native_code_-25308` (interaction not allowed).
  Thus screen lock did not revoke key access immediately; the observed delay is
  not an API timing guarantee and must not become a product authorization window.
- Unlock: user confirmed manual unlocking. The first stable unlocked sample again
  succeeded for both roles through fresh processes and the original held handles,
  with unchanged public-key digests. There were 23 stable locked samples; all
  after the initial two successful samples showed the same native denial.
- Pre-reboot guard: `resume` was executed before reboot and correctly rejected
  with `no_reboot_observed`; a process restart cannot count as a system reboot.
- Post-unlock full verification: original combined binding and the independent Rust
  digest-signature/ECDH verifier passed again.
- Reboot and login: **passed** at 2026-09-09 07:28:14 UTC (15:28:14 +08:00).
  The kernel boot-session ID differed from the saved pre-reboot ID. Both copied
  test binaries and all original reference bytes matched their saved digests;
  the session was unlocked before and after sampling. Signing and ECDH succeeded
  under the original public-key digests and combined binding. The independent
  Rust verifier passed again. No creation or repair path was executed by `resume`.
- Scope: this validates reopening **after user login** on this Mac. It does not
  validate access before first unlock, logged-out/SSH service contexts, replay
  persistence, or any phone authorization path.
- Cleanup: after recording the result, the exact original `signing.ref`,
  `selection.ref` and `binding` files were integrity-checked and removed. A native
  observation then returned `missing` for both roles. Non-sensitive evidence was
  retained. This is local-reference cleanup, not irreversible hardware destruction.

Measured probe SHA-256: `cd43e0441c448c56da4060feea76ebc23b57f9cb8444fa590d045dbebcb9ec91`.
Rust verifier SHA-256: `6dd03cc4a5dfd4213fba36b7aabe460ffbfc2ff20c9cd3581b0a14cf8b1f4741`.
The fixture uses `WhenUnlockedThisDeviceOnly` with `privateKeyUsage`, no user-presence
or biometric flags. Kept handles did not bypass the eventual native denial.
Four deterministic session-guard tests pass; the updated standalone fixture passes
all-target Clippy with `-D warnings`.

See [M0 evidence](macos-m0-evidence.md) and [ADR 0025](adr/0025-macos-secure-enclave-m0.md).
