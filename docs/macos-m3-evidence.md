# macOS M3 setup integration and remaining lifecycle gates

Date: 2026-09-09. Scope: PR 4 (managed setup and age entry points) of the
[macOS plan](macos-support-plan.md), after M1/M2 and independent M4 preparation.
This is implementation evidence, not complete macOS or real-phone acceptance.

## Implemented

- macOS shares the existing setup orchestration and versioned public JSON output.
  Platform capability and selected transport are checked before creating setup
  state. The new read-only CryptoKit availability hint never provisions a key;
  actual dual-key creation/reopening remains the final hardware operation gate.
- Setup generates managed paths under the protected configuration root, holds
  the native lifecycle lock, persists its ownership journal before key creation,
  and journals the verified response and full-fingerprint confirmation separately.
  The normal protocol transcript verification and phone confirmation are unchanged.
- `setup --resume` accepts only a currently persisted, identical `Confirmed`
  journal. Opening hardware metadata revalidates both public roles against the
  candidate. Replay, locator and public stub commits resume idempotently; existing
  replay consumption is retained, and pending/corrupt replay remains unavailable.
- Managed public stubs use macOS descriptor-relative bounded create/read/full-sync
  operations with private mode. JSON success remains schema version 1 containing
  only `schema_version`, `identity_path` and `recipient`; interactions use stderr.
  `--json` remains incompatible with `--cleanup`.
- macOS failed setup retains its ownership journal and partial files and requests
  explicit `setup --cleanup`. Cleanup revalidates the exact durable journal and
  takes the replay lock before removing its owned files. It removes reference
  metadata, replay and pending/lock files, locator and managed stub, then the journal.
  A failure leaves the journal so teardown can continue after interruption.
  Local reference deletion is not phone revocation or irreversible key destruction.
- New replacement temporary names encode their exact target child filename.
  Journaled teardown removes only that target's temporaries. Other pairing files,
  temporary files for other targets, links and legacy unscoped `.state-*` files
  are never treated as owned merely because they share the directory.
- macOS explicit pair requires direct private state children. Explicit unwrap now
  resolves the transcript-bound locator, checks the supplied state paths, and
  observes pending setup/cleanup before discovery or starting a signed session.
  Standard `identity-v1` still opens the same checked locator; public encryption
  remains independent of Secure Enclave availability.

## Verification

On MacBookPro18,3 / arm64 / macOS 26.6.2 (25G83):

| Check | Result |
| --- | --- |
| Format, all-target locked Clippy with warnings denied | Passed |
| Locked workspace tests | Passed; hardware tests explicitly ignored in the ordinary suite |
| Each confirmed-commit write boundary | Passed: journal retained, locator blocked, resume completes |
| Unconfirmed stage, changed candidate keys, missing ownership | Rejected before commit |
| Uncertain replay and existing consumption | Preserved; no empty-store recovery |
| Lifecycle/replay concurrent owners | Rejected |
| Interrupted owned cleanup and unrelated files | Exact teardown resumes; unrelated state preserved |
| Temporary ownership, legacy names and hostile links | Exact target only; legacy retained, links rejected |
| Native Secure Enclave managed-commit test | Passed separately; independent role reopening and candidate binding |
| Existing protocol negative tests and vectors | Passed |

The native test was invoked explicitly:

```console
cargo test -p age-plugin-phone --test macos_setup native_confirmed_setup_reopens_and_commits_hardware_roles --locked -- --ignored
```

It creates only an isolated temporary root and synthetic pairing metadata, then
removes that fixture. It does not pair a real phone, compare a product fingerprint,
or simulate successful native phone verification. Ordinary setup fixtures use
test-only software operations without accessing the user's hardware keys.
Commands use `RUSTC_WRAPPER=`; full socket/process tests and native security-service
access ran outside the sandbox. The existing `block 0.1.6` notice remains.

## Remaining gates

- PR 5 must integrate normal and orphaned pairing cleanup, including unavailable
  keys and replay, interrupted teardown at every transition, and recovery guidance.
- Legacy unscoped M2 temporaries cannot be safely attributed to a pairing. They
  remain retained and are not reported as securely destroyed. No software state
  is imported or silently erased.
- The M2 same-user snapshot rollback counterexample remains unresolved; scoped
  temporary names and a setup ownership journal do not create a monotonic anchor.
- Exact installed CLI + age/rage, phone fingerprint comparison, per-unwrap native
  verification, caller permissions, revocation and independent recovery still need
  the M4–M6 real-device acceptance. Windows runtime regression is not established
  by compiling/testing the macOS target.
