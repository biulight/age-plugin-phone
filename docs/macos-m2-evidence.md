# macOS P3 / M2 storage implementation and remaining gates

Date: 2026-09-09. Base: P2 commit `0504533`, followed by this working-tree M2 change.
Status: implementation and local automated checks completed; **M2 acceptance is
not complete**. No expanded macOS support or production-secrets claim is made.

## Implemented

- `platform-storage::macos::Directory` traverses absolute paths one component at
  a time using directory descriptors and `O_NOFOLLOW`, rejects parent traversal,
  and opens direct children with `O_CLOEXEC | O_NONBLOCK`. File operations never
  follow a final symlink. Root-owned sticky system ancestors are allowed; other
  writable-by-group/other ancestors are rejected. Ancestors must be root/current
  UID owned; only deny ACL entries are accepted on ancestors. The protected root
  and files require current UID, private modes and no extended ACL. Regular files
  require a single link; wrong types and oversized reads/writes fail closed.
- Held directory and lock handles are compared by device/inode with the current
  namespace. Replay validates its lock on commit, so unlink/replacement of its
  lock cannot leave an old owner silently committing under a new lock owner.
  These checks do not claim isolation from arbitrary concurrent same-user mutation
  of file contents, or from the trusted kernel/administrator.
- Create-only writes retain partial files on error. Replacement writes a bounded
  same-directory temporary, syncs it, verifies the original/temporary handles,
  renames relative to the held directory, and syncs the directory. Removal uses
  `unlinkat` and directory sync. Uncertain temporary files are retained rather than
  used to reconstruct state. There is no weaker sync fallback.
- Files and directories use `fsync` plus `F_FULLFSYNC`. The latter requests a device
  buffer flush; successful return is not a physical power-loss experiment. See
  [Apple's fsync documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html)
  and [current guidance on durable disk writes](https://developer.apple.com/documentation/xcode/reducing-disk-writes).
- Core owns replay scope, capacity, encoding and `.lock`/`.pending` names. A marker
  is durably written before replacing consumed state. Any existing marker blocks
  open/create, including malformed/empty markers. Only the successful commit path
  removes it; errors poison the live guard. Missing state is never recreated by
  commit. After replacement, an error leaves either unavailable state or the
  already-consumed token, never an accepted duplicate.
- Desktop metadata now uses the new reader and create-only reservation/replacement
  instead of raw filesystem writes. Locators require desktop and replay files to
  be distinct direct children of the protected configuration root. Test fixtures
  now place multiple pairings in that layout without weakening runtime checks.
- macOS cleanup/setup journals use the new read/create/replace/remove primitives;
  locator opening observes pending or corrupt journals. Full lifecycle orchestration
  remains P4/P5. Until that journaled cleanup exists, macOS pairing-failure rollback
  retains partial files and reports incomplete cleanup instead of deleting them.
- Preparing a root sets descriptor-based Time Machine exclusion metadata. The
  current host's `tmutil isexcluded` confirms exclusion. This excludes future
  ordinary backup capture; it neither erases old backups nor enforces freshness of
  restored state. Do not use Migration Assistant or Time Machine to migrate pairing
  keys/replay. Recover via an independent encryption recipient, then pair anew.

The default layout remains `~/Library/Application Support/age-plugin-phone`.
No existing untrusted directory is followed and then chmodded. Existing insecure
roots are rejected. Ancestors must already exist; only the final private root is
created. Explicit test/config paths must have no symlink components; tests resolve
the system temporary-directory alias before creating their private fixture roots.

## Checks on the existing local macOS baseline

The host is the M0/M1 baseline: MacBookPro18,3, arm64, macOS 26.6.2 / 25G83.

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo test --workspace --locked` | Passed; native hardware tests remain separately invoked |
| `cargo test -p age-plugin-phone native_metadata_lifecycle --locked -- --ignored` | Passed with the new storage backend, including child-process reopen and concurrent create-only |
| Descriptor/file checks | Passed: soft/hard links, permissions, directory replacement, bounded reads, create-only, exclusive locking, removal |
| Native ACL and backup checks | Passed: ACL widening rejected; `tmutil` reports the fixture root excluded |
| Storage fault injection | Passed: synthetic write, sync and rename failures preserve old state and retain temporary artifacts |
| Replay fault boundaries | Passed: failure after pending marker, after replacement, and after marker removal cannot accept a duplicate; uncertain state blocks restart; other pairing state remains usable |
| Independent process tests | Passed: concurrent lock rejected, consumed response still rejected after child-process reopen |
| Actual SIGKILL | Passed: committed consumption survives; durable pending marker remains unavailable and unchanged |
| Actual bounded APFS ENOSPC | Passed on a 128 MiB mounted image after data and metadata exhaustion; storage errors poison the guard; freeing space preserves replay rejection and the other pairing |
| Old-state rollback counterexample | **Failed protection observed**: restoring earlier synthetic replay bytes permits consuming the same digest again |
| Actual reboot | Passed after user reboot/login: changed boot ID, unchanged original binary/state hashes, previously consumed digest rejected |
| Journal/layout checks | Passed: external state rejected; matching cleanup/setup and corrupt setup journals block locator opening; automatic rollback preserves uncertain files |
| Existing protocol negatives/vectors | Passed, including cancellation, replay, wrong device, timeout, malformed messages, clock rollback, capacity and upgrade fixtures |
| `git diff --check` and local documentation links | Passed |

Commands used `RUSTC_WRAPPER=` because the configured sccache wrapper cannot run
inside this sandbox. Full tests ran outside the sandbox for existing loopback and
process-group tests; the native metadata test also requires the macOS security
service. No real phone pairing, native phone approval, hardware destruction or
user-state cleanup was performed. Tests use isolated temporary state. The pre-existing
`block 0.1.6` future-Rust compatibility notice remains; current Clippy passes.

## Gates still open — do not count these as passed

1. **Same-user state rewriting / same-Mac snapshot rollback.** There is no trusted
   monotonic counter outside the restorable filesystem. A valid old state and old
   or removed marker cannot be distinguished from history by this backend alone.
   Phone verification and ephemeral response binding remain unchanged, but they
   are not a proof that the persistent replay store itself cannot roll back.
   Restoring the earlier file was actually tested on isolated synthetic state and
   permitted the same digest to be consumed again. This is a counterexample for the
   replay store; it is not an end-to-end bypass of phone verification or ephemeral
   response binding. The user has not approved weakening the requirement; it remains open.
2. **Sudden power-loss durability.** Actual ENOSPC, SIGKILL and real user-initiated
   reboot/login tests now pass on this host. The reboot check used the original M2
   binary and consumed state, not M0 key-only evidence. An orderly reboot does not
   certify sudden power loss; that separate physical-failure row remains untested.
3. **Hardware/platform matrix and focused review.** Wrong-Mac copying, other OS or
   filesystems, Intel/T2, and Windows native runtime regression remain unverified
   here. A focused review of the new storage FFI/race/failure boundary is still
   required before formal macOS support. This change does not alter Windows or
   other Unix native storage implementations.
4. **Lifecycle recovery.** P4/P5 must implement exact journaled cleanup of keys,
   locators, replay state, lock/pending files and retained temporaries. Do not
   manually delete a pending marker to retry, restore an earlier replay snapshot,
   or treat a missing file as permission to create an empty replay scope.

## Native acceptance follow-up and reboot handoff

The reproducible harness is `scripts/macos-m2-acceptance.py`, using the explicitly
invoked `macos-replay-acceptance` core example. It handles fixed synthetic scope and
digest values only; it never processes real phone messages, file keys or plaintext.
See [machine-readable outcomes](macos-m2-acceptance-results.json) for source and
binary digests. The fixed binary used for the final full-volume, SIGKILL/rollback,
and successfully resumed reboot fixture has SHA-256
`4f6e6fda3e883fcb3e062f9c20452f7793a705151638976ea895710b300acb0e`.
A later workspace test build emitted a different example binary; the acceptance
runs intentionally use the retained fixed copy, not the mutable build output.

The full-volume test creates its own 128 MiB APFS image, confirms a distinct mounted
device and a <=256 MiB filesystem, limits data writes to 192 MiB and metadata fill
to 16,384 files, then detaches its exact mount in a `finally` block. It does not fill
the host filesystem. Final data filler allocation was 129,249,280 bytes before
ENOSPC; empty-file creation subsequently also hit ENOSPC. The replay attempt had
to return the specific storage-state error, including on retry, rather than merely
an error due to an already-consumed token. After removing only the fixture filler,
the baseline digest and the unrelated pairing still rejected duplicate consumption.
The final test image was detached successfully.

An earlier attempt exhausted large-file allocation while small metadata commits
still succeeded. That was not counted as failed product durability or as a passed
full-volume negative test; it motivated separately exhausting metadata allocation.
Initial harness command/sandbox failures likewise were not counted as passes.

The rollback experiment restores previously saved bytes of the synthetic replay
file, not an actual Time Machine backup or whole APFS snapshot. It is sufficient
to demonstrate that the store cannot authenticate freshness. The SIGKILL tests
terminate an actual holder process after durable commit or durable pending-marker
creation, and check original state from another process. They do not substitute
for power interruption or reboot.

Five runner guardrail tests pass: oversized volumes are rejected before writing;
same-boot resume is rejected; changed binary/state blocks resume; replay must be
rejected after reboot; checks remain active under optimized Python. Rust fmt,
all-target Clippy, and the complete locked workspace suite also pass with the
acceptance example included.

The original reboot fixture is retained at:

```text
target/macos-m2-reboot-20260909-v2
```

It holds a fixed executable, already-consumed replay state and a manifest with the
original boot ID and hashes. It has no real pairing or hardware key. After the user
reported reboot/login, the following command completed successfully against the
original fixture, without rebuilding or reseeding it:

```console
python3 scripts/macos-m2-acceptance.py resume-reboot --root target/macos-m2-reboot-20260909-v2
```

Resume requires a changed boot ID, unchanged binary/state hashes, and rejection of
the previously consumed synthetic digest. It cannot create state and does not
accept mere process restart as a reboot. The harness never reboots the machine.
Sudden power loss and focused external security review remain separate open rows.

The post-reboot run returned `reboot=passed`, `binary_unchanged=true`,
`state_unchanged=true`, and `consumed_response=replay_rejected`. The harness first
verified a changed boot ID. The recorded source-file hashes also still match the
current implementation. The initial sandboxed attempt could not read the boot ID;
rerunning the same verification outside the sandbox succeeded. No state was
recreated or cleared. The timestamp and hashes are retained in the machine-readable
outcomes; this closes only the current-host M2 orderly reboot row.
