# Desktop replay rollback POC — deferred cross-platform validation

Date: 2026-09-10. Status: **POC proposal, not implemented or validated as an enhancement**.
The user approved a common Windows/macOS guarantee boundary and deferred stronger
store freshness to a later version. This decision does not claim rollback resistance,
complete M2 or macOS acceptance, or authorize installing a privileged service.

## Current common boundary

Both desktop platforms persist response consumption across supported ordinary process
failures and restarts. They reject missing, corrupt, mismatched, full or unavailable
state; an uncertain write must not become empty state. Existing platform-specific
crash guarantees and outstanding durability tests remain distinct.

Neither desktop backend currently promises to detect replacement with an older valid
same-machine replay file or restoration of an earlier valid filesystem snapshot.
This is a narrow store-freshness limitation, not exclusion of all same-user malware.
The existing attacker may still invoke the plugin and modify user files. Response
verification must continue to reject old messages in fresh sessions, and every new
phone identity operation must require fresh native verification. Phone request replay
consumption before prompting, including cancellation/failure, remains required.
Do not restore a replay snapshot as an operational recovery method.

The stronger desktop store-freshness requirement moves out of the current macOS-only
release gate into this cross-platform POC. The observed counterexample stays failed;
it is neither fixed nor relabeled passed. Other physical and security gates remain.

## Why investigate, and when would it add value?

A replay ledger is a used-message list. Restoring its pre-consumption bytes can make
it forget an entry. Its persistence is useful for normal retries, restarts and crash
handling; resisting malicious restoration is a separate, stronger property.

The file-key response also binds the paired desktop, exact request digest, nonce and
one-time session key. Forgetting a ledger entry does not make an old response match a
new session. The Mac experiment demonstrates repeated store-level consumption, not
an end-to-end bypass of phone verification. An existing synthetic test rejects an old
response in a fresh session after restoring the ledger. It is not a native-phone
rollback test or proof for every attack combination.

A stronger anchor earns its cost if a concrete supported attack can turn rollback
into unauthorized key release, a new prompt from a consumed request, or another
explicitly required security failure; alternatively a future product may explicitly
require restore-resistant audit/consumption history. Do not introduce administrator
services or extra QR exchanges solely to turn a store-level counterexample green
without identifying the additional security property and its adversary.

## Evidence and platform comparison

| Aspect | Windows | macOS |
| --- | --- | --- |
| Replay open/commit | Reads canonical file, checks scope, commits via atomic replacement | Reads canonical file, checks scope, commits with durable pending marker |
| Filesystem controls | Current-user full-control protected DACL, exclusive lock, reparse/hard-link checks, flush/write-through | Owner/mode/ACL/link checks, descriptor-relative operations, lock validation, full sync |
| Desktop key custody | TPM CNG signing and selection keys | Secure Enclave signing and selection keys |
| Independent freshness authority in current code | None identified; no TPM NV counter used by replay backend | None identified; no external monotonic anchor |
| Old valid state restoration | Expected to be accepted based on code inspection; native reproduction pending | Synthetic file-byte restore permitted a digest to be consumed again |

Windows user-only ACLs separate users; they do not deny writes by every process
running as the owner. Locking and atomic writes do not authenticate historical
freshness. TPM key non-exportability prevents copying private key operations to
another machine, not restoring this machine's replay file. The same distinction
applies to Secure Enclave references. This is a project implementation assessment,
not a claim that either operating system has no possible anti-rollback facility.

Authoritative implementation/evidence:

- [Windows replay backend](../crates/core/src/protocol/replay.rs), `windows_file`.
- [Windows storage](../crates/platform-storage/src/windows.rs), including current-user DACL.
- [Windows key custody](adr/0013-windows-cng-key-boundaries.md) and [storage ADR](adr/0015-windows-private-storage.md).
- [Mac replay backend](../crates/core/src/protocol/replay_macos.rs) and [M2 evidence](macos-m2-evidence.md).
- [Fresh-session regression](../crates/desktop/src/unwrap.rs),
  `restored_response_store_does_not_bind_an_old_response_to_a_fresh_session`.
- [Earlier Mac feasibility review](macos-replay-decision.md), retained as history.

## Candidate approaches, not selected implementations

**Local signatures, encryption, backup exclusion or a second user file.** These do
not independently establish freshness: the old valid data and any restorable
checkpoint can be replayed together. A user-accessible Keychain counter needs a
separate proof against update/delete/recreate and restore; its location alone is
insufficient. The inspected CryptoKit interface exposes no arbitrary application
monotonic counter. Hardware anti-replay descriptions must not be treated as such an API.

**Privileged local authority.** A service could own the ledger outside ordinary-user
write access and expose atomic check-and-consume, not arbitrary file writes or counter
replacement. It must authenticate the OS caller, scope operations to user/pairing,
commit before replying, preserve consumption after reply loss, and prevent reset by
uninstall/reinstall or delete/recreate. It would require a reviewed administrator
installation and maintenance flow. It can address user-file restoration while the
service ledger stays intact; root ownership alone does not resist restoring the
service ledger or whole disk. Administrator/kernel compromise remains outside the
existing threat model. Recovery from ordinary system restore still needs a policy.

**Phone-held authority.** A new authenticated exchange could anchor desktop freshness
in phone-held state. Replies need a fresh challenge and exact scope/transition binding;
a cached signed checkpoint is insufficient. Durable consumption, concurrency, lost
replies, phone restore/replacement and fail-closed recovery all need a design. This
would require protocol version/compatibility changes and both phone implementations.
QR would need an explicit offline flow; no silent network dependency or cached
biometric approval is permitted. Existing v2 binding alone does not implement this.

## Later-version experiment and exit criteria

Use isolated synthetic fixtures only. Never restore production pairing/replay files,
retain raw messages in logs, or automate native biometric confirmation.

1. Reproduce store-byte rollback on native Windows with valid owner ACLs and on Mac.
   Keep the original evidence distinct from ordinary clock-rollback/restart tests.
2. On both platforms, restore synthetic desktop state and exercise old responses
   against new sessions, repeated responses in the original session, wrong device,
   wrong request/nonce, expiry and malformed data. Require no unauthorized file key.
3. Verify native phone request replay after cancellation, timeout and restart does not
   prompt again for the consumed request. Verify each genuinely new successful
   identity operation requires fresh native authentication. This is not a phone-state
   restore experiment; do not broaden the desktop exception to phone private storage.
4. If any end-to-end authorization/session-binding failure appears, treat it as a
   current security defect, not an exception allowed by this deferral.
5. Select an authority only after documenting the threat it improves and proving
   crash/reply-loss/concurrency behavior, reset prevention, scope isolation, and
   unavailable/corrupt/full-state rejection. Test authority rollback separately from
   user-file rollback; do not claim universal snapshot resistance from the latter.
6. Review installation, upgrade/downgrade, removal, recovery and offline QR costs.
   Publish exact platform/artifact evidence and remaining limitations before making
   a stronger guarantee. Assign the implementation to a future version only after
   that review; no version or implementation is committed by this proposal.

No runtime, protocol, signing, replay reset or authorization behavior changes with
this document. Existing runtime status output may still call Mac snapshot rollback
unresolved; that accurately describes the implementation limitation, not a new
requirement to solve it before the current scoped CLI acceptance can proceed.
