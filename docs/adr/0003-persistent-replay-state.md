# ADR 0003: Persistent replay-consumption state

- Status: experimental, accepted for implementation testing
- Date: 2026-08-24
- Scope: durable consumption of accepted unwrap requests and returned unwrap responses

## Context

ADR 0002 initially used an in-memory replay guard. That is sufficient to prove message binding but
not sufficient across an app restart or process crash. A captured request must not produce a second
authorization prompt after it has once passed public validation, including when the first operation
was later cancelled. A returned response must not release its file key twice.

Replay state is security state, not an authorization cache. It never permits an operation and never
contains a protocol message, recipient stanza, file key, private key, label, or plaintext.

## Decision

### Scope and contents

Each state file is permanently bound to exactly one paired `desktop_id`, `identity_id`, and endpoint
role:

- the phone role stores `(request_id, request_nonce, request_expiry)`;
- the desktop role stores `(response_digest, request_expiry)`.

Mixing roles or opening a file for a different pairing fails closed. The state uses a versioned,
fixed-length canonical CBOR encoding. Unknown versions, roles, entry kinds, fields, indefinite
arrays, duplicate IDs or nonces, non-canonical ordering, trailing bytes, and oversized files are
rejected. It stores identifiers and hashes only, never raw signed envelopes.

### Consumption order

The phone verifies canonical structure, pairing bindings, expiry, recipient structure, and the
desktop signature before attempting a replay-state write. It then durably consumes the request ID
and nonce before returning a verified request or displaying authorization UI.

The desktop verifies all response bindings and the phone signature and authenticates the response
ciphertext first. It durably consumes the response digest before returning the decrypted file key
to its caller. A storage failure discards and zeroizes the transient plaintext.

This ordering has the safe crash asymmetry:

- a crash before the durable commit returns no authorization or file key, so retry is allowed;
- a crash after the durable commit may deny one legitimate retry, but cannot authorize or release a
  secret twice.

### Durability and concurrency

The file backend holds a non-blocking exclusive lock on a separate lock file for its complete
lifetime. Concurrent owners fail closed. Every update is written to a newly created same-directory
temporary file, flushed with `fsync`, atomically renamed over the state file, then followed by a
directory `fsync`. The in-memory state changes only after the durable commit succeeds. Any storage
error poisons that guard instance so it cannot continue from uncertain state.

Creation and opening are separate operations. Opening a missing file never silently creates empty
state. State creation must be committed with initial pairing setup; deletion or corruption requires
explicit pairing recovery rather than an automatic replay reset.

### Clock and capacity

The state persists a wall-clock high-water mark. A consumption attempt with an earlier timestamp
fails closed, preventing clock rollback from making a pruned request valid again. Entries are kept
through their request expiry and pruned only when `expiry < now`.

Capacity is configured at creation/open time and is hard bounded. Expired entries are pruned before
the limit is checked. If no slot is available, the request or response fails closed; no live entry is
evicted to make room.

### Platform boundary

The initial file backend targets Unix-family app-private storage, including Android and the first
desktop prototype. Its advisory lock and filesystem durability assumptions must be re-evaluated for
each platform filesystem. Mobile integration must place the file in non-backed-up app-private
storage. Restoring or replacing replay state independently of pairing state is unsupported. Android
implements that lifecycle by embedding request-replay entries in the pairing record's atomic
storage unit; see [ADR 0004](0004-android-pairing-state.md).

An in-memory guard remains available only for deterministic tests. It does not satisfy this ADR.

## Consequences

- Restart, concurrent-open, clock-rollback, corruption, capacity, and write-failure behavior can be
  tested without QR or hardware authorization.
- Storage failure can cause denial of service but cannot create a fallback or cached authorization.
- Replay-state rollback by a compromised OS or app-private-storage implementation remains outside
  the threat model. Same-user modification of an unprotected desktop state file is not treated as a
  trust boundary.
- The native Android storage and request-verification path adopt this state machine. The QR flow
  must use that lifecycle before the bidirectional prototype may handle real secrets.
