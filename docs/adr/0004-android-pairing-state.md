# ADR 0004: Android pairing and replay-state lifecycle

- Status: experimental, accepted for implementation testing
- Date: 2026-08-24
- Scope: phone-side persistence of paired desktop public state and request replay consumption

## Context

ADR 0003 defines durable replay-consumption semantics. On Android, a replay file cannot have an
independent lifecycle from its pairing record: creating one without the other, silently rebuilding
a missing replay file, or restoring either from backup would reopen requests that were already
consumed.

The production QR flow does not exist yet. This ADR defines the storage boundary it must use before
any real pairing or unwrap request is enabled.

## Decision

### Storage location and unit

Each paired desktop is represented by one canonical CBOR state file below a dedicated directory in
Android `Context.noBackupFilesDir`. The filename is derived only from the paired desktop and phone
identity identifiers. The file is the atomic unit for both:

- the public pairing record: identifiers, untrusted desktop label, canonical recipient, desktop and
  phone signing public keys, offer digest, transcript fingerprint, and creation time;
- the phone request-replay state: clock high-water mark, fixed capacity, and bounded
  `(request_id, nonce, expiry)` entries.

It never stores a private key, file key, recipient stanza, signed request, protocol payload, QR
content, or authorization result. Android Keystore aliases are derived within the native key layer
and are not caller-provided state fields.

### Creation and opening

Creation is explicit and allowed only after both pairing signatures and the user comparison have
succeeded. The initial empty replay scope and the pairing record are encoded and committed in one
atomic write. Creation never overwrites an existing scope.

Android enforces this with a one-shot native pairing-confirmation session. It strictly verifies the
canonical signed offer and response, derives the stored record and full transcript fingerprint, and
returns only the untrusted desktop label and fingerprint as presentation data. The native transport
controller supplies the fingerprint shown in its explicit user-confirmation action. A mismatch,
non-canonical fingerprint, cancellation, duplicate action, lifecycle loss, existing pairing, or
write failure makes that session terminal; the caller must rescan rather than retry it.

Raw signed messages are accepted only by this internal native API. They are not plugin command
arguments and are not returned to the Rust or WebView layers.

Opening requires the expected desktop and identity identifiers and an existing state file. Missing,
corrupt, non-canonical, oversized, wrong-scope, or unsupported state fails closed. It is never
interpreted as a new pairing.

### Request consumption

The native protocol entry point verifies a request against the signing key and identifiers loaded
from the opened pairing state. Only after canonical parsing, expiry checks, recipient-stanza checks,
and signature verification succeed does it add the request ID and nonce and durably replace the
combined state file. It returns a verified request only after that commit succeeds.

Expired entries are pruned only during a successful replacement. Time rollback, capacity
exhaustion, lock contention, or any I/O uncertainty fails before biometric UI. The current store
instance becomes unusable after a failed write.

### Durability and concurrency

A separate per-scope lock file is held with an exclusive process lock for the store lifetime. Each
replacement writes a newly created same-directory temporary file, flushes its file descriptor,
renames it with Android's POSIX filesystem API, and fsyncs the containing directory. Temporary names
and state paths never include caller-provided labels.

### Revocation and recovery

[`ADR 0017`](0017-lifecycle-and-recovery.md) supersedes the lifecycle terminology in this section.
Revoking one paired desktop makes and keeps only that pairing unavailable, then removes its combined
pairing/replay state; it does not remove identity-wide key aliases or another desktop pairing.
Deleting the complete phone identity first makes every pairing unavailable, then removes every
pairing/replay record, the exact identity key aliases, and residual metadata through a fail-closed
journal. A crash at any point must leave the affected scope unavailable or recoverable only through
an explicit cleanup path; it must not reconstruct empty replay state.

Uninstalling the app removes both app-private state and Keystore ownership. Android backup/restore
must not copy pairing or replay state. Phone replacement continues to require an independent age
recovery recipient.

## Consequences

- Pairing display metadata and replay security state cannot drift through independent writes.
- The WebView receives only non-sensitive booleans from the storage Doctor; filenames, protocol
  bytes, identifiers, and key aliases are not exposed.
- A storage or clock fault can deny service, which is safer than reauthorizing a consumed request.
- The future QR pairing flow must call this native lifecycle rather than SharedPreferences or an
  independently created replay file.

## Implementation evidence

The Kotlin implementation strictly decodes the combined canonical CBOR state, checks role-key
separation and private file modes, rejects symbolic-link lock files before opening them, and exposes
one verify-then-durably-consume entry point. JVM tests cover restart replay, wrong scope, expiry
pruning, capacity, clock rollback, corruption, non-canonical bytes, permissions, lock-file symlinks,
duplicate creation, deletion, injected replacement failure, malformed transcripts, cancellation,
fingerprint mismatch, duplicate confirmation, and terminal write failure. The Android Doctor uses
only fresh synthetic keys and file-key material and removes its exact, separately named no-backup
directory.

On 2026-08-24, the Doctor passed on the Samsung `SM-F9660`: all storage, atomic creation,
verify-before-consume, replay-after-reopen, wrong-scope, missing-after-delete, and cleanup checks
were true with no error category. An independent app-sandbox check found no Doctor directory after
the run, and a PID-scoped device log filter found no prohibited key, payload, stanza, QR, or alias
markers and no crash markers.

The extended native-confirmation run on the same device additionally passed transcript verification,
fingerprint-mismatch rejection, cancellation rejection, confirmation commit, and duplicate-action
rejection. All twelve report booleans were true with no error category. The independent residual,
sensitive-log, and crash checks remained clean.
