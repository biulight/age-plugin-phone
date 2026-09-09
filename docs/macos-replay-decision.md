# macOS replay rollback decision — historical review

Status: **superseded on 2026-09-10 by the user-approved cross-platform boundary**.
See [Desktop replay rollback POC](desktop-replay-rollback-poc.md) for the current
Windows/macOS guarantee and deferred validation. The choices and feasibility review
below record the earlier discussion; statements that approval is pending or rollback
alone blocks current Mac acceptance are historical. No runtime fix is claimed.

## Observed boundary

The [M2 experiment](macos-m2-evidence.md) restores the synthetic response store's
earlier valid bytes and then consumes an already-used digest again. File modes,
ACL checks, atomic replacement, pending markers, backup exclusion and hardware key
custody do not authenticate the freshness of those restored bytes. Copies of a
wrapped key reference remain usable on the original Mac. Thus adding a MAC or
signature to a restorable store, using another same-user file, or encrypting it
under the same hardware key would not by itself distinguish the old valid state.

That is a replay-store counterexample, not evidence that a recorded encrypted
response decrypts in a newly created session. Requests separately bind the desktop,
request digest, nonce and one-time response key; the phone separately consumes
verified requests and requires fresh native verification for identity use. The
regression test `restored_response_store_does_not_bind_an_old_response_to_a_fresh_session`
tests this distinction using synthetic software fixtures. It cannot establish
native phone behavior, arbitrary process-memory security or filesystem freshness.

## Choice A: retain the store-freshness requirement

Keep macOS experimental until a trusted freshness authority outside the same-user
restorable state is designed and validated. A privileged service or a changed
phone-mediated protocol could be investigated, but neither is implemented or
claimed sufficient here. The design must state which rollback adversary it resists,
how authority survives crashes and restore, how an uncertain update fails closed,
and how installation, recovery and offline operation change. A privileged service
would require revisiting the ordinary source-installed CLI delivery contract.

This choice does not authorize a software-key fallback, resetting replay state, or
weakening per-unwrap phone verification. It leaves the present M2 exit condition open.

## Choice B: explicitly narrow the filesystem freshness claim

The proposed text, if separately approved, would be:

> The desktop response store preserves consumption across supported ordinary
> process failures and restarts and rejects missing, corrupt, mismatched or uncertain
> state. It does not detect restoration of an older valid same-Mac filesystem state.
> Recorded responses must still fail against a fresh session's complete cryptographic
> binding, and every successful phone identity operation requires fresh native phone
> verification. This limitation does not permit automatic store recreation or
> authorization caching.

This would change the M2 **store-level** acceptance requirement; it would not make
the existing rollback experiment pass. The threat model and support statement would
have to name the limitation explicitly, with evidence for session binding and the
phone's own replay/verification behavior. Broader real-device and security-review
gates would remain. No such change has been made in the threat model or runtime.

Until that choice is reviewed, the implementation and evidence retain Choice A's
open gate. Installation and lifecycle tests must not be presented as resolving it.

## 2026-09-10 feasibility review

The user's instruction to continue does not approve Choice B. No runtime or protocol
change was made in this review. The current `FileReplayGuard::open` validates canonical
bytes and scope; `commit` durably updates the file and pending marker. Every persistent
input used to establish freshness is still in the same-user restorable directory. A
prior valid snapshot therefore supplies exactly the inputs that previously passed.

The installed CryptoKit Swift interface exposes Secure Enclave P-256 signing and key
agreement with restorable `dataRepresentation` references. Inspection found no public
application monotonic-counter operation there. This is bounded API evidence, not proof
that no Apple platform facility could ever address the problem. Apple's hardware
[Secure Enclave description](https://support.apple.com/guide/security/the-secure-enclave-sec59b0b31ff/web)
describes internal replay protection; it does not specify an arbitrary application
replay-store API. The public [CryptoKit interface](https://developer.apple.com/documentation/cryptokit/secureenclave)
must not be credited with that additional guarantee.

| Direction | Required change | What it does not yet establish |
| --- | --- | --- |
| Sign/encrypt state, second file, clock, backup exclusion | Local-only changes | Old authenticated bytes remain valid; a restorable high-water mark is not an anchor |
| User-accessible Keychain record | Alternate storage and access policy | Must prove update/delete/recreate and backup rollback resistance for the same-user adversary; merely storing a counter is insufficient |
| Privileged local authority | Independently protected service/state and administrator-approved installation | Does not resist rollback of that authority itself; changes the ordinary source-only installation contract |
| Phone-held authority | New authenticated freshness exchange, durable phone state, revised transport flows and compatibility | Current v2 response binding alone does not prove desktop store freshness; requires new protocol design and both phone implementations |

### Minimum requirements for a privileged-authority prototype

The authority must own the replay ledger, validate peer credentials, scope requests to
the authenticated OS user and pairing, and never accept arbitrary filesystem paths.
It needs an atomic check-and-consume operation, not a client-supplied replacement counter.
Commit must complete before success; uncertain writes and restart failures stay unavailable.
Lost replies must never make a duplicate look like a new successful consumption. Pairing
initialization, deletion and reinstall require explicit rules that prevent delete/recreate
from resetting an existing scope. Bounded capacity and caller flooding may deny service,
but must not authorize identity use. It stores no file keys or phone private keys.

The threat boundary must distinguish an attacker restoring user files from restoration
of the privileged ledger itself. Administrator/kernel compromise remains excluded by
the threat model, but ordinary system restore still needs a documented failure/recovery
policy. A root-owned file on the same restored volume is not universal snapshot protection.
This direction cannot be called complete merely because a launch daemon runs as root.

### Minimum requirements for a phone-authority prototype

An authority reply must bind a fresh challenge, exact paired scope and transition, and be
verified before the desktop accepts a consumption result. A cached signed checkpoint is
replayable and insufficient. The phone must distinguish concurrent transitions, consumed
operations, unavailable/uncertain state and reply loss without resetting its ledger or
caching identity approval. Phone replacement and restore must fail closed or require
independent recovery. Request/response changes require explicit version handling and
negative cross-version tests; they must not be added as ignored v2 fields.

Wi-Fi/ADB would need a reviewed exchange sequence; offline QR must retain an explicit
user-visible flow rather than silently requiring a network. Phone signing may attest state
without biometrics, but every actual identity unwrap still requires fresh native verification.
This is a candidate design requirement, not an implemented or validated protocol.

### Decision boundary

No small patch within the currently inspected filesystem/CryptoKit implementation closes
M2. Preserve experimental status while choosing whether to investigate privileged local
installation or a phone-mediated protocol revision. Either choice needs an isolated
prototype and failure/recovery review before integration. Retaining the existing CLI and
v2 protocol unchanged leaves M2 open; that is not permission to narrow the threat model.
