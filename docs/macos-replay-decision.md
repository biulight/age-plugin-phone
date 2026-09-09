# macOS replay rollback decision — pending review

Status: **no scope change approved**. The current threat model and M2 acceptance
requirement remain in force. This document makes the unresolved choice reviewable;
it does not close the macOS support gate.

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
