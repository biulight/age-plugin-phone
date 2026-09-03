# ADR 0020: simplified transactional Windows identity setup

- Status: implemented; packaged Windows/Android validation pending
- Date: 2026-09-03
- Scope: managed Windows setup paths, create-only TPM state, interruption recovery, and CLI output

## Context

The explicit `pair` command requires users to invent and coordinate TPM metadata, replay-state, and
public identity-stub paths. Those arguments are useful for diagnostics, but they expose internal
storage plumbing as the normal product experience. Hiding the paths is safe only if setup retains
the existing transport, fingerprint, replay, TPM, and lifecycle boundaries and can attribute every
partial write after process loss.

## Decision

The Windows Alpha adds `age-plugin-phone setup --label LABEL` as its normal entry point. `auto`
continues to resolve to one Developer USB ADB route; `--transport qr` remains an explicit fallback,
and `--adb-serial` pins one untrusted ADB route hint. Wi-Fi and BLE are not pairing routes. The
existing explicit `pair` command remains available for diagnostics and does not become a second
managed setup format.

Setup is Windows-only because this product path requires the Windows 11 x64, TPM 2.0, Microsoft
Platform Crypto Provider, protected filesystem, and crash-safe cleanup boundaries. Non-Windows
builds reject `setup` and retain explicit interoperability commands.

Before creating setup state, the command validates the label and route, performs the read-only
Windows capability probe, and preflights the selected transport. ADB preflight requires exactly one
online device unless a serial is supplied and rejects an existing fixed reverse rule. QR preflight
opens the camera stream before setup state is created. Phone StrongBox enforcement remains inside
the authenticated native pairing controller; no unauthenticated capability RPC is added.

After preflight, setup creates or validates `%LOCALAPPDATA%\age-plugin-phone`, takes the existing
global desktop-lifecycle lock, and refuses to run beside a cleanup or another setup attempt. A
random desktop ID allocates three create-only direct children:

- `desktop-<desktop-id>.state` for TPM metadata;
- `replay-<desktop-id>.state` for desktop response replay; and
- `identity-<desktop-id>.txt` for the public age plugin identity.

Labels, ADB serials, device names, and routes never enter filenames or the setup journal. The
locator retains its existing identity-and-desktop-bound canonical filename.

Before provisioning either CNG key, setup durably creates `desktop-setup.cbor` with a protected
current-user ACL. Its fixed canonical encoding binds a random recovery code, exact desktop ID,
exact paths, stage, and—after response verification—the canonical public pairing candidate. Unknown
versions, stages, fields, non-canonical encodings, or path mismatches fail closed. Setup uses a new
strict CNG create operation that refuses complete or partial pre-existing key sets and removes the
first role if the second cannot be created.

The durable stages are:

1. `Provisioning`: exact targets are owned for bounded cleanup;
2. `Pairing`: TPM metadata and both role-separated keys exist;
3. `ResponseVerified`: the authenticated public candidate and full transcript fingerprint exist,
   but desktop confirmation has not completed; and
4. `Confirmed`: the user typed the exact complete fingerprint and the candidate may be committed.

Only `Confirmed` may be resumed. `setup --resume` displays and requires the complete fingerprint
again, validates the TPM public keys against the candidate, and idempotently completes local commit.
Every earlier stage may only use `setup --cleanup`, which requires either the full fingerprint or,
before one exists, the setup recovery code. Neither maintenance mode contacts or revokes the phone.

Commit activates the identity in this order: create or validate the exact replay scope, create or
validate the exact locator, create or validate the exact public stub, then remove the setup journal.
While the journal targets a candidate, ordinary locator opening rejects it. Existing objects are
accepted during resume only when their complete binding or decoded contents equal the journal;
nothing is overwritten or repaired.

Cleanup idempotently removes the journaled replay file and lock, exact CNG key set, TPM metadata,
canonical locator, possible public stub, and finally the setup journal. If a verified phone response
existed, output always tells the user to revoke the matching full fingerprint on the phone. Local
cleanup is not phone-side revocation.

Success prints only the public recipient, public identity-stub path, standard age examples, and an
explicit warning that pairing is not a recovery drill. It never prints private paths, ADB serials,
key aliases, or protocol payloads.

## Consequences

- The normal Windows path no longer asks callers such as Shine to reproduce plugin storage rules.
- Re-running setup creates a distinct desktop ID, key set, paths, offer, nonce, transcript, and
  replay scope; it never overwrites a previous pairing.
- A hard interruption can leave one exact private journal, but cannot expose an identity to unwrap
  before replay, locator, stub, and journal removal complete.
- A phone may already retain a pairing after a desktop-side failure. Recovery output must say so;
  no desktop command claims remote revocation.
- The age recipient, `recipient-v1`, `identity-v1`, Android protocol, and Shine integration remain
  unchanged.

## Validation

Portable coverage validates strict journal encoding and stages, managed CLI modes, response
candidate equality, ADB preflight, and non-Windows rejection. Windows-native coverage must validate
ACLs, strict CNG creation, restart resume and cleanup, storage conflicts, partial commits, and
multi-pairing isolation. The exact packaged Windows/Android candidate must still complete the setup,
interruption, standard-age, Shine, and independent-recovery matrix before this ADR gains physical
validation status.
