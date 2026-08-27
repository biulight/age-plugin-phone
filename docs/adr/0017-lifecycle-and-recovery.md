# ADR 0017: identity lifecycle, revocation, and recovery

- Status: accepted design; product commands and UI are pending
- Date: 2026-08-27
- Scope: phone replacement, recovery recipients, paired-desktop revocation, identity deletion,
  application removal, and hardware-key invalidation

## Context

The prototype can provision a StrongBox identity, pair a TPM-backed desktop, and unwrap one file
key after fresh phone user verification. Those successful paths are not sufficient for an Alpha.
The product must also explain what remains usable after a phone, application, biometric enrollment,
TPM key, or pairing record is lost, and it must never turn a lifecycle failure into a weaker key-
custody path.

Version 2 recipients bind both the phone identity public key and the paired desktop selection public
key. Consequently, replacing only one endpoint and pairing again does not make an old v2 stanza
usable. Recovery is a data migration using a recipient that was present when the data was encrypted;
it is not reconstruction of either hardware private key.

## Invariants

- No flow exports or reconstructs a StrongBox or TPM private key.
- No desktop cleanup, reinstallation, or transport failure creates a software, DPAPI, password, or
  cached-authorization fallback.
- A new phone identity or desktop pairing always uses new random identifiers, key aliases, keys,
  replay scopes, and pairing transcript. Deleted identifiers and scopes are never reused.
- Missing, invalidated, partial, corrupt, or deletion-pending state is unavailable for pairing and
  unwrap. It is never opened as empty state or repaired during an unwrap.
- Revocation and deletion are local security-state transitions. There is no server and therefore no
  claim that an offline peer, copied public stub, or ciphertext has been remotely erased.
- Existing ciphertext is immutable evidence of its original recipients. Changing recipients means
  decrypting with an existing usable recipient and creating a newly encrypted ciphertext.

## Independent recovery recipient

Important data used during the Alpha must be encrypted to the phone recipient and at least one
independent recovery recipient in the same age encryption operation. Independence is about failure
domains: the recovery path must not require the primary phone's StrongBox keys, the paired Windows
desktop's TPM keys, this application's Android state, or this plugin's locator and replay files.

Suitable candidates include an offline age identity kept off the working desktop, a separately
managed hardware recipient, a Secure Enclave identity on another machine, or a second phone whose
recovery path does not depend on the same desktop TPM pairing. A second phone paired only to the
same Windows TPM is not independent of that TPM.

The plugin does not generate, store, escrow, or silently add the recovery identity. The calling age
workflow supplies all public recipients explicitly. Before relying on a recovery recipient, the
user must perform a recovery drill on a separate path, compare the recovered plaintext, and record
only non-sensitive evidence such as recipient fingerprints, tool versions, date, and pass/fail.
Recovery private material, file keys, plaintext, and raw protocol messages must not enter the
report.

Adding, rotating, or removing a recovery recipient requires a fresh decrypt-and-encrypt operation.
The caller writes a new ciphertext, verifies it through both the new phone recipient and the
remaining recovery path, and only then may replace or retire the old ciphertext. This project does
not perform in-place age-header mutation.

## Paired-desktop revocation

The phone is authoritative for whether a desktop may request an unwrap. Revoking one paired desktop
uses this order:

1. The native app identifies the pairing by immutable desktop ID and transcript fingerprint. Its
   caller-provided label is display-only.
2. After an explicit destructive confirmation, native storage atomically moves that exact pairing
   to a deletion-pending state. Request lookup, pairing creation for the same identifiers, and
   unwrap all reject it from this point.
3. The app removes that pairing's combined public record and request-replay scope. A crash or
   storage failure leaves deletion-pending state that only the explicit cleanup path may resume.
4. The phone identity keys, other desktop pairings, and their replay scopes remain untouched.

Deleting desktop files or uninstalling the desktop binary is not phone-side revocation. When the
desktop is still available, local cleanup follows phone revocation and removes only the selected
pairing's public stub, locator, response-replay file, TPM metadata, and the two exact CNG keys. A
local cleanup failure does not restore phone authorization. If the desktop is lost or suspected
compromised, phone revocation proceeds without contacting it.

Re-pairing after revocation creates a new desktop ID, distinct TPM signing and selection keys, and a
new transcript. Because old v2 ciphertext is bound to the old selection key, it must be recovered
and re-encrypted to the new paired recipient before the old local state is destroyed when continuity
is required.

## Phone replacement

Pairing state, replay history, and StrongBox keys are never copied, backed up, or migrated to a new
phone. Replacement is:

1. Provision a new StrongBox identity on the replacement phone and verify its public recipient.
2. Create a fresh pairing with a supported TPM-backed desktop.
3. For every retained ciphertext, decrypt through the independent recovery recipient. The old phone
   may be used instead when it is still trusted and each file receives a fresh authorization, but
   this is not a recovery guarantee.
4. Encrypt the recovered data to the new paired-phone recipient and at least one independent
   recovery recipient, then verify byte-for-byte recovery through both paths.
5. Only after that verification, revoke the old desktop pairings and delete the old phone identity
   or retire the old device.

Loss of the old phone without a previously included recovery recipient is unrecoverable by design.
Support tooling must say so directly and must not offer desktop identity extraction.

## Identity deletion

Deleting a phone identity revokes every pairing for that identity and destroys its ability to open
all ciphertext addressed only to it. The native operation requires an explicit, fresh destructive
confirmation and uses a fail-closed journal:

1. Atomically mark the identity deletion-pending before deleting any pairing or key. From this
   commit onward, provisioning, pairing, and unwrap reject the identity.
2. Remove every combined pairing/replay record for that identity.
3. Delete the exact derived StrongBox identity and phone-signing aliases and verify that neither can
   be reopened.
4. Remove committed public metadata and then the deletion journal. If any step fails, retain a
   non-secret deletion-pending marker and permit only status and retry-cleanup operations.

The UI must identify the public recipient and number of affected pairings, warn that ciphertext is
not deleted, and require the user to acknowledge a verified recovery path. Acknowledgement is a
safety interlock, not proof that recovery exists. Deleting one paired desktop must never call this
identity-wide operation.

## Application removal

Android uninstall is treated as unplanned identity deletion: app-private, non-backed-up pairing
state becomes unavailable and Android Keystore ownership is lost. Reinstallation provisions a new
identity and never imports backup data or reuses the former identifiers. Recovery therefore follows
the phone-replacement flow. The product must warn about this before a user-initiated uninstall when
the platform permits it, but it cannot rely on uninstall code running.

Removing the desktop application is not revocation. `%LOCALAPPDATA%` records and CNG keys may
survive, so the phone's paired-desktop screen remains the authoritative removal control. A desktop
uninstaller must not silently destroy TPM state that is still needed to migrate old v2 ciphertext.
An explicit "remove private desktop state" option uses the paired-desktop cleanup order above.

## TPM and StrongBox invalidation

If either TPM key is missing, changed, exportable, or unavailable, the desktop pairing is unusable.
Opening state never provisions the missing role. The user revokes the old pairing on the phone,
recovers and re-encrypts old ciphertext through an independent recipient, and pairs again with two
new TPM keys. If the original TPM becomes usable again, its old state remains revoked and is not
silently reactivated.

If the StrongBox age-identity key is permanently invalidated, including by the configured biometric-
enrollment policy, the phone-signing key cannot substitute for it. If the phone-signing key or its
bound metadata is unavailable, the age-identity key cannot return an unauthenticated response.
Either condition makes the complete identity unavailable, suppresses repeated authorization
prompts, and enters the identity replacement flow. There is no TEE or software fallback.

Status and diagnostics expose only a coarse state and recovery guidance. They never include key
aliases, raw identifiers, protocol payloads, stanza bodies, QR contents, or private storage paths.

## Required implementation and negative tests

This ADR defines behavior; the current Doctor UI is not a lifecycle-management UI. Milestone 6 must
implement the native journals, management commands, and presentation flows before Alpha release.
Tests must cover at least:

- revoking one desktop without deleting the identity or another pairing;
- a request already captured from the revoked desktop and a replayed old response;
- crash or storage failure after every deletion-journal transition;
- wrong pairing, wrong identity, duplicate deletion, missing state, and malformed state;
- cancellation and timeout before the destructive commit;
- TPM signing-key loss, selection-key loss, partial CNG cleanup, and later TPM recovery;
- StrongBox identity-key invalidation, phone-signing-key loss, and biometric-enrollment change;
- Android uninstall/reinstall and backup/restore exclusion; and
- successful recovery/re-encryption plus failure when no independent recovery stanza exists.

Every failure path must produce no plaintext, no cached authorization, no recreated replay scope,
and no change to an unrelated identity or pairing.

## Consequences

- Recovery becomes an explicit multi-recipient data-management responsibility rather than a hidden
  key export feature.
- Pairing revocation, identity deletion, and local desktop cleanup have deliberately different
  scopes.
- Hardware invalidation can cause permanent loss when recovery was not configured; this is a
  security property that the Alpha UI and documentation must present before encryption.
- Protocol version 2 remains experimental. This lifecycle decision does not freeze its wire format.
