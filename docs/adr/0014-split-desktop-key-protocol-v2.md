# ADR 0014: split desktop key roles in experimental protocol version 2

- Status: accepted for implementation testing; not approved for production secrets
- Date: 2026-08-25
- Scope: pairing transcript, desktop state, public identity stub, replay state, and vectors

## Context

Protocol version 1 used one desktop P-256 key for both ECDSA request signing and ECDH private
stanza selection. Windows TPM custody requires algorithm-specific non-exportable keys. Reusing one
public field for both roles would either prevent Microsoft Platform Crypto Provider integration or
blur the audit boundary between authentication and ciphertext selection.

## Decision

The experimental offline protocol version is now 2. All pairing, request, response, digest,
fingerprint, and response-session domains end in `/v2`; version 1 messages are rejected before any
state change or authorization.

The signed pairing offer is the fixed canonical CBOR array:

```text
[2, 1, 1, desktop_id, desktop_label,
 desktop_signing_public_key, desktop_selection_public_key, nonce]
```

Both public keys are canonical compressed P-256 points and must differ. The signing key signs the
offer and all later unwrap requests. The selection key is carried inside the pairing-specific v2
recipient and performs only ECDH selector recovery. The phone response remains bound to the exact
offer digest, so its signature and the full transcript fingerprint cover both desktop roles.

The four long-term P-256 roles in the complete transcript—the phone identity, phone signing key,
desktop signing key, and desktop selection key—must have pairwise-distinct canonical public keys.
Both transcript verifiers reject any role reuse before confirmation or persistence. Strict desktop
stub and Android pairing-state parsing repeat this check so manually copied or corrupted public
state cannot bypass the transcript boundary.

The public desktop identity stub is version 2 and stores both public keys independently. The
desktop software test/interoperability state uses the new `APDK2` format with two scalars; the
version 1 magic and shorter state are rejected. New encryption derives the existing v2 paired
recipient from the selection public key, never from the signing public key.

Android pairing state is version 2, uses new root and scope domains, persists both desktop public
keys, and rejects equal role keys. Desktop locators and Rust replay files are also version 2. No old
pairing, locator, replay file, or public stub is migrated or interpreted. Users must delete the old
pairing and pair again; the long-term phone identity keys do not need to be regenerated.

## Consequences

- Compromise or misuse of the desktop selection operation cannot create authenticated requests.
- A request-signing operation cannot test which v2 stanza belongs to the desktop.
- The transcript shown on both endpoints commits to both hardware public keys.
- Existing experimental identity stubs and pairing state stop working by design.
- The v2 paired-recipient byte layout is unchanged, but newly paired recipients contain the
  independent selection public key. An old recipient has no usable matching version 2 pairing
  state and therefore fails before phone authorization.

## Validation

`pairing-transcript-v2.json` and `offline-envelope-v2.json` are deterministic public vectors shared
by Rust and Kotlin. Tests cover exact canonical round trips, pairwise rejection of reused long-term
key roles, version 1 message rejection, version 1 stub and desktop-key rejection, version 1 replay-
state rejection, Android version 1 pairing-state rejection, wrong device, wrong identity, replay,
expiry, malformed input, high-S signatures, cancellation, and failed persistence.
