# macOS state removal and recovery

macOS remains experimental while the [support plan](macos-support-plan.md) has
open acceptance gates, including same-Mac snapshot rollback. Use disposable test
data for acceptance. The commands below do not expand that support declaration.

## Incomplete setup

On macOS, explicit `pair` uses the same ownership journal and recovery commands as
managed `setup`. Each explicit pairing requires unused paths; private desktop and
replay files must be direct children of the protected root. The public stub may be
outside it. Explicit filenames must be distinct and use lowercase ASCII letters,
digits, `.`, `_` or `-`; `.cbor`, `.lock`, `.pending` and internal temporary prefixes
are reserved. Existing or uncertain state cannot be reused for another pairing.

`setup --resume` completes only the exact setup whose full fingerprint was already
confirmed and durably recorded. It does not continue an unconfirmed phone exchange.
If confirmation was not recorded, use `setup --cleanup`, compare the displayed
fingerprint or setup code with the intended attempt, and type it yourself. If the
phone committed that attempt, revoke its matching pairing on the phone as well.

A pending/corrupt replay file is never reset to retry an unwrap. Do not remove a
pending marker, restore old replay bytes, or copy pairing state through Migration
Assistant or Time Machine. Backup exclusion does not prove state freshness.

## Remove a paired desktop

First revoke the pairing in the phone's native UI and complete its destructive
confirmation. Then run:

```console
age-plugin-phone remove-desktop-state --identity-stub /absolute/path/to/identity.txt
```

Compare the complete transcript fingerprint with the intended pairing and type it
yourself. The command journals the exact target before deleting private state and
the supplied public stub. If interrupted, run the same command with the same stub
path; the journal retains the target even if an earlier step already removed it.

If the public stub is unavailable, use its canonical private locator:

```console
age-plugin-phone remove-orphaned-desktop-state --locator /absolute/path/to/pairing.cbor
```

The locator must be directly under the selected protected configuration root.
Orphan cleanup does not search for or delete public stubs. Both commands refuse an
active replay owner, redirected/overlapping journal paths, insecure files, or
another locator sharing the targeted desktop or replay state. Do not bypass such
errors by deleting journals or other pairings' files.

For the deterministic paths created by `setup`, cleanup can remove lost/partial
hardware metadata and unavailable replay state after exact confirmation. Arbitrary
explicit state paths still require valid key metadata and replay scope before a
new cleanup can begin. Software `APDK2` state is not imported or silently removed.

Deletion removes this Mac's reference files and attributable replacement
temporaries. CryptoKit does not provide this CLI an irreversible per-key destroy
operation: another copy of a hardware-wrapped reference on the same Mac may remain
usable. Legacy unscoped `.state-*` temporaries cannot be attributed safely and are
retained. Phone revocation is authoritative even when local reference copies exist.

## Replace an endpoint or leave the software prototype

Version 2 ciphertext binds both the phone identity and this desktop's selection
key. A new pairing cannot decrypt old ciphertext. Before replacing either endpoint:

1. Decrypt through the still-working original pairing or an independent recovery
   recipient that was included in the original encryption operation.
2. Pair the new endpoints with a new full-fingerprint comparison. Encrypt anew to
   the new phone recipient and a separately verified independent recovery recipient.
3. Verify both recovery and the new phone path before retiring old ciphertext or
   revoking the old pairing. Each phone unwrap still requires fresh native verification.

An independent recovery path must work without the original phone, Mac hardware
keys, plugin locator or replay files. A second phone paired only to the same Mac
does not cover loss of that Mac. The recovery identity is managed separately and
must never be stored in desktop plugin state. If no usable recipient was included
when the ciphertext was created, pairing again cannot recover it.

`cargo uninstall age-plugin-phone` removes the binary, not pairing state. Source
reinstallation must reuse supported hardware metadata and replay rather than
silently creating replacement keys. Treat an incompatible older binary as
unavailable; do not convert hardware state to a software key to make it open.
Exact install/upgrade acceptance is tracked separately in M5.
