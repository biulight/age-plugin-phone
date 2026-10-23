---
title: "Upgrade, revoke, and recover"
sidebar_position: 4
---

# Upgrade, revoke, and recover

Before changing devices or deleting state, prove that an independent recovery identity decrypts every retained test file. Recovery must work without the original phone, desktop hardware keys, or plugin state. A public stub alone and a second phone paired only to the same desktop do not provide that protection.

## Upgrade without replacing the pairing

Install the compatible desktop version and matching phone release while preserving app data and desktop state. Beta 2's multi-identity fix does not require re-pairing or state migration from Beta 1. Test phone and recovery decryption after updating. Do not uninstall the phone app to resolve a signing conflict, clear its data, or create a replacement identity as a troubleshooting step.

`cargo uninstall age-plugin-phone` removes the executable, not pairing state. Reinstallation does not restore lost hardware keys. Do not restore replay files from an older snapshot, copy pairing state through a device migration tool, or delete pending markers to make a request work. Windows and macOS do not guarantee detection of older valid desktop replay snapshots.

## Recover interrupted setup

Only resume an attempt whose full fingerprint was already confirmed and durably recorded:

```sh
age-plugin-phone setup --resume
```

If its public file was created as tag, repeat `--recipient-type tag`. To abandon an incomplete attempt:

```sh
age-plugin-phone setup --cleanup
```

Cleanup deletes the exact journaled incomplete attempt. Inspect the displayed fingerprint or setup code and type the confirmation yourself. If the phone already committed the pairing, revoke that record on the phone as well. Neither command resets an uncertain replay store. If state is corrupt or the command refuses, stop and consult [troubleshooting](../troubleshooting.md).

## Revoke and remove a pairing

These operations are destructive. First test independent recovery. On the phone, select the intended entry under **Paired desktops**, compare its complete fingerprint, and complete native revocation confirmation. Then remove its desktop state:

```sh
age-plugin-phone remove-desktop-state --identity-stub '<identity-stub-path>'
```

Inspect and type the complete fingerprint. This removes the exact pairing's local state and supplied public stub. It does not revoke the phone remotely. If interrupted, repeat the same command with the same stub path; it resumes only its journaled target.

If the stub is already unavailable, use recovery-only orphan cleanup after identifying the exact canonical locator directly under the protected configuration root:

```sh
age-plugin-phone remove-orphaned-desktop-state --locator '<absolute-locator-path>'
```

Never use a wildcard or guess by the desktop label. This command does not find/delete public stubs or revoke the phone. Prefer stub-based cleanup whenever possible. On macOS, removal of local key references is not proof that every copied reference on the same Mac is destroyed; phone-side revocation is authoritative.

## Replace a device or delete the phone identity

New pairing does not recover old v2 ciphertext. Before retiring either endpoint:

1. Decrypt retained test files using the original working pairing or an independent recovery recipient included when they were encrypted.
2. Pair the new devices and encrypt anew to the new recipient plus independent recovery.
3. Verify both paths before revoking the old pairing or deleting the old phone identity.

Phone identity deletion removes its pairings and keys after native destructive confirmation. If the phone is lost, local cleanup is still not phone revocation. If no usable recipient was included in the original encryption, re-pairing cannot recover the file. Changing recipients does not revoke access to old ciphertext copies.
