---
title: "Choose phone or tag recipients"
sidebar_position: 2
---

# Choose phone or tag recipients

Choose the public address format for new encryption. Both formats use the same public identity stub for decryption and require intact paired desktop state, the phone, and fresh verification.

| Choice | Encrypting machine | Privacy and compatibility |
| --- | --- | --- |
| `phone` (default) | Compatible age client and phone plugin | Phone v2 uses private paired-desktop selection; legacy v1 remains readable for unambiguous files |
| `tag` (explicit) | age 1.3+; no phone plugin required for encryption | Anyone knowing the recipient can test whether a stanza may target it; older phone apps reject tag decryption |

## Export from an existing pairing

Use the public stub from [setup](../quick-start.md):

```sh
age-plugin-phone recipients -i phone-identity.txt --recipient-type tag
age-plugin-phone recipients -i phone-identity.txt --recipient-type phone
```

Each invocation prints one public recipient. Export does not contact the phone or open private state. Existing protocol v2 pairings do not need re-pairing solely for tag support; update desktop and phone to a compatible Beta release before decrypting tags.

To make a new setup display a tag recipient:

```sh
age-plugin-phone setup --label "Test laptop" --recipient-type tag --json
```

This example uses the default `auto` connection policy; follow its [platform-specific order](transports.md). Full fingerprint comparison is still required. When resuming a confirmed setup whose public file was already created with tag, repeat `--recipient-type tag`; a conflicting type is rejected.

## Encrypt and verify

Replace both recipient placeholders with exported public addresses. The second must be an independently tested recovery recipient:

```sh
age -e -r '<tag-recipient>' -r '<recovery-recipient>' -o synthetic.age synthetic.txt
age -d -i phone-identity.txt -o recovered.txt synthetic.age
```

Verify both phone and recovery paths as in the [quick start](../quick-start.md). A failed tag operation does not switch to phone mode or another pairing. Exporting a new address does not convert existing ciphertext: decrypt and encrypt again to migrate it. Updating a recipient list does not revoke access to old copies; rotate actual upstream credentials when needed.
