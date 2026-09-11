# Explicit tagged-recipient workflow

This workflow applies to the source candidate implementing [ADR 0026](adr/0026-native-tagged-recipients.md),
not the published alpha.5 snapshot. It remains experimental and is for synthetic data only.
Upgrade both desktop and phone software to a compatible candidate before testing tag decryption.
Existing protocol v2 pairings and public identity stubs remain usable without re-pairing.

| Choice | Encryption requirement | Selection/privacy |
| --- | --- | --- |
| `phone` (default) | Standard age plugin-capable client plus `age-plugin-phone` | Paired-desktop phone v2 private selection; old phone v1 ciphertext remains readable |
| `tag` (explicit) | age 1.3+; validated with age v1.3.2 and rage 0.12.1; no phone plugin on the encrypting machine | Standard p256tag; anyone knowing the recipient can publicly test whether a stanza may target it |

Export a native recipient from an existing public identity file:

```console
age-plugin-phone recipients -i phone-identity.txt --recipient-type tag
```

The command outputs one canonical recipient plus a newline. It does not contact the phone, select
a transport, open private state, or require hardware. Keep using the same identity file for decrypting
both old phone ciphertext and new tagged ciphertext. To export the paired desktop's phone recipient:

```console
age-plugin-phone recipients -i phone-identity.txt --recipient-type phone
```

New pairing can select its displayed recipient explicitly:

```console
age-plugin-phone setup --label "Work laptop" --recipient-type tag --json
```

`pair` accepts the same option alongside its existing explicit paths and transport options.
Without the option both commands still output phone. Setup JSON remains
`{"schema_version":1,"identity_path":"...","recipient":"age1tag..."}` with one recipient only;
the underlying `AGE-PLUGIN-PHONE-...` stub does not change with the display type. Fingerprint
comparison is still mandatory. When resuming a confirmed setup, repeat `--recipient-type tag`
if its public file was already created with tag; a conflicting output type fails without rewriting it.

Copy the exported recipient to any machine with age 1.3+, then use ordinary age commands:

```console
age -e -r age1tag... -r age1... -o synthetic.age synthetic.txt
age -d -i phone-identity.txt -o recovered.txt synthetic.age
```

Replace both recipient placeholders with real public addresses. The second address must be an
independently verified recovery recipient. Public encryption needs neither the phone nor its plugin;
decryption needs the plugin, intact paired desktop state, the phone, and fresh native verification
for that operation. A failed or cancelled tag operation never falls back to phone, another pairing,
another transport, or cached authorization. An older phone app strictly rejects the new stanza.

To migrate retained ciphertext, decrypt it using an existing authorized identity, update the public
recipient list, and encrypt anew. Exporting a tag alone does not migrate ciphertext. Changing the
list does not revoke historical access; rotate actual upstream credentials when removing a member.
Keep recovery separate from both primary devices.

Shine and other applications consume these generic recipients and identity paths through age.
They must accept native tag recipients and use age 1.3+ on their encryption path. No application
process, configuration format or private RPC is needed by the plugin. Candidate-specific Shine
acceptance is [tracked separately](tagged-recipient-evidence.md).
