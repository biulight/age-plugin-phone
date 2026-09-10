# ADR 0026: Explicit native tag and paired phone recipients

Date: 2026-09-10. Status: implementation candidate; phone hardware acceptance pending.

The [PRD](../tagged-recipient-prd.md) adds standard `age1tag` without changing the default
`age1phone` or the meaning of any existing identity. This extends ADRs 0001, 0010 and 0012;
their historical vectors and acceptance records still describe phone v1/v2 only.

`setup`, `pair` and the read-only `recipients -i FILE` command accept `--recipient-type phone|tag`.
Omission always selects phone. The public stub's compressed phone P-256 key produces native
tag recipients; substituting the HRP of a paired phone v2 recipient would be invalid. The public
stub, locator, paired keys, replay records, setup journal and protocol v2 encoding remain unchanged.
`phone_recipient`, `tag_recipient` and `recipient_for` are explicit Rust APIs; the compatibility
`selectable_recipient` API still returns phone v2. Setup JSON retains schema 1 and exactly its
three existing fields. The chosen recipient appears in the identity file's first comment.

Recipient export reads and strictly validates only the single canonical public stub. It never
opens a locator, replay scope, hardware key or transport. An interrupted setup that already wrote
its public file must resume with the same recipient type: it cannot report an output inconsistent
with that file or silently rewrite the file. Before that write, the choice affects only output.

The byte specification is [C2SP age v1.1.0](https://c2sp.org/age@v1.1.0#p256tag-recipient-stanza)
and [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html). Implementation references are
`age-plugin-se` commit `57ccea12fc1a3d3bb81b8866745be4d2951c4eaf`, specifically
[Plugin.swift](https://github.com/remko/age-plugin-se/blob/57ccea12fc1a3d3bb81b8866745be4d2951c4eaf/Sources/Plugin.swift)
and [HPKE.swift](https://github.com/remko/age-plugin-se/blob/57ccea12fc1a3d3bb81b8866745be4d2951c4eaf/Sources/HPKE.swift).
Actual client acceptance uses age v1.3.2 and rage 0.12.1; native age encryption requires 1.3+.

The standard stanza has two arguments after `p256tag`: canonical unpadded Base64 encodings of
a four-byte public selector and a 65-byte uncompressed P-256 encapsulated key. Its body is exactly
32 bytes. HPKE uses base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305,
`info = age-encryption.org/p256tag`, empty AAD and sequence number zero. The selector is the first
four bytes of HKDF-Extract-SHA256 with that same info string as salt and
`enc || SHA256(compressed phone public key)[:4]` as input.

All supported stanza structure is validated before private state is opened. The desktop scans all
tag candidates for ambiguity first: two distinct matching phone public keys are fatal. The first
matching tag stanza in file order is selected, and the first input pairing for its phone key wins.
If no tag matches, the existing phone selection rules apply. This public prefilter never attempts
a private operation. Once a matching tag selects a pairing, any missing state or failure is final;
there is no trial of another pairing, phone format or transport. Unknown stanza types are ignored.

The selected canonical stanza travels inside the existing signed request. Kotlin and Swift parse
it before authorization, retain request consumption on failure and use the existing fresh
StrongBox CryptoObject or Secure Enclave LAContext for identity ECDH. Native code then performs
the HPKE key schedule and authenticated open. The ordinary signed, encrypted response and durable
desktop consumption still gate file-key release. Swift invalidates the new context even if open
throws. No additional WebView, Tauri, discovery or transport interface carries secret material.

Tag is publicly testable by anyone who knows the recipient, so it offers less recipient privacy
than phone v2 private selection. It is not an authorization token: the real collision fixture
demonstrates that matching selectors for two keys do not imply successful HPKE decryption.
Re-pairing the same surviving phone key can authorize a new desktop to access old tag ciphertext;
phone v2 ciphertext remains bound to its original paired desktop. Neither recipient-list edits
nor pairing revocation erase historical access. Independent recovery and credential rotation
remain necessary. No state migration, recovery fallback or production claim is introduced.

See [candidate evidence and remaining gates](../tagged-recipient-evidence.md). Publishing,
signing, installing a new phone build for physical acceptance, and Shine support claims remain
separate actions; source tests do not satisfy those gates.
