# ADR 0012: private selection for paired phone stanzas

Status: experimental, accepted for implementation testing; not approved for production secrets.

## Context

The anonymous `phone-p256-v1` stanza contains only an ephemeral public key and authenticated file-key
ciphertext. A desktop that holds public phone identities cannot determine which identity a stanza
targets. Trying phone identities would consume authorization attempts; adding a stable public tag
would make ciphertexts linkable by anyone who knows the recipient.

## Decision

Version 2 recipients are pairing-specific. Their plugin payload is the fixed sequence:

```text
0x02 || phone_identity_public_key || desktop_selection_public_key || identity_id
```

Both public keys are canonical 33-byte compressed P-256 points and `identity_id` is 16 bytes. The
desktop selection key is the existing role-separated desktop authentication key. Its private scalar
may recover only an identity identifier; it never decrypts an age file key.

A version 2 stanza is exactly:

```text
tag  = "phone-p256-v2"
args = [base64-no-pad(ephemeral_public_key),
        base64-no-pad(selection_ciphertext)]
body = file_key_ciphertext
```

Both ciphertexts are exactly 32 bytes: 16 bytes of plaintext and a 16-byte Poly1305 tag. Encryption
uses one fresh uniformly random P-256 ephemeral scalar and two independent ECDH/HKDF domains:

```text
phone_shared = P-256-ECDH(ephemeral_private, phone_identity_public)
file_key_key = HKDF-SHA256(
  phone_shared,
  ephemeral_public || phone_identity_public,
  "age-plugin-phone/recipient/p256/v2/file-key")

desktop_shared = P-256-ECDH(ephemeral_private, desktop_selection_public)
selection_key = HKDF-SHA256(
  desktop_shared,
  ephemeral_public || desktop_selection_public,
  "age-plugin-phone/recipient/p256/v2/selection")
```

Both AEAD operations use ChaCha20-Poly1305 with a zero nonce. This is safe only because the
ephemeral scalar is fresh for every stanza and the HKDF domains are distinct. File-key AAD binds the
tag, ephemeral key, and phone public key. Selection AAD binds the tag, ephemeral key, both recipient
public keys, and the complete file-key ciphertext. The selection plaintext is the exact 16-byte
`identity_id`.

The desktop tests candidate v2 stanzas against locally opened pairing records. A candidate matches
only after selection AEAD authentication and constant-time identity-ID comparison. It chooses the
first authenticated match in the age client's identity order and then stanza order; unlike v1,
order never substitutes for cryptographic matching and cannot select a stanza for the wrong phone.
No match fails before camera capture or phone authorization. Version 1 remains readable only when
there is exactly one identity and one stanza; it is never guessed by order.

The phone validates the two-argument v2 structure before prompting, ignores the selection
ciphertext for key custody, and unwraps the file-key body with the v2 file-key domain. Request
signature, pairing identifiers, user verification, response encryption, and replay handling remain
unchanged.

## Consequences

- Outsiders cannot test a v2 ciphertext against a known recipient without the paired desktop
  private key.
- Copying desktop state reveals which stanza belongs to that pairing but still cannot decrypt its
  file key or authorize the phone operation.
- A v2 recipient is specific to one phone identity and paired desktop. Re-pairing produces a new
  recipient.
- Reusing an ephemeral scalar compromises the zero-nonce AEAD construction and remains prohibited.
- The construction requires independent cryptographic review before wire-format stabilization.

## Validation

`docs/test-vectors/p256-recipient-v2.json` contains fixed public test scalars, identity ID, recipient,
selector, and file-key ciphertext. Rust and Kotlin independently reproduce the vector and unwrap the
file-key body. Negative tests cover wrong desktop key, wrong identity ID, modified selector,
modified file-key body, missing or padded selector arguments, v1 ambiguity, no matching pairing,
and ordered selection across multiple identities and stanzas. The vector contains no production
secret and must never be imported into a platform keystore.
