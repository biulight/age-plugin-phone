# ADR 0010: reference age state-machine integration

Status: accepted for the QR prototype; not approved for production secrets.

## Decision

The desktop binary implements both standard age plugin state machines:

- `recipient-v1` strictly decodes the public `age1phone` payload and wraps every supplied age file
  key into a `phone-p256-v1` stanza using only the phone's public P-256 key.
- `identity-v1` ignores unknown stanza tags, rejects malformed supported stanzas, creates one fresh
  signed unwrap session per file key, and returns an `age_core::format::FileKey` only after the
  paired phone response has passed all binding, signature, expiry, AEAD, and durable replay checks.

An identity stub contains no private desktop key and no filesystem path. Pairing therefore creates
a separate private locator under the desktop user's `age-plugin-phone` configuration directory.
The canonical locator is bound to the identity ID, desktop ID, and pairing transcript fingerprint,
and contains absolute paths to the private desktop authentication state and scoped response replay
state. Locator files are mode `0600`, live under a mode `0700` directory, reject symlinks and hard
links, are never overwritten, and are treated only as locators: the referenced cryptographic state
must still match the public identity stub.

The configuration directory defaults to the platform user configuration location. The
`AGE_PLUGIN_PHONE_CONFIG_DIR` override must be absolute and is intended for isolated installations
and tests; it does not weaken any cryptographic binding.

## QR interaction

The identity state machine renders the complete request as one maximum-size framed terminal QR
through the standard `message` callback, then opens the default desktop camera. Decoded transport
frames are bounded and reassembled in zeroizing memory; only a complete digest-checked response is
passed to protocol verification. Raw requests, responses, stanza bodies, file keys, camera frames,
and QR text are never written to messages, files, or logs. Callback cancellation, scanner
cancellation, camera failure, and timeout close the session.

## Multiple inputs

Unknown stanza types are ignored as required by age. Each file with a supported stanza receives a
separate request and fresh phone authorization. Encryption wraps every file key to every supplied
phone recipient.

Version 1 phone stanzas deliberately reveal no recipient identifier. If several phone identities or
several `phone-p256-v1` stanzas are supplied together, the desktop cannot select the correct pair
without trying private operations. The plugin therefore rejects either ambiguity before opening
the camera or requesting phone authorization; it never silently chooses by list order. A versioned,
privacy-preserving selection design is required before claiming general multi-phone-recipient
interoperability.

## Consequences

- Reference age can encrypt to the public phone recipient without contacting the phone.
- Reference age can invoke the paired one-shot unwrap through `identity-v1`.
- The long-term phone identity remains non-exportable and the desktop still stores no age identity.
- Desktop camera permission and device interoperability require packaged-binary validation.
- Anonymous multi-phone ciphertext fails closed instead of causing wrong-phone authorization.
