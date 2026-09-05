# AGENTS.md

This repository implements a security boundary. Favor a small, auditable design over convenience.

Before changing protocol, key custody, pairing, transport, or mobile authentication behavior, read
`docs/architecture.md`, `docs/protocol.md`, and `docs/threat-model.md` in full.

## Security invariants

- Never add a fallback that stores a long-term age identity on the desktop.
- Require fresh native phone user verification for each identity unwrap; never cache authorization
  across unwrap operations.
- Never log private keys, file keys, decrypted plaintext, raw protocol payloads, or QR contents.
- Treat all caller-provided labels and application names as untrusted display hints.
- Bind every unwrap response to the paired desktop, request digest, one-time session key, and nonce.
  Verify the complete signed pairing transcript before confirming or persisting a peer.
- Reject unknown protocol versions, algorithms, and message fields. At the standard age
  `identity-v1` input boundary, ignore unknown stanza tags and reject malformed supported stanzas.
- Keep application-layer authentication and encryption independent of transport security. BLE
  pairing, USB/ADB authorization, Wi-Fi discovery, and listener availability never authorize unwrap.
- Preserve durable replay consumption on cancellation and failure; never reset uncertain replay
  state to an empty store.

## Task authorization

Continue authorized, reversible work and relevant verification without repeated approval. Explicit
task instructions take precedence over skill workflow guidance; do not infer extra approval gates
from advisory wording. When additional authorization is needed, finish independent preparation
first, then identify the action and authorization boundary, citing any instruction requiring approval.

Development-task authorization never substitutes for product fingerprint comparison, fresh phone
verification, or native destructive-action confirmation.

## Verification

For security-behavior changes, add or update negative tests for cancellation, replay, wrong-device,
timeout, and malformed messages. For documentation-only changes, check references, consistency, and
`git diff --check`; runtime tests are not required. Complete the relevant checks and repeat or
broaden them only for new changes, failures, or unresolved concerns.

Before committing Rust changes, run:

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```
