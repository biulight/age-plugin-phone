# AGENTS.md

This repository implements a security boundary. Favor a small, auditable design over convenience.

Before changing protocol, key custody, pairing, transport, or mobile authentication behavior, read
`docs/architecture.md`, `docs/protocol.md`, and `docs/threat-model.md` in full.

Mandatory rules:

- Never add a fallback that stores a long-term age identity on the desktop.
- Never cache user authorization across unwrap operations.
- Never log private keys, file keys, decrypted plaintext, raw protocol payloads, or QR contents.
- Treat all caller-provided labels and application names as untrusted display hints.
- Bind every response to the paired desktop, request digest, one-time session key, and nonce.
- Reject unknown protocol versions, algorithms, message fields, and recipient stanza types.
- Keep transport security independent from BLE pairing or USB transport security.
- Add negative tests for cancellation, replay, wrong-device, timeout, and malformed messages.

Before committing Rust changes, run:

```console
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

