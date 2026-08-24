# age-plugin-phone

`age-plugin-phone` is an experimental, standalone [age] identity plugin that will keep long-term
decryption keys on a phone and authorize individual file-key unwrap operations over a fully offline
QR, BLE, or USB channel.

It is intended to work with any compatible age client. It does not depend on Shine, understand
Shine environments, or define a Shine-specific ciphertext format.

> [!WARNING]
> This repository is a design and fail-closed plugin scaffold. It cannot create identities or
> decrypt files yet. Do not use it to protect real secrets.

## Intended boundary

```text
age-compatible application
          |
          v
       age/rage
          |
          v
 age-plugin-phone  <---- QR / BLE / USB ---->  phone app
                                                   |
                                                   v
                                      hardware-backed private key
```

The phone should release only the file key for the single age recipient stanza approved by the
user. It must never export the long-term private key to the desktop.

## Repository layout

- `crates/desktop`: the `age-plugin-phone` desktop binary and age plugin entry point.
- `crates/protocol`: transport-independent pairing and unwrap message types.
- `apps/mobile`: Tauri 2 mobile application with a deliberately non-sensitive TypeScript UI.
- `docs`: architecture, protocol, threat model, and roadmap.

## Current commands

```console
cargo run -p age-plugin-phone -- status
cargo test --workspace

cd apps/mobile
bun install
bun run tauri android init
bun run tauri ios init
```

The plugin accepts the age `--age-plugin=identity-v1` entry point, but deliberately returns an
unsupported error until a reviewed phone transport and cryptographic backend exist.

## Design goals

- No server, account, cloud rendezvous, or online authorization dependency.
- Independent phone user verification for every private-key operation.
- Long-term private keys are non-exportable or wrapped by a hardware-backed phone key.
- The desktop receives only a request-bound file key, never the long-term identity.
- Replay, copied desktop state, cancellation, and transport failure all fail closed.
- Standard age plugin and recipient behavior remains the only application integration boundary.

See [the architecture](docs/architecture.md), [protocol draft](docs/protocol.md), and
[threat model](docs/threat-model.md) before implementing a transport or cryptographic backend.

## Why Tauri

Tauri 2 provides one mobile application shell while keeping protocol logic in Rust and allowing the
hardware-key boundary to be implemented as a small native Swift/Kotlin plugin. The WebView is UI
only: long-term keys, unwrapped file keys, raw signed requests, and hardware-key commands must not
cross into JavaScript. The generic Tauri biometric plugin is not a substitute for binding user
authentication to the actual Secure Enclave or Android Keystore private-key operation.

[age]: https://age-encryption.org/
