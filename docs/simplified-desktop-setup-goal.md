# Simplified desktop identity setup goal

Status: proposed product goal; not an implemented command or release claim.

## Motivation

A local hardware-backed age plugin can expose a small key-generation surface. For example, Shine
can invoke `age-plugin-se keygen` behind `shine env secret identity init --touch-id` because the
operation creates one identity on one computer and returns its public recipient.

Phone custody has a necessarily larger security lifecycle. The current Windows Alpha requires the
user to choose desktop-state, replay-state, and public identity-output paths, start
`age-plugin-phone pair`, select a transport, confirm the complete transcript fingerprint on both
endpoints, retain the public identity stub, and then configure a compatible age client. Those steps
accurately expose the prototype, but the path-plumbing should not remain the normal product
experience.

The desired endpoint is one discoverable desktop setup command plus the required phone interaction.
It should feel comparable to initializing another hardware-backed age identity without pretending
that pairing, recovery, revocation, or per-use phone authorization can be removed.

## Target experience

The intended normal entry point is conceptually:

```console
age-plugin-phone setup --label "Work laptop"
```

The final command name and exact options require an implementation ADR, but the product behavior
must meet this goal:

1. Probe all supported-platform requirements before creating persistent state.
2. Resolve the platform-private configuration root and safe create-new state paths without asking
   the user to invent desktop, replay, locator, or identity-stub filenames.
3. Resolve exactly one transport through the existing transport policy. On the Windows Alpha path,
   `auto` selects Developer USB ADB; multiple online devices require an explicit `--adb-serial`.
4. Start the existing authenticated pairing protocol and require comparison and confirmation of the
   complete transcript fingerprint on both endpoints.
5. Commit the public identity stub, private locator, replay scope, TPM metadata, and role-separated
   TPM keys only through the existing fail-closed storage and protocol boundaries.
6. On success, print the public `age1phone...` recipient, the public identity-stub path, and concise
   standard-age next steps. Clearly state that pairing success is not a recovery drill.

The command may reduce path and command-line ceremony. It must not reduce user verification,
cryptographic binding, state isolation, or lifecycle visibility.

## Ownership boundary

`age-plugin-phone` owns this setup experience because it owns pairing, transport selection, desktop
TPM state, replay state, the private locator, and the public identity stub. A caller such as Shine
must not need to understand or reproduce those internals.

The result remains an ordinary standard age plugin identity:

- encryption uses the public `age1phone...` recipient;
- decryption uses the public identity stub through `identity-v1`;
- the long-term age private key remains in phone hardware;
- every file-key unwrap still requires fresh phone user verification; and
- compatible age clients and applications require no plugin-specific ciphertext or RPC.

The setup command must not edit Shine configuration, parse Shine workspaces, or emit a
Shine-specific identity format. Shine may continue to consume the resulting stub through its
existing `age_identity` and `age_recipients` settings without any pairing integration.

## Safety and lifecycle requirements

- Setup is create-only. It never overwrites or silently repairs an existing stub, replay scope,
  locator, TPM record, or CNG key.
- Unsupported Windows capabilities, missing StrongBox support, ambiguous ADB device selection,
  fingerprint rejection, cancellation, timeout, transport loss, and malformed state all fail
  closed.
- A failed or interrupted attempt must not expose a usable partial pairing. Any retained state must
  be exact, attributable to that attempt, unavailable for unwrap, and recoverable only through a
  bounded resume or cleanup path that does not guess targets.
- Retrying after a terminal pairing failure creates a fresh offer, identifiers, nonce, transcript,
  and confirmation. It never resumes an unconfirmed transcript as though it were approved.
- Convenience never introduces a desktop software identity, DPAPI, password, TOTP, weaker
  transport, automatic cross-transport retry, or cached authorization fallback.
- Labels, ADB serials, device names, and routes remain untrusted display or routing hints.
- Success output must warn that retained data needs an independently verified recovery recipient.
  The recovery path must not depend on the same phone StrongBox keys, paired Windows TPM keys,
  application state, locator, or replay scope.
- Revocation, identity deletion, phone replacement, re-pairing, and desktop cleanup remain explicit
  lifecycle operations. Setup does not imply that old ciphertext follows a new pairing.

## Non-goals

- Installing or updating the desktop executable, Android application, age client, ADB, or device
  drivers.
- Authorizing USB debugging, choosing silently among multiple devices, or treating ADB as trust.
- Generating, escrowing, selecting, or testing an independent recovery identity automatically.
- Combining pairing, encryption, decryption, revocation, or cleanup into one opaque operation.
- Adding a Shine dependency, configuration parser, RPC, URI, or custom ciphertext format.
- Claiming public-Alpha or production-secret readiness before the existing release gates close.

## Acceptance criteria

The goal is met only when all of the following are demonstrated:

- On a supported clean Windows Alpha host with exactly one authorized compatible phone,
  `age-plugin-phone setup --label LABEL` can complete a new pairing without user-supplied state
  paths while preserving full fingerprint comparison and phone confirmation.
- The resulting recipient encrypts through released standard age `recipient-v1`, and the resulting
  stub decrypts through standard `identity-v1` with a fresh strong biometric operation for every
  file-key unwrap.
- Existing Shine `age_identity` and `age_recipients` configuration can consume the output without a
  Shine code or ciphertext change.
- Multiple ADB devices fail before pairing state is created and provide an actionable explicit
  selection instruction; no device is selected by label or enumeration order.
- Cancellation, wrong fingerprint, phone rejection, timeout, process interruption, storage
  conflict, partial prior state, and transport failure produce no usable identity and no weaker
  retry path.
- Re-running setup never overwrites an existing pairing. A new pairing is distinct, while an
  interrupted owned attempt follows only its documented exact recovery or cleanup path.
- Portable CLI and state-machine tests, Windows-native TPM/storage tests, packaged-command smoke
  tests, and the applicable physical pairing/cancellation/interruption matrix all pass for one exact
  candidate artifact pair.
- User documentation distinguishes pairing success from recovery readiness and continues to limit
  the current owner-only preview to synthetic or disposable data.

## Delivery sequence

1. Write an ADR defining the command name, default path allocation, create/commit transaction,
   interruption semantics, safe output, and compatibility with the existing explicit `pair`
   command.
2. Implement the setup orchestrator by composing the existing capability probe, transport policy,
   pairing controller, Windows storage, and identity-stub boundaries rather than duplicating them.
3. Add negative portable and Windows-native coverage before physical testing.
4. Update the Windows quick start to use the simplified command while retaining the explicit form
   as a diagnostic or advanced path.
5. Validate the packaged command on the exact Windows/Android candidate and record only
   non-sensitive evidence in the Alpha matrix.
