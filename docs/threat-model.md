# Threat model

## Security goals

- Copying desktop files or the plugin identity stub does not enable decryption elsewhere.
- A desktop process cannot obtain a long-term phone private key.
- Every unwrap using the phone identity key requires a fresh phone user-verification gesture.
- Cancellation, timeout, malformed input, transport loss, and unsupported capability fail closed.
- Captured requests and responses cannot be replayed or moved between paired desktops.
- Approval releases only the file key for one cryptographically bound age recipient stanza.

The separate phone-signing key authenticates protocol and discovery messages without requiring or
caching identity authorization. It cannot unwrap an age file key or replace the fresh verification
required by the identity key.

## Adversary capabilities

Assume an AI agent or same-user malware can invoke the plugin, read and modify user files, display a
QR code, use permitted BLE devices, and observe plaintext after the user approves decryption on the
compromised desktop.

In Developer USB mode, assume the ADB-authorized desktop can create, replace, observe, delay,
truncate, and replay loopback stream connections and can exercise unrelated broad ADB capabilities.
ADB authorization, serial numbers, connection state, and the USB cable provide no protocol trust.
Developer USB is unavailable on iOS: it is absent from the product UI and its native command fails
closed with `unsupported_transport`.

In the owner-only foreground Wi-Fi experiment, assume any LAN peer can discover or reach the fixed
port, connect first, impersonate an address, observe, replace, delay, truncate, inject, and replay
stream bytes, or disconnect while authorization is pending. IP addresses, private-address routing,
interface choice, and TCP connection success provide no protocol trust. Such a peer may deny
service but must not reach a biometric prompt without a valid signed request from the paired
desktop. Enabling foreground auto-listen expresses transport availability only; it is not cached
authorization. Automatic re-arming lets an attacker repeat connection-level denial of service, and
a compromised paired desktop may repeatedly present valid requests, but every unwrap still needs a
fresh auth-per-use system verification.

Assume the same LAN peer can observe pairing identifiers in short-lived Wi-Fi discovery queries and
can forge, suppress, replay, or multiply discovery packets. An existing-pairing route is selected
only after a nonce-bound response verifies under the paired phone-signing key. Pre-pairing discovery
has no trusted phone key and therefore provides availability only: a forged response may redirect or
deny service, but the signed pairing response and complete transcript comparison must still prevent
an incorrect pairing from being committed. The persistent unwrap listener never accepts pairing.

The phone operating system, hardware-backed key implementation, and user-verification UI are trusted
within their documented guarantees.

## Explicit non-goals

The design does not protect against:

- user approval of a deceptive or unexpected request;
- desktop administrator, kernel, debugger, or process-memory compromise after approval;
- phone operating-system or secure-hardware compromise;
- plaintext leakage by the application that requested decryption; or
- denial of service, prompt flooding, phone loss, or battery exhaustion.

Rate limiting and clear phone UI reduce prompt flooding and misapproval but cannot eliminate them.

## Recovery

There is no server-side recovery in the offline design. Users must encrypt important data to at
least one independent recovery recipient, such as a second phone, Secure Enclave identity, hardware
token, or offline age identity. Replacing a phone requires decrypting with that recovery recipient
and resealing to a newly generated phone recipient.

The recovery path must not share the primary phone hardware keys or the paired desktop TPM/Secure Enclave
keys. Phone replacement, paired-desktop revocation, application removal, identity deletion, and
hardware invalidation follow [`ADR 0017`](adr/0017-lifecycle-and-recovery.md). Without a recovery
recipient that was included when the data was encrypted, loss of either required version 2 hardware
key is unrecoverable by design.

On iOS, also assume the WebView, camera input, LAN peers, lifecycle events, and caller labels are
hostile. Secure Enclave references, raw QR contents, protocol payloads, stanzas, and file keys remain
inside the Swift native boundary. Every unwrap uses a fresh LocalAuthentication context.
Biometric-set invalidation, protected-storage failure, replay-state uncertainty, and clock rollback
make the operation unavailable instead of creating a fallback key or replay scope.

## Explicit tag privacy and selection

The optional native `age1tag` mode exposes a publicly testable four-byte stanza selector. Anyone
who knows the recipient can check whether a ciphertext may target it. The default phone v2 mode
retains private selection. Tag collision is possible and provides no authorization: multiple distinct
matching configured keys fail before private state is opened, and even a single match must pass
HPKE authentication, fresh phone verification, complete signed-response checks and durable replay.

Duplicate pairings for one phone key use the first input pairing. Its missing state, cancellation,
timeout or cryptographic failure never selects another pairing or recipient mode. Phone v2 binds
ciphertext to its paired desktop; tag ciphertext can be accessed through another explicitly
confirmed pairing to the same phone key. Neither changing recipients nor revoking a pairing
retroactively erases plaintext or historical ciphertext access. See [ADR 0026](adr/0026-native-tagged-recipients.md).

## Prohibited shortcuts

- Returning the long-term identity to the desktop.
- Authorization windows such as "remember for ten minutes."
- DPAPI, Keychain, file-key, password, or TOTP fallback on transport failure.
- Logging protocol payloads, recipient stanza bodies, file keys, or plaintext.
- Treating missing, corrupt, mismatched, or full replay state as an empty store.
- Trusting caller labels, device names, BLE pairing, ADB authorization, selected serials, reverse
  connections, LAN addresses, private subnets, Wi-Fi association, TCP connections, or enabled
  foreground listeners as peer authentication or phone user authorization.

## Desktop replay persistence and restore boundary

Windows and macOS retain response consumption across supported ordinary failures
and restarts and reject missing, corrupt, mismatched, full or uncertain state. Neither
currently promises detection of an older valid same-machine replay file or filesystem
snapshot restored by a same-user attacker. ACLs, atomic replacement, backup exclusion
and TPM/Secure Enclave key custody do not supply an independent freshness authority.

This exception is limited to desktop store freshness. Same-user invocation and file
modification remain adversary capabilities. Old responses must still fail against a
fresh session's complete cryptographic binding; each new phone identity operation
requires fresh native verification. Phone request consumption before prompting and
retention on cancellation/failure remain required. No state reset, replay-based
recovery, software-key fallback or authorization cache is permitted.

The user approved this common boundary on 2026-09-10. Stronger restore resistance is
a deferred [cross-platform POC](desktop-replay-rollback-poc.md), not a Mac-only current
acceptance gate. The Mac store counterexample remains real; the analogous Windows
limitation is based on implementation inspection pending native reproduction. This
is not evidence of an end-to-end biometric bypass or completion of other security gates.
