# Threat model

## Security goals

- Copying desktop files or the plugin identity stub does not enable decryption elsewhere.
- A desktop process cannot obtain a long-term phone private key.
- Every private-key operation requires a fresh phone user-verification gesture.
- Cancellation, timeout, malformed input, transport loss, and unsupported capability fail closed.
- Captured requests and responses cannot be replayed or moved between paired desktops.
- Approval releases only the file key for one cryptographically bound age recipient stanza.

## Adversary capabilities

Assume an AI agent or same-user malware can invoke the plugin, read and modify user files, display a
QR code, use permitted BLE devices, and observe plaintext after the user approves decryption on the
compromised desktop.

In Developer USB mode, assume the ADB-authorized desktop can create, replace, observe, delay,
truncate, and replay loopback stream connections and can exercise unrelated broad ADB capabilities.
ADB authorization, serial numbers, connection state, and the USB cable provide no protocol trust.

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

The recovery path must not share the primary phone StrongBox keys or the paired Windows desktop TPM
keys. Phone replacement, paired-desktop revocation, application removal, identity deletion, and
hardware invalidation follow [`ADR 0017`](adr/0017-lifecycle-and-recovery.md). Without a recovery
recipient that was included when the data was encrypted, loss of either required version 2 hardware
key is unrecoverable by design.

## Prohibited shortcuts

- Returning the long-term identity to the desktop.
- Authorization windows such as "remember for ten minutes."
- DPAPI, Keychain, file-key, password, or TOTP fallback on transport failure.
- Trusting application labels, BLE pairing, or device names as authorization.
- Logging protocol payloads, recipient stanza bodies, file keys, or plaintext.
- Treating missing, corrupt, mismatched, or full replay state as an empty store.
- Treating ADB authorization, a selected serial, or a successful reverse connection as peer
  authentication or phone user authorization.
