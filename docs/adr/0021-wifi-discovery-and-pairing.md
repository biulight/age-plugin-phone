# ADR 0021: pairing-scoped Wi-Fi discovery and explicit Wi-Fi pairing

- Status: source implemented; initial Android/Windows debug validation passed; full matrix pending
- Date: 2026-09-03
- Scope: foreground Wi-Fi endpoint discovery, Wi-Fi-first `auto`, local route preference, and one-shot pairing

## Context

ADR 0018 required users to copy the phone's private IPv4 address into
`AGE_PLUGIN_PHONE_WIFI_ADDRESS`. ADR 0019 consequently selected Wi-Fi only when that explicit route
hint was present. This made the foreground listener usable as a proof of concept but unsuitable as
the normal Shine or standard-age flow.

The managed setup `--transport` option also selected only that setup command's route. Shine saved
the resulting public identity path, but later standard-age invocations had no per-pairing transport
preference. Finally, Wi-Fi pairing was prohibited even though pairing offers and responses already
use the same authenticated common stream boundary as unwrap.

Discovery and route preference remain convenience state. They must not become peer authentication,
phone authorization, or input to any signed pairing or unwrap message.

## Decision

### Fixed discovery exchange

The desktop sends a bounded IPv4 UDP broadcast to port `47141` before it creates a pairing offer or
unwrap request. It always targets `255.255.255.255`; on Windows it also derives and targets the
directed broadcast for every active private or link-local IPv4 interface with a valid subnet mask.
This prevents a VPN or virtual default route from swallowing discovery on a multi-homed desktop.
Failure to enumerate interfaces retains the limited-broadcast target. It retransmits the same query
every 200 milliseconds for a total 900-millisecond window and accepts only private or link-local
IPv4 response sources. The discovered TCP endpoint always uses the existing fixed port `47140`.

A query is exactly 72 bytes:

| Field | Bytes | Rule |
| --- | ---: | --- |
| magic | 4 | ASCII `APWD` |
| version | 2 | unsigned big-endian `1` |
| kind | 1 | query `1` |
| purpose | 1 | pairing `1` or unwrap `2` |
| nonce | 32 | fresh desktop randomness |
| desktop ID | 16 | target desktop or proposed pairing desktop |
| identity ID | 16 | target identity; all zero for pairing |

Unknown versions, kinds, purposes, lengths, fields, and non-zero pairing identity IDs are ignored.
The phone sends the response only to the query's source address and port; it does not continuously
advertise a stable phone service or name.

An unwrap discovery response is exactly 136 bytes. Its first 72 bytes repeat the query with kind
`2`, followed by a 64-byte compact low-S P-256 ECDSA signature over:

```text
"age-plugin-phone/wifi-discovery-response/v1" || 0x00 || response-prefix
```

The phone opens the exact app-private pairing state named by the query before signing with the
corresponding non-exportable StrongBox phone-signing key. The desktop verifies the response against
the phone-signing public key in the selected public identity stub. Invalid, wrong-pairing, replayed,
or forged responses cannot select a route. Discovery signing does not require or cache user
verification and never unwraps a file key.

UDP retransmits repeat the exact same 72-byte query. The foreground responder strictly parses every
copy but invokes StrongBox only for the first copy, retaining one in-memory public signed response
for that exact query. A different nonce, purpose, desktop ID, identity ID, or any other byte replaces
the cache and requires normal parsing and signing. Closing the responder clears the cached query and
response. This bounds normal discovery to one StrongBox signature without caching authorization,
agreement output, a file key, or decrypted plaintext.

The query exposes random pairing identifiers to an observing LAN peer. Those identifiers are not
keys or authorization secrets and already occur in authenticated application messages, but this is
still linkable metadata during the short discovery window. A later privacy revision may replace
them with a blinded selector; it must retain strict parsing and exact-pairing response behavior.

### Route resolution

Exactly one authenticated matching unwrap source selects Wi-Fi. More than one matching source is
ambiguous and fails closed. For explicit `wifi`, no response, ambiguity, or discovery failure is
terminal. For `auto`, no matching response preserves the existing platform default: Developer USB
ADB on Windows and QR elsewhere. Ambiguity and local discovery-socket failure remain terminal rather
than silently selecting a different route.

An explicit ADB serial continues to pin ADB. An explicit
`AGE_PLUGIN_PHONE_WIFI_ADDRESS` or diagnostic `--wifi-address` continues to pin that address for
compatibility and diagnostics, but it is no longer required in the normal flow.

Discovery finishes before `DesktopUnwrapSession::begin` or `DesktopPairingSession::begin`. Once a
signed offer or unwrap request exists, the selected attempt does not race, switch, reconnect, or
silently retry another transport or address.

### Per-pairing preference

Private pairing locator version 3 adds one canonical transport choice. Managed setup journal
version 2 records the same choice before TPM state creation so interruption, resume, and commit
cannot silently change it. Existing locator version 2 and setup-journal version 1 decode as `auto`;
no protocol message, key, replay scope, public identity stub, or ciphertext is migrated.

Without `AGE_PLUGIN_PHONE_TRANSPORT`, the standard age identity state machine uses the selected
pairing's private preference after private stanza selection and before request creation. An explicit
environment value remains a diagnostic override. Therefore:

- `--transport wifi` persists Wi-Fi-only discovery for later unwraps;
- `--transport auto` persists Wi-Fi-first discovery with the unchanged no-response platform default;
- `adb` and `qr` remain explicit single-route preferences; and
- `ble` remains unavailable.

The preference is not signed and is not an authentication input. Same-user modification may change
availability or select another untrusted delivery route, but the application protocol still rejects
the wrong phone or response.

### Explicit Wi-Fi pairing

The Android product UI adds **Pair · Wi-Fi**. This local action pauses the passive unwrap listener
and opens one foreground, bounded TCP pairing listener plus the UDP discovery responder. The
ordinary persistent Wi-Fi auto-listen mode remains unwrap-only and cannot create an identity or
pairing from unsolicited LAN traffic.

Because no phone key is trusted before pairing, the 72-byte pairing discovery response is not
signed. The desktop requires exactly one candidate address. It then sends the existing signed
pairing offer through the common stream with purpose `pairing`; the phone returns the existing
StrongBox-signed pairing response. Both endpoints still display and require confirmation of the
complete transcript fingerprint before state is committed. A forged discovery response can cause
denial of service or route the offer to the wrong phone, but cannot complete or substitute a
pairing.

`setup --transport wifi` uses only this explicit phone mode. `setup --transport auto` probes it
first and, when no phone is in Wi-Fi pairing mode, performs the existing platform-default setup
preflight. No fallback occurs after an offer is created.

## Consequences

- Normal standard-age and Shine unwraps no longer require a manually copied Wi-Fi address.
- `auto` uses foreground Wi-Fi when the matching phone is reachable and otherwise retains the
  current platform default before protocol work begins.
- LAN discovery can reveal short-lived pairing metadata and remains vulnerable to denial of
  service. It does not weaken paired-device authentication, replay consumption, response binding,
  or fresh auth-per-use biometric approval.
- Wi-Fi pairing removes the ADB and camera requirement but still requires a local phone action and
  two-ended transcript comparison.
- Broadcast delivery, Android foreground lifecycle, network transitions, and packaged Windows
  behavior require physical validation before this becomes a production transport claim.

## Validation

Portable Rust tests cover canonical query/response bytes, paired-key signature enforcement,
wrong-key and modified-query rejection, endpoint validation, route policy, legacy locator defaults,
and standard protocol/state-machine behavior. Kotlin tests cover strict query parsing, purpose and
length rejection, compact low-S response signatures, and signature verification. Existing stream,
pairing, cancellation, replay, wrong-device, malformed-request, and biometric tests remain in
force.

An isolated physical debug run on 2026-09-03 used Windows 11 build 22631 and a StrongBox-qualified
Samsung Android phone. It passed explicit `wifi` pairing, `auto` pairing while Developer USB was
also connected, authenticated 136-byte paired discovery, and standard-age unwraps for both saved
preferences without either transport environment variable. Both recovered synthetic files matched
their inputs byte for byte. The run also exposed a local fixed-port handoff race when **Pair ·
Wi-Fi** preempted an enabled auto-listener; a bounded pre-discovery bind handoff fixed it, and the
repeated `auto` pairing passed. A confirmation-page label that incorrectly named every stream
response Developer USB was also corrected to identify Wi-Fi.

A follow-up on the same NUC found an intermittent `DiscoveryUnavailable` after USB removal despite
an enabled foreground auto-listener. The NUC had both a ZeroTier default route and a physical
`192.168.50.0/24` LAN. A directed `192.168.50.255` probe reached the phone at `192.168.50.111`;
repeated probes then exposed both a 30-second Android accept timeout followed by a one-second listener
re-arm gap and repeated StrongBox signing for copies of one UDP query. Windows discovery now covers
every eligible local subnet, the passive foreground Android accept remains armed until lifecycle
cancellation, and exact retransmits reuse one public signed response. After reinstalling the isolated
`.wifipoc` build, 12 consecutive three-second signed discovery windows passed across the old timeout
boundary. A real `shine env secret decrypt TEST_SECRET` returned `test123` with `adb` deliberately
absent from `PATH`, proving that the saved `auto` pairing completed through Wi-Fi.

The remaining physical matrix includes discovery on Windows and Android, no listener, wrong and
multiple phones, hostile first connection, backgrounding, network change, pairing cancellation,
unwrap cancellation, timeout, replay, and a fresh user-initiated recovery attempt through ADB.
