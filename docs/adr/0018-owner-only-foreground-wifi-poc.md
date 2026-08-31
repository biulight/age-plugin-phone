# ADR 0018: owner-only foreground Wi-Fi unwrap proof of concept

- Status: implemented for owner-only experimentation; not a production transport
- Date: 2026-08-31
- Scope: explicit one-shot Wi-Fi routing for unwrap only

## Context

Developer USB is reliable for the current technical preview but requires USB debugging, broad ADB
authorization, a cable, and platform-tools. The application is not being prepared for public use,
so a small owner-only experiment can test everyday LAN convenience before investing in discovery,
background delivery, BLE, or stable transport orchestration.

The experiment must not create a second pairing or authorization protocol. It must not turn an IP
address, LAN reachability, or successful TCP connection into a trust input.

## Decision

The Android application exposes an explicit **Approve · Wi-Fi** action. While the application
remains in the foreground, this action opens one listener on TCP port `47140` for at most 30
seconds and accepts at most one connection. Leaving the foreground, cancellation, timeout,
malformed input, peer loss, or completion closes the listener and any accepted socket.
The product UI explicitly explains that other actions are disabled while this one-shot operation
waits, and that an accepted peer remains bounded by the longer message and authorization timeouts.
An explicit **Cancel Wi-Fi listener** action replaces **Approve · Wi-Fi** in the same control slot
while the Wi-Fi operation owns the listener, an accepted socket, or its biometric prompt. Its
visibility is restored from the native operation state when the WebView becomes visible again;
it is not inferred only from one JavaScript invocation. Cancellation closes those exact resources,
returns `user_cancelled`, and never restores a consumed request or starts a retry. The disabled
controls must not look like an unexplained application freeze.

The dedicated `android:build:wifi-poc` build path combines `tauri.wifi-poc.conf.json` with a guarded
Gradle switch that adds the `.wifipoc` application-ID suffix, so its debug APK can be installed
beside the signed owner-preview application. The separate
Android UID also gives the experiment separate app storage and Keystore state. Testing must never
uninstall or overwrite the signed application merely to change signing certificates. The PoC APK
is built only through `bun run android:build:wifi-poc`; an ordinary debug build retains the normal
application ID and must not be installed over a differently signed preview.

The desktop connects only when the caller explicitly selects `wifi` and supplies a numeric private
or link-local IPv4 `IP:47140` endpoint. Hostnames, DNS, discovery, public addresses, IPv6, alternate
ports, `auto`, fallback, racing, reconnect, and silent retry are out of scope. Pairing over Wi-Fi is
also out of scope; an existing ADB or QR pairing is reused unchanged.

The TCP connection carries the version 1 common stream frame from ADR 0016: one opaque signed
unwrap request and one opaque encrypted response, each bounded to 65,536 bytes and bound to a
random transport session ID, purpose, and direction. The stream header is not authentication.

Android passes the complete request directly to the existing native unwrap controller. The
controller must verify the paired desktop, request signature, request digest, identity, stanza,
nonce, expiry, and replay scope and must durably consume the request before it constructs the
auth-per-use StrongBox operation or presents `BiometricPrompt`. The response remains signed,
request-bound, encrypted to the desktop's one-time session key, and durably replay-consumed on the
desktop before release to age.

While authentication is pending, EOF, reset, timeout, or any additional desktop byte terminates
the operation and cancels the exact `CancellationSignal` without restoring the consumed request.
No route property is displayed as authenticated identity.

The standard age plugin selects the experiment only with both:

```text
AGE_PLUGIN_PHONE_TRANSPORT=wifi
AGE_PLUGIN_PHONE_WIFI_ADDRESS=192.168.1.20:47140
```

`AGE_PLUGIN_PHONE_ADB_SERIAL` must be absent. The direct diagnostic `unwrap` command uses
`--transport wifi --wifi-address 192.168.1.20:47140`. The phone action must be started first and
must remain visible. A failed attempt is terminal; retrying invokes age again and creates a fresh
protocol request.

## Consequences

- The PoC removes the cable and ADB requirement for one foreground unwrap without changing key
  custody, pairing, replay, response verification, or user authorization.
- The side-by-side debug application has an independent identity and must be paired separately. Its
  results do not transfer to the signed owner-preview application.
- Any LAN peer may connect first, send malformed traffic, or prevent the owner from connecting.
  Strict parsing prevents authorization, but denial of service remains expected.
- There is no discovery, authenticated route establishment, background listener, cold start,
  notification, service, wake lock, automatic selection, or production support claim.
- Binding a wildcard listener is acceptable only for this short-lived owner-only experiment. A
  production design must separately evaluate interface binding, LAN isolation, discovery privacy,
  Android lifecycle restrictions, and response routing.
- The current public-Alpha matrix and protocol-freeze gates are unchanged. Wi-Fi results do not
  satisfy ADB or QR evidence rows.

## Validation

Portable Rust tests cover explicit private-address and fixed-port validation, one-shot exchange,
wrong transport session binding, disconnect, and terminal reuse. Kotlin tests cover a real
one-shot TCP listener, bounded request/response framing, cancellation of a blocked listener and an
accepted socket, port release, wrong
purpose/direction/session/version, oversize, truncation, EOF, and unexpected post-request input.
The existing protocol and state-machine tests continue to cover wrong desktop, wrong identity,
replay, expiry, cancellation, malformed request, failed persistence, and bad response.

On 2026-08-31, the exact `3ff2cea` Windows source and the side-by-side `.wifipoc` Android debug build
completed a physical private-LAN unwrap through reference age. The phone presented a fresh strong
biometric operation, the returned response decrypted the synthetic ciphertext, and the resulting
SHA-256 matched both the source plaintext and a separately verified independent-recovery decrypt:
`C658D6436354B65450AFE7C1A4EF72BF250965CFFCAC972CFAFCB9FF16463AFF`.

The physical run also confirmed that a recipient from an earlier pairing does not match a later
pairing's public stub, and that mismatched one-sided pairing state produces no plaintext. The test
therefore re-encrypted the disposable plaintext to the fresh pairing-bound phone recipient plus
the unchanged independent recovery recipient before the successful Wi-Fi unwrap. No discovery,
background, reconnect, fallback, or production-transport claim follows from this result.
