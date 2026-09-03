# ADR 0018: owner-only foreground Wi-Fi unwrap proof of concept

- Status: implemented for owner-only experimentation; not a production transport
- Date: 2026-08-31
- Scope: opt-in foreground Wi-Fi auto-listen routing for unwrap only

> Historical PoC decision. ADR 0021 supersedes its explicit-address, no-discovery, no-`auto`, and
> no-Wi-Fi-pairing limitations while retaining the foreground-only listener, untrusted-route, and
> fresh-per-unwrap authorization boundaries.

## Context

Developer USB is reliable for the current technical preview but requires USB debugging, broad ADB
authorization, a cable, and platform-tools. The application is not being prepared for public use,
so a small owner-only experiment can test everyday LAN convenience before investing in discovery,
background delivery, BLE, or stable transport orchestration.

The experiment must not create a second pairing or authorization protocol. It must not turn an IP
address, LAN reachability, or successful TCP connection into a trust input.

## Decision

Every Android build exposes a persistent, default-off **Wi-Fi auto-listen** mode. The setting is a
versioned app-private value under `noBackupFilesDir`; missing, malformed, unreadable, or restored
state means disabled. Enabling it expresses transport availability only and never counts as user
authorization.

While enabled and the application remains in the foreground, Android owns at most one listener,
accepted socket, verified request, or response on TCP port `47140`. A 30-second accept timeout is
an internal lifecycle bound rather than a terminal user operation. Timeout, malformed input, peer
loss, cancellation, authentication failure, or completion closes the exact resources and re-arms
after at least one second while the mode remains enabled and foregrounded. Listener bind failures
back off for 1, 2, 4, 8, 16, then at most 30 seconds. Leaving the foreground immediately closes the
listener, accepted session, or matching biometric operation and prevents re-arming until the
application becomes visible again.

The product UI replaces **Approve · Wi-Fi** with **Enable · Wi-Fi auto-listen** / **Pause · Wi-Fi
auto-listen** and a coarse read-only state. Pausing first persists the disabled state and then
cancels the exact listener, socket, response, or biometric operation; a consumed request is never
restored. USB wake and explicit local actions may preempt a passive listener before it accepts a
connection. An accepted session, durably consumed request, or response cannot be implicitly
preempted; it must terminate through its own result, explicit pause, transport loss, or lifecycle
loss. Local operations temporarily suspend the listener and it re-arms afterward if still enabled.

The dedicated `android:build:wifi-poc` build path combines `tauri.wifi-poc.conf.json` with a guarded
Gradle switch that adds the `.wifipoc` application-ID suffix, so its debug APK can be installed
beside the signed owner-preview application. The separate
Android UID also gives the experiment separate app storage and Keystore state. Testing must never
uninstall or overwrite the signed application merely to change signing certificates. The PoC APK
is built only through `bun run android:build:wifi-poc`; an ordinary debug build retains the normal
application ID and must not be installed over a differently signed preview. Auto-listen is
available in both paths; the suffix isolates experimental storage and signing rather than enabling
the transport.

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
`--transport wifi --wifi-address 192.168.1.20:47140`. Auto-listen must be enabled and the phone app
must remain visible. Re-arming never retries a desktop protocol request or switches transport; a
failed desktop attempt is terminal, and invoking age again creates a fresh protocol request.

## Consequences

- The PoC removes the cable and ADB requirement for foreground unwraps without changing key
  custody, pairing, replay, response verification, or user authorization.
- The side-by-side debug application has an independent identity and must be paired separately. Its
  results do not transfer to the signed owner-preview application.
- Any LAN peer may connect first, send malformed traffic, or prevent the owner from connecting.
  Strict parsing prevents authorization, but automatic re-arming permits repeated denial of
  service and remains expected. A paired-desktop compromise may prompt-flood, but cannot bypass a
  fresh auth-per-use biometric operation.
- There is no discovery, authenticated route establishment, background listener, cold start,
  notification, service, wake lock, automatic selection, or production support claim.
- Binding a wildcard listener is acceptable only for this short-lived owner-only experiment. A
  production design must separately evaluate interface binding, LAN isolation, discovery privacy,
  Android lifecycle restrictions, and response routing.
- The current public-Alpha matrix and protocol-freeze gates are unchanged. Wi-Fi results do not
  satisfy ADB or QR evidence rows.

## Validation

Portable Rust tests cover explicit private-address and fixed-port validation, one-shot exchange,
wrong transport session binding, disconnect, and terminal reuse. Kotlin tests cover persistent
default-off state, foreground lifecycle delivery, a real one-shot TCP listener, bounded
request/response framing, cancellation of a blocked listener and an accepted socket, port release, wrong
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

On 2026-09-01, source commit `503f0e8add7850557208f7f1055e6432e7c68626` and the installed
side-by-side `.wifipoc` base APK with SHA-256
`EE8C0D6B1F63D83749E4AC8E01C98A5127EA6C89B0D0F76702343249043A17E3` completed the
foreground auto-listen continuation on the same Samsung test phone. The persisted mode remained
off until explicitly enabled, released port `47140` when backgrounded or paused, and resumed after
the application returned to the foreground. An empty LAN connection produced no biometric prompt
and the single listener re-armed. Two consecutive reference-age Wi-Fi unwraps, without toggling the
mode between them, each required a new system biometric operation and produced the same synthetic
plaintext SHA-256 recorded above. Cancelling a third biometric operation produced no output and
the listener re-armed without restoring that request.

Supporting physical checks confirmed that a Developer USB request suspended the passive listener,
completed only after a fresh biometric operation, and then allowed auto-listen to resume. Because
the packaged desktop USB wake intentionally names the normal signed application, this side-by-side
check used a test-only desktop binary whose sole routing change named the `.wifipoc` component; it
is not packaged-candidate USB evidence. Entering the native QR scanner likewise suspended the
listener, and cancelling returned `user_cancelled` before auto-listen resumed. The Windows test
instance had no camera, so a real desktop QR unwrap ended at its five-minute capture deadline with
no plaintext rather than completing a QR round trip.

The differently signed normal application was not uninstalled or replaced. Android rejected an
attempt to install the current ordinary debug APK over that package because the signatures differ.
The continuation therefore validates the side-by-side owner PoC and its shared source, but it does
not claim exact signed-normal-package, camera-complete QR, discovery, background service, or
production transport evidence.
