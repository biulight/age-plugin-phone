# ADR 0019: unified desktop transport policy

- Status: accepted
- Date: 2026-09-01
- Scope: deterministic desktop selection of QR, Developer USB ADB, foreground Wi-Fi, and future BLE transports

## Context

ADR 0016 defines a bounded one-request/one-response stream boundary, but transport selection still
lives separately in the command-line pairing and unwrap paths and in the standard age identity
state machine. Adding BLE to those separate branches would let discovery, reconnect, and fallback
behavior define security-relevant request lifecycle semantics by accident.

Transport properties are not authentication inputs. Even so, selection controls which endpoint
receives a signed request and when a failed attempt may be retried. That behavior needs one small,
auditable policy before another convenience transport is added.

## Decision

The desktop library owns one transport policy with five user choices: `auto`, `adb`, `ble`, `wifi`,
and `qr`. The policy resolves a choice, operation purpose, platform default, and untrusted route
hints into exactly one concrete route before a pairing or unwrap protocol session is created.

The current capability matrix is:

| Transport | Pairing | Unwrap | Current status |
| --- | --- | --- | --- |
| Developer USB ADB | yes | yes | implemented; Windows `auto` default |
| QR | yes | yes | implemented; non-Windows `auto` default and offline fallback |
| foreground Wi-Fi | no | yes | implemented owner-only PoC; requires an explicit private IPv4 endpoint |
| BLE | reserved | reserved | unavailable until the separately gated native PoC exists |

`auto` is deterministic and performs no race:

1. conflicting route hints fail closed;
2. an explicit ADB serial selects ADB;
3. an explicit Wi-Fi endpoint selects Wi-Fi for unwrap only; and
4. without a route hint, Windows selects ADB and other desktop platforms select QR.

These are route and capability hints only. They do not authenticate a phone, authorize an unwrap,
or weaken the signed pairing and request verification above the transport. A future capability
probe may refine a route before the protocol session is created, but it must still produce one
selection or an error.

After resolution, one command attempt uses only the selected route. Once request transmission
begins, the implementation must not race another transport, switch transports, or silently retry.
Connection failure, malformed input, timeout, cancellation, lifecycle loss, and response failure
terminate that attempt. Retrying pairing or unwrap creates a fresh protocol session and therefore a
fresh signed offer or request, request identifier, nonce, expiry, and one-time session key.

The policy owns no sockets, cameras, discovery, protocol bytes, replay state, or authorization. The
existing transport implementations remain responsible for bounded exchange and cleanup; the
protocol controllers remain responsible for peer authentication, replay consumption, and fresh
phone user verification.

## Route-hint rules

- `adb` accepts only an optional ADB serial.
- `wifi` accepts exactly one Wi-Fi endpoint and is unwrap-only.
- `qr` accepts no route hint.
- `ble` accepts no route hint until its discovery and explicit-selection model is reviewed.
- `auto` accepts at most one transport-specific hint; a hint pins the single route rather than
  creating a fallback order.

Unknown choices, malformed route hints, and unsupported operations fail before persistent pairing
output, a signed request, or a phone authorization prompt is created.

## BLE entry criteria

The native BLE PoC must consume this policy rather than extend it inside the BLE controller. Its
separate review must define untrusted discovery, explicit phone selection, bounded fragmentation,
connection deadlines, cancellation, lifecycle cleanup, and fail-closed reconnect. Reconnect may
resume only transport establishment before request transmission; it may not replay or move an
in-flight protocol request to another connection or transport.

## Consequences

- CLI commands and the standard age identity state machine share one parser, capability matrix,
  route validation, and platform default.
- Adding a transport requires an explicit capability and policy update plus negative contract tests.
- `auto` initially preserves the existing Windows ADB and non-Windows QR behavior; it is not a
  best-effort fallback mechanism.
- BLE is visible as a reserved explicit choice and fails closed until a native implementation is
  reviewed and enabled.
