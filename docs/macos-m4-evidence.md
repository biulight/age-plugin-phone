# macOS M4 transport implementation and remaining gates

Date: 2026-09-09. This independent M4 preparation follows M1/M2 and does not
declare the M4 phone/transport/caller acceptance matrix complete.

## Implemented

- The platform package takes a new `getifaddrs` snapshot for each discovery attempt.
  Only active, running, broadcast-capable IPv4 interfaces are returned; loopback
  and point-to-point interfaces (including typical VPN tunnels) are excluded.
  Darwin compact netmasks are zero-extended without reading beyond their advertised
  length. The earlier full-structure length check incorrectly discarded these interfaces.
  Native list ownership and pointer checks remain outside the unsafe-free desktop.
- Desktop derives and deduplicates broadcasts per interface for RFC1918 subnets,
  excluding self-assigned link-local addresses from automatic discovery. Both subnet
  and limited broadcasts use separate source-address sockets and `IP_BOUND_IF` for
  the enumerated interface; replies are polled in rotation and the binding
  is cleared before reception, including after a failed send. Explicit link-local
  routes remain supported. No interface-specific address is hardcoded. Invalid masks and /31 or /32 point-to-point/host
  routes do not produce a subnet broadcast. Interface addresses remain untrusted
  route hints, and no protocol, discovery signature or phone authorization changes.
- Enumeration errors, send errors on any destination, and short sends terminate
  discovery. Success on another interface cannot hide a permission or route error
  as an absent listener. This stricter send rule also applies to Windows; Windows
  native enumeration itself is unchanged. It can reduce availability when a route
  disappears during an attempt; a user retry takes a fresh snapshot.
- macOS `status` distinguishes compiled implementation from unverified hardware,
  camera and local-network permissions. It opens no keys or cameras and performs
  no discovery. It explicitly retains experimental status and the M2 rollback gate.

## Checks

On the current M0 host, automated tests cover null/short/wrong-family native
addresses, byte order, interface flags, native enumeration, multiple subnets,
interface-scoped deduplication, link-local exclusion, native binding cleanup after successful
and failed loopback sends, changed snapshots, invalid masks, partial send failure, permission
denial, disappearing routes, short sends and empty destination sets. Existing
discovery authentication, replay, ambiguity, timeout, cancellation, wrong-device,
malformed-message and stream-disconnect tests remain enabled.

The complete workspace suite passed outside the sandbox after the initial run
could not bind existing loopback sockets or create a process group. The failure
was environmental and was not counted as a pass. Native Secure Enclave tests stay
explicitly ignored in this ordinary suite; no phone operation was performed.
Formatting, all-target Clippy with warnings denied, and `git diff --check` pass.
The existing `block 0.1.6` future-compatibility notice remains.

## Still required

- Actual Wi-Fi + Ethernet, VPN routing and interface removal during discovery;
  synthetic snapshots do not certify those physical configurations.
- Terminal and GUI age/rage caller chains, local-network permission denial and
  revocation on the exact installed artifact. A timeout alone cannot diagnose TCC.
- Built-in and UVC cameras, first permission grant/denial/revocation, occupancy,
  cancellation and timeout; usage description and caller permission attribution.
- Android ADB device authorization, multiple devices, unplugging, daemon restart,
  termination cleanup and phone launch/lifecycle tests. iOS has no ADB support.
- Fresh phone verification and no plaintext on every negative path in the declared
  phone/transport/caller combinations. These require user-performed phone approval
  and fingerprint comparison; automation cannot replace them.

M3 managed setup now has [separate implementation evidence](macos-m3-evidence.md).
Normal/orphaned cleanup now also has M3 implementation evidence. M5 extracted-archive
installation and M6 precise artifact acceptance/security review remain separate work.
