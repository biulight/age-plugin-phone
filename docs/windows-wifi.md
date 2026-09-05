# Windows Wi-Fi setup and diagnosis

Use this with the [Windows quickstart](windows-alpha-quickstart.md). `wifi-doctor` and the
firewall helper are source-candidate additions after alpha.3; the published alpha.3 binary does
not contain that command. Use a matching newly built candidate for these checks, and keep its
executable path fixed. Do not mix results from different APKs or EXEs.

## Prepare the phone and network

1. Keep the intended phone application unlocked and in the foreground. If both the normal app and
   an isolated PoC are installed, open the one owning this pairing. Do not create a replacement
   identity to troubleshoot discovery.
2. For **new pairing**, tap **Pair · Wi-Fi** immediately before the desktop command. This opens a
   bounded, one-shot pairing listener. **Wi-Fi auto-listen** alone never accepts new pairings.
   For an **existing pairing**, enable **Wi-Fi auto-listen**, wait for its listening status, and
   use the corresponding public identity stub.
3. Connect both devices to the same trusted IPv4 subnet. Windows may use Ethernet to the phone's
   Wi-Fi LAN. A shared SSID alone is insufficient: guest/client isolation, VLANs and VPN routes can
   prevent broadcast or peer traffic. Check the phone's Wi-Fi details and Windows
   `Get-NetIPConfiguration`, `Get-NetIPAddress -AddressFamily IPv4`, and `Get-NetConnectionProfile`
   locally. Choose the physical LAN interface, not a VPN or virtual adapter.
4. Check whether the chosen Windows network is already **Private**. The helper refuses Public or
   Domain profiles; it never reclassifies a network. For managed networks, request an equivalent
   scoped rule from the administrator. Do not disable the firewall or endpoint protection.

## Check and configure discovery replies

Use PowerShell 5.1 or later from a source checkout or a newer Windows ZIP containing this guide and
the helper. Select the exact executable that will perform
discovery, including when invoked as an age plugin. If there are multiple PATH matches, resolve
the intended installation first:

```powershell
Get-Command age-plugin-phone.exe -All | Select-Object Source
$pluginExe = (Get-Command age-plugin-phone.exe -CommandType Application).Source
$lan = '<exact physical InterfaceAlias from Get-NetConnectionProfile>'
$helper = '.\scripts\windows-wifi-firewall.ps1'
& $helper -Action Inspect -Program $pluginExe -InterfaceAlias $lan
& $helper -Action Enable -Program $pluginExe -InterfaceAlias $lan -WhatIf
```

Inspect and `-WhatIf` do not require elevation. Review the printed executable, interface and rule
scope, then run the same Enable command without `-WhatIf` in an **administrator PowerShell**:

```powershell
& $helper -Action Enable -Program $pluginExe -InterfaceAlias $lan
& $helper -Action Inspect -Program $pluginExe -InterfaceAlias $lan
```

Reassign the same absolute executable/helper paths and interface alias in a new administrator
window. The helper supports `Get-Help $helper -Full`. It never changes execution policy; if your
organization disallows scripts, have an administrator review and deploy the rule through its
normal policy process.

The Windows ZIP places the helper beside the executable; when working from that extracted folder,
set `$helper = '.\windows-wifi-firewall.ps1'` instead of the source-checkout path above.

The rule allows **inbound UDP replies from remote port 47141**, only for the selected executable,
interface, Private profile and LocalSubnet; edge traversal is blocked. The local port is **Any**
because the desktop query socket uses a random ephemeral port. UDP local port 47141 would be the
wrong direction. The phone owns UDP 47141 and TCP 47140; Windows initiates TCP connections to the
phone, so this helper does not open an inbound desktop TCP listener. It assumes ordinary outbound
allow policy. If outbound policy is restricted, the administrator must review outbound discovery
UDP destination 47141 and phone TCP destination 47140 separately.

The deterministic rule name binds the executable path and interface. Repeating Enable does not
create duplicates. A conflicting existing definition is rejected rather than overwritten. Inspect
shows both stored scope and effective-policy status: presence alone does not prove packets are
allowed. Explicit block rules take precedence, and organizational policy may disallow local-rule
merging. See Microsoft's [rule parameters](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)
and [firewall rule policy](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules).

To temporarily undo or completely remove this exact allowance, use the same arguments:

```powershell
& $helper -Action Disable -Program $pluginExe -InterfaceAlias $lan -WhatIf
& $helper -Action Disable -Program $pluginExe -InterfaceAlias $lan
& $helper -Action Remove -Program $pluginExe -InterfaceAlias $lan
& $helper -Action Inspect -Program $pluginExe -InterfaceAlias $lan
```

Removal should report `Present=False`; repeat removal is harmless. Keep the old path and interface
for removal after moving/uninstalling the EXE. A new EXE location needs its own review and rule;
updating a binary in place retains the path-based allowance. Do not delete unrelated rules or use
a wildcard removal command.

## Isolate the failing stage

Run a discovery-only check with the same `$pluginExe` covered by the rule:

```powershell
# Phone is explicitly waiting in Pair · Wi-Fi:
& $pluginExe wifi-doctor
# Or: phone auto-listen is active for an existing pairing:
& $pluginExe wifi-doctor --identity-stub $identityStub
```

Each invocation runs one production three-second discovery window and prints only purpose, phase,
elapsed milliseconds, a result category and next action. Exit 0 means exactly one matching source;
nonzero means failure. Existing-pairing replies are verified under the phone signing key from the
selected public stub. Pairing discovery is unauthenticated. Neither result proves the phone has
authorized an operation. The check creates no desktop keys, pairing state or replay consumption,
does not send an unwrap request and does not connect TCP. It does not use transport environment
overrides or fall back to USB.

Do not use `Test-NetConnection -Port 47140`, telnet, or a port scanner against an active one-shot
listener: the test connection itself can consume it and cause a misleading failure/re-arm gap.
When ADB is already available, `adb shell ss -lntu` can inspect listening sockets without connecting;
look locally for UDP 47141 and TCP 47140. This may be unavailable on some Android versions and
does not establish which app owns a socket. Correlate it with the intended app's foreground status.

| Stage / result | Meaning and next action |
| --- | --- |
| `public_stub_unavailable` | Select an existing, valid public stub. Do not repair this by deleting replay or pairing state. |
| Discovery `no_matching_response` | No acceptable reply within the window. Check foreground and correct pairing/unwrap mode, same subnet and isolation, listener status, then effective firewall rule and EXE/interface match. Timeout alone is **not** evidence of a firewall fault. |
| Discovery `multiple_candidates` | Leave only the intended phone listener active and run a fresh check. Never select the first response. |
| Discovery `local_socket_unavailable` | Inspect Windows interfaces, routing, socket restrictions and endpoint-security policy. The check has not established phone reachability. |
| Discovery succeeds, TCP connect fails | Check whether the phone backgrounded, pairing listener expired, network changed, another connection consumed the listener, or outbound TCP was blocked. Start a fresh operation after the correct listener is ready. |
| Connected, but no valid response | Inspect phone cancellation, authentication timeout, background interruption or peer/protocol rejection. This is distinct from discovery and does not justify broadening the UDP rule. |
| Loading cleared, setup says a journal exists | Follow quickstart resume/cleanup rules. UI recovery does not erase uncertain desktop state; `--resume` is only for an already fully confirmed transcript. |

If `auto` quietly chooses USB, use explicit `wifi` for diagnosis. Its lack of a discovery response
is terminal rather than a fallback; after diagnosis return to the user's intended transport policy.
On cancellation/timeout/backgrounding, return to the foreground, wait for loading to clear and the
buttons to enable, then tap pairing again or start a **new** age decrypt. Each attempt needs a new
signed session and each unwrap needs fresh native phone verification. Never reuse a request or
delete replay state to make retry work. If loading remains stuck, record it as a UI failure rather
than declaring a firewall fault or passing the retry case after force-restarting the app.

## Bounded reproduction record

Use synthetic data only. Record the APK/EXE digests, source revision, rule state and whether the
phone was foreground/listening. At each of the following transitions run at most three fresh
discovery checks: immediately after full pairing completion; immediately after a successful,
owner-authorized decrypt; and after backgrounding then returning to foreground. Record time since
the transition as well as the command's elapsed time. If a check fails, inspect listener status
without a TCP probe, wait for the visible listening state, and run one fresh check; preserve the
failure row. Do not add automatic unwrap retries or lengthen deadlines based on one failure.

| Candidate | Transition / delay | Foreground / listener | Rule | Stage | Elapsed ms | Result / next step |
| --- | --- | --- | --- | --- | --- | --- |
| APK + EXE digest | pairing / decrypt / foreground | observed or unknown | absent / enabled / disabled | discovery / connect / response / UI recovery | measured | coarse error; unresolved when evidence is insufficient |

For a firewall comparison, keep the candidate, interface and phone mode fixed and compare absent
or disabled versus enabled rule state, then restore the original state. Repeated improvement with
the rule is evidence of a filtering contribution on that host, not an explanation for every
historical failure. Do not record packet payloads, QR contents, keys, plaintext, serials, private
state paths or key aliases. Full interface/IP details are local troubleshooting inputs, not public
acceptance-report content.
