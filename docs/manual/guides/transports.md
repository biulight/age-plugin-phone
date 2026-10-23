---
title: "Choose a connection"
sidebar_position: 1
---

# Choose a connection

Choose one route before starting. Every route still requires full fingerprint comparison for pairing and fresh native phone verification for each unwrap.

| Route | Before pairing | Before decrypting |
| --- | --- | --- |
| Developer USB (`adb`) | Android only: start desktop setup, then tap **Pair · USB** | Connect and authorize ADB; the desktop launches the native phone approval flow |
| Foreground Wi-Fi (`wifi`) | Tap **Pair · Wi-Fi** first, then start desktop setup | Enable **Wi-Fi auto-listen** and keep the app visible |
| QR (`qr`) | Select QR explicitly; scan the desktop offer on the phone, then the phone response with the desktop camera | Scan the age request on the phone and its response on the desktop; experimental |

## Developer USB

```sh
adb devices -l
age-plugin-phone setup --label "Test laptop" --transport adb
```

The phone's pairing action makes one immediate connection attempt. Choosing it before desktop setup is ready can produce `usb_transport_failed`. With multiple devices, add `--adb-serial SERIAL` to setup and set `AGE_PLUGIN_PHONE_ADB_SERIAL` for subsequent age calls. Do not combine ADB selection with a Wi-Fi address override.

ADB access is broader than this app needs. Use it only on a computer you intend to authorize. Neither the cable nor ADB authorization approves decryption.

## Foreground Wi-Fi

Connect both devices to a reachable local IPv4 network. On the phone, tap **Pair · Wi-Fi**, then run:

```sh
age-plugin-phone setup --label "Test laptop" --transport wifi
```

Compare the full fingerprint on both ends. For later decryption, enable **Wi-Fi auto-listen** and keep the app in the foreground. Auto-listen does not accept new pairings. It starts disabled and remembers the opt-in. Pausing it closes a pending connection or verification; it does not retry the request. No background wake is provided.

A pairing created with `--transport wifi` remembers Wi-Fi-only routing. Discovery normally needs no address setting. Use [Wi-Fi diagnostics](../troubleshooting.md#wi-fi) if discovery fails; a timeout alone does not prove a firewall problem.

## Automatic routing and manual overrides

`setup` defaults to `auto`. Without explicit route hints, it first performs bounded Wi-Fi discovery. Exactly one eligible listener selects Wi-Fi; no listener selects ADB on Windows and QR on macOS. Ambiguous replies or discovery errors stop the attempt. After sending begins, the plugin never races, switches, or silently retries another route.

For standard age decryption, an environment override takes precedence over the pairing's saved route. To try QR with an existing pairing in PowerShell:

```powershell
$env:AGE_PLUGIN_PHONE_TRANSPORT = "qr"
age -d -i "<identity-stub-path>" -o recovered.txt example.age
Remove-Item Env:AGE_PLUGIN_PHONE_TRANSPORT
```

Or for one macOS invocation:

```sh
AGE_PLUGIN_PHONE_TRANSPORT=qr age -d -i '<identity-stub-path>' -o recovered.txt example.age
```

Clear conflicting `AGE_PLUGIN_PHONE_ADB_SERIAL` or `AGE_PLUGIN_PHONE_WIFI_ADDRESS` overrides first. QR changes only the connection, not the pairing. Camera access must work in the actual caller; a Terminal success does not prove GUI permissions. QR/tag physical coverage remains incomplete. `ble` is accepted as a reserved option but fails as unavailable.
