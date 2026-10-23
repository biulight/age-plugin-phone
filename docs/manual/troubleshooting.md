---
title: "Troubleshooting"
sidebar_position: 6
---

# Troubleshooting

Start with read-only checks and preserve pairing state. Do not delete keys, replay files, pending markers, or journals to make a failed operation work.

## age cannot find the plugin

Check `age-plugin-phone --version` in the caller's environment. The executable must retain the name `age-plugin-phone` (`age-plugin-phone.exe` on Windows). Reopen the terminal after changing `PATH`; check GUI callers separately. Confirm that the public stub is supplied with `-i`, not `-R`.

## Hardware or phone verification is unavailable

Run `age-plugin-phone status`. Recheck [platform prerequisites](support.md) and the phone app's hardware identity status. A supported OS alone does not establish TPM/StrongBox/Secure Enclave availability. Do not replace hardware keys with software keys. Unlock the intended phone and complete its native verification. A cancellation requires a new request; it never grants approval for the next one.

## USB connection fails

Run `adb devices -l` locally. Resolve `unauthorized` on the intended phone, then select the device explicitly if several are present. Start desktop setup before tapping **Pair · USB**. For standard age, also set `AGE_PLUGIN_PHONE_ADB_SERIAL` when needed. iOS cannot use this route. Do not include device serials in reports.

## Wi-Fi discovery fails {#wi-fi}

1. Keep the correct phone app visible. For new pairing, tap **Pair · Wi-Fi**; auto-listen is only for existing pairings. For decryption, enable **Wi-Fi auto-listen** for the phone owning the stub.
2. Check that the devices share a reachable private IPv4 network. Guest isolation, VLANs, VPN routing, and firewall policy can block discovery even on the same SSID.
3. Remove stale address/ADB overrides and run one discovery-only check:

```sh
age-plugin-phone wifi-doctor
age-plugin-phone wifi-doctor --identity-stub '<identity-stub-path>'
```

Use the first command while the phone is waiting for new pairing, or the second for an existing pairing. It creates no pairing or unwrap request. Exit 0 means exactly one matching source; nonzero means failure. Multiple replies are an error, not a reason to choose an arbitrary phone.

On Windows, use the reviewed `windows-wifi-firewall.ps1` helper from the Beta 2 ZIP (beside the executable) or its matching source checkout. In PowerShell, select the exact installed executable and physical interface:

```powershell
Get-Command age-plugin-phone.exe -All | Select-Object Source
Get-NetConnectionProfile
$pluginExe = (Get-Command age-plugin-phone.exe -CommandType Application).Source
$lan = '<exact physical InterfaceAlias>'
$helper = '<absolute-path-to-windows-wifi-firewall.ps1>'
& $helper -Action Inspect -Program $pluginExe -InterfaceAlias $lan
& $helper -Action Enable -Program $pluginExe -InterfaceAlias $lan -WhatIf
```

Inspect and preview need no elevation. If the printed scope is correct, reassign those same values in an administrator PowerShell and run Enable without `-WhatIf`. It allows inbound UDP discovery replies only for that executable, interface, Private profile, and local subnet. It refuses Public/Domain profiles and never reclassifies the network. Do not disable the firewall or bypass organizational policy.

```powershell
& $helper -Action Enable -Program $pluginExe -InterfaceAlias $lan
& $helper -Action Inspect -Program $pluginExe -InterfaceAlias $lan
```

To undo the allowance, preview then remove the same exact rule:

```powershell
& $helper -Action Remove -Program $pluginExe -InterfaceAlias $lan -WhatIf
& $helper -Action Remove -Program $pluginExe -InterfaceAlias $lan
& $helper -Action Inspect -Program $pluginExe -InterfaceAlias $lan
```

Removal should report `Present=False`. A stored rule does not prove effective policy permits traffic. Ask the network administrator about restricted outbound UDP 47141/TCP 47140. A discovery timeout alone does not identify a firewall fault.

## Setup stops or private state is unavailable

Do not overwrite an existing stub. Use [resume or cleanup](guides/recovery.md) for the recorded attempt. Recheck that pairing and age use the same configuration root. A missing/corrupt private locator or replay store is fatal, even in a multiple-identity invocation. Do not restore an old snapshot to bypass it; use independent recovery if the original pairing is unavailable.

## Tag decryption fails

Confirm age 1.3+ on the encrypting machine and compatible desktop/phone Beta versions. Keep using the original public stub and paired desktop. An old phone rejects tag stanzas. Exporting another address does not convert an existing file or authorize fallback. See [recipient choices](guides/recipients.md).

## Report an unresolved problem

Include product/age versions, OS and hardware capability category, selected transport, the failing step, and a sanitized error category. Exclude private keys, file keys, plaintext, QR contents, raw payloads, device serials, and private state paths. Use synthetic data for reproduction and the repository's [issue tracker](https://github.com/biulight/age-plugin-phone/issues); follow [SECURITY.md](https://github.com/biulight/age-plugin-phone/blob/main/SECURITY.md) for security reports.
