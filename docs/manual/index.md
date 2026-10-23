---
title: "Phone-authorized age decryption"
sidebar_position: 1
slug: /
---

# Phone-authorized age decryption

Use `age-plugin-phone` with a compatible age client to encrypt files to a public recipient and approve decryption on your phone. The phone keeps the long-term decryption key; the desktop receives only the file key for the approved operation. Every unwrap requires fresh native phone verification.

:::warning Limited technical beta
This manual covers **0.1.0-beta.2**, published on September 11, 2026. Protocol v2 is not frozen. Use synthetic or disposable data only, with an independently tested recovery recipient. Publication does not establish production safety or support for every device combination.
:::

## Start here

1. Check [supported platforms and prerequisites](support.md).
2. Install on [Windows](installation/windows.md) or experimental [macOS](installation/macos.md).
3. Complete [your first encryption and decryption](quick-start.md), including independent recovery.

Encryption uses a public **recipient** with `age -r`. Decryption uses a public **identity stub** with `age -i`, the paired desktop's intact state, and the phone. The stub alone is not a backup of the pairing or phone identity.

## After the first round trip

- Choose [Developer USB, foreground Wi-Fi, or experimental QR](guides/transports.md).
- Compare [phone and tag recipients](guides/recipients.md).
- Configure [daily use and compatible applications](guides/applications.md).
- Plan [upgrades, revocation, and recovery](guides/recovery.md) before replacing a device.

The plugin is independent of Shine. Applications use the standard age interface; they do not need a plugin-specific service or ciphertext format. See [versions and limitations](reference/releases.md) before adopting a different release.
