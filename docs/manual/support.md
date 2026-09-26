---
title: "Support and prerequisites"
sidebar_position: 2
---

# Support and prerequisites

Check your complete desktop/phone combination before installing. A successful build, a published package, and physical-device acceptance are different claims.

| Component | Available path | Boundary |
| --- | --- | --- |
| Windows | Windows 11 or later x64 client, TPM 2.0, Microsoft Platform Crypto Provider; source install or test-signed ZIP | Limited technical beta; not Windows Server or software-key fallback |
| macOS | Source install with Secure Enclave on the recorded Apple Silicon host | Experimental; macOS 14 is the compilation floor, not a tested minimum; Intel/T2 and other OS/hardware combinations remain unverified |
| Android | Signed ARM64 APK; live StrongBox P-256 capability and strong biometric authentication required | Android version alone does not prove hardware compatibility |
| iOS | Existing iOS 17+ development-device cohort, Secure Enclave and Face ID/Touch ID | No external iOS package or TestFlight distribution; Developer USB unavailable |
| Linux desktop | No supported phone-decryption setup path in this beta | Portable builds/tests do not establish desktop hardware-key support |

The recorded macOS baseline is MacBookPro18,3 on macOS 26.6.2. Windows/Android and macOS/Android Developer USB and foreground Wi-Fi have scoped records; the iPhone cohort uses foreground Wi-Fi. These observations do not certify every combination or the separately published Beta 2 package pair. The exact-package multi-identity regression repeat remains open.

## Tools and access

- Install age 1.3+ for the examples. `rage` is an alternative compatible client, not an additional prerequisite.
- Source installation requires Rust 1.88+, plus Windows MSVC C++ Build Tools/Windows SDK or macOS Xcode Command Line Tools.
- Developer USB requires Android platform-tools (`adb`), USB debugging, and explicit ADB authorization. An authorized ADB host has broader phone access than this application needs.
- Wi-Fi requires the app to remain in the foreground on a reachable local IPv4 network. It does not wake the phone in the background.
- QR needs working cameras and permissions at both ends and remains experimental. BLE is reserved but not implemented.

Keep an independent recovery identity outside plugin state and verify it with disposable data. Do not use this beta to protect real secrets. Continue to [Windows installation](installation/windows.md) or [macOS installation](installation/macos.md).
