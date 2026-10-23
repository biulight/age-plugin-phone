---
title: "Install on Windows"
sidebar_position: 1
---

# Install on Windows

Install the desktop CLI and matching Android application, then check capabilities before creating a pairing. Review [support and prerequisites](../support.md) first.

## Install the desktop CLI

Install Rust with the MSVC toolchain and Visual Studio C++ Build Tools with the Windows SDK. In PowerShell:

```powershell
rustup default stable-x86_64-pc-windows-msvc
cargo install age-plugin-phone --version 0.1.0-beta.2 --locked
age-plugin-phone --version
age-plugin-phone status
```

`rustup default` changes your default Rust toolchain. The plugin executable must be on the `PATH` inherited by age. Reopen the terminal after changing `PATH`. `status` is read-only: it must report a supported Windows client, TPM 2.0, and Microsoft Platform Crypto Provider before setup.

Source installation does not require the private Windows test-signing root. If using the optional ZIP from [Beta 2](https://github.com/biulight/age-plugin-phone/releases/tag/v0.1.0-beta.2), compare its SHA-256 with the release checksum file and review the signature-verification record. Ordinary Windows installations do not trust its test root; do not install that root into a system trust store.

## Install the phone app and age

Download `age-plugin-phone-0.1.0-beta.2-android-arm64.apk` and its checksum file from the same release. Before installation, compare:

```powershell
Get-FileHash .\age-plugin-phone-0.1.0-beta.2-android-arm64.apk -Algorithm SHA256
```

Install the verified APK using Android's package installer and open it. On first use, select **Create StrongBox identity** and complete the native flow. Confirm that the app reports an available StrongBox identity; if one already exists, preserve it. If updating, preserve the existing app data and pairing; do not uninstall the app to work around a signature conflict. See [recovery](../guides/recovery.md).

Install [age](https://github.com/FiloSottile/age#installation) 1.3+ and Android SDK platform-tools for the Developer USB quick start. Verify:

```powershell
age --version
adb version
adb devices -l
```

Enable USB debugging and authorize only the intended computer. The device must appear as `device`, not `unauthorized`. Do not publish its serial. Continue to [your first round trip](../quick-start.md).
