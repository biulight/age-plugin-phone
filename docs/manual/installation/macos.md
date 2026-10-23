---
title: "Install on macOS"
sidebar_position: 2
---

# Install on macOS

This is an experimental source-install path. Check the [recorded hardware boundary](../support.md); a successful installation does not establish support for your device.

## Install and inspect

Install Rust 1.88+ and Xcode Command Line Tools with the macOS SDK and Swift compiler. Then run in Terminal:

```sh
xcrun swiftc --version
cargo install age-plugin-phone --version 0.1.0-beta.2 --locked
age-plugin-phone --version
age-plugin-phone status
```

Cargo places the executable in its normal `bin` directory. Include that directory in the `PATH` used by age; GUI applications may inherit a different path. Desktop installation does not require Android/iOS development tooling or a Developer ID certificate. `status` does not create keys or request camera permission; actual setup still needs working Secure Enclave operations.

## Prepare Android and age

Install the signed Android ARM64 APK from [Beta 2](https://github.com/biulight/age-plugin-phone/releases/tag/v0.1.0-beta.2). Compare its checksum with the release file before installation:

```sh
shasum -a 256 age-plugin-phone-0.1.0-beta.2-android-arm64.apk
```

Open the app. On first use, select **Create StrongBox identity** and complete the native flow; if an identity already exists, preserve it. Confirm StrongBox identity availability. Preserve existing app data when upgrading. Install [age](https://github.com/FiloSottile/age#installation) 1.3+ and Android SDK platform-tools, then check:

```sh
age --version
adb version
adb devices -l
```

For the [quick start](../quick-start.md), explicitly select `--transport adb` with Android. macOS `auto` uses Wi-Fi discovery and otherwise QR, not USB. USB debugging and ADB authorization are prerequisites, not permission to decrypt. iPhone remains outside external distribution scope and cannot use ADB.
