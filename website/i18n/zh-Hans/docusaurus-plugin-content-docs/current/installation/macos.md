---
title: "在 macOS 上安装"
sidebar_position: 2
---

# 在 macOS 上安装

这是实验性的源码安装路径。先检查[已记录的硬件范围](../support.md)；安装成功不代表你的设备组合已获支持。

## 安装与检查

安装 Rust 1.88+，以及包含 macOS SDK 和 Swift 编译器的 Xcode Command Line Tools。然后在终端执行：

```sh
xcrun swiftc --version
cargo install age-plugin-phone --version 0.1.0-beta.2 --locked
age-plugin-phone --version
age-plugin-phone status
```

Cargo 将可执行文件安装到其常规 `bin` 目录。确保 age 使用的 `PATH` 包含该目录；图形应用可能继承不同的路径。桌面安装不需要 Android/iOS 开发工具或 Developer ID 证书。`status` 不会创建密钥或请求摄像头权限；实际配对仍需要可用的 Secure Enclave 操作。

## 准备 Android 和 age

从 [Beta 2](https://github.com/biulight/age-plugin-phone/releases/tag/v0.1.0-beta.2) 下载已签名的 Android ARM64 APK，安装前将其校验值与发布文件比较：

```sh
shasum -a 256 age-plugin-phone-0.1.0-beta.2-android-arm64.apk
```

打开应用。首次使用时点击 **Create StrongBox identity** 并完成原生流程；已有身份则保留它。确认 StrongBox 身份可用。升级时保留已有应用数据。安装 [age](https://github.com/FiloSottile/age#installation) 1.3+ 和 Android SDK platform-tools，然后检查：

```sh
age --version
adb version
adb devices -l
```

[快速入门](../quick-start.md)使用 Android，并显式选择 `--transport adb`。macOS 的 `auto` 会发现 Wi-Fi，无监听器时选择 QR，而不是 USB。USB 调试和 ADB 授权仅是连接条件，不是解密授权。iPhone 不在外部分发范围内，也不能使用 ADB。
