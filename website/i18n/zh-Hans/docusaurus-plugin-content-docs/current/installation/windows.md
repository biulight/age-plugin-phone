---
title: "在 Windows 上安装"
sidebar_position: 1
---

# 在 Windows 上安装

安装桌面 CLI 与对应 Android 应用，在创建配对之前检查设备能力。请先阅读[支持范围与前置条件](../support.md)。

## 安装桌面 CLI

安装使用 MSVC 工具链的 Rust，以及包含 Windows SDK 的 Visual Studio C++ Build Tools。在 PowerShell 中执行：

```powershell
rustup default stable-x86_64-pc-windows-msvc
cargo install age-plugin-phone --version 0.1.0-beta.2 --locked
age-plugin-phone --version
age-plugin-phone status
```

`rustup default` 会更改默认 Rust 工具链。插件可执行文件必须位于 age 继承的 `PATH` 中；修改 `PATH` 后重新打开终端。`status` 是只读检查：开始配对前，它必须报告受支持的 Windows 客户端、TPM 2.0 和 Microsoft Platform Crypto Provider。

源码安装不需要 Windows 私有测试签名根证书。如果使用 [Beta 2](https://github.com/biulight/age-plugin-phone/releases/tag/v0.1.0-beta.2) 的可选 ZIP，请将其 SHA-256 与发布校验文件比较，并查看签名验证记录。普通 Windows 系统不信任其测试根证书；不要将该根证书安装到系统信任库。

## 安装手机应用和 age

从同一发布版本下载 `age-plugin-phone-0.1.0-beta.2-android-arm64.apk` 及校验文件。安装前比较：

```powershell
Get-FileHash .\age-plugin-phone-0.1.0-beta.2-android-arm64.apk -Algorithm SHA256
```

使用 Android 的安装器安装校验过的 APK 并打开应用，首次使用时，点击 **Create StrongBox identity** 并完成原生流程，确认应用报告 StrongBox 身份可用；若已有身份则保留它。如果是升级，保留已有应用数据与配对；不要为了绕过签名冲突而卸载应用。请参阅[恢复指南](../guides/recovery.md)。

安装 [age](https://github.com/FiloSottile/age#installation) 1.3+，以及 Developer USB 入门所需的 Android SDK platform-tools。检查：

```powershell
age --version
adb version
adb devices -l
```

启用 USB 调试，仅授权预期的电脑。设备应显示为 `device`，而非 `unauthorized`。不要公开设备序列号。接下来完成[第一次往返](../quick-start.md)。
