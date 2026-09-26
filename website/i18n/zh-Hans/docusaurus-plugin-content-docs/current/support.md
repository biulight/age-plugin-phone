---
title: "支持范围与前置条件"
sidebar_position: 2
---

# 支持范围与前置条件

安装前检查完整的电脑与手机组合。能够编译、有发布包和通过真机验收是不同的结论。

| 组件 | 可用路径 | 边界 |
| --- | --- | --- |
| Windows | Windows 11 或更新的 x64 客户端、TPM 2.0、Microsoft Platform Crypto Provider；源码安装或测试签名 ZIP | 有限技术测试版；不支持 Windows Server，也不回退到软件密钥 |
| macOS | 在已记录的 Apple Silicon 主机上源码安装，使用 Secure Enclave | 实验性；macOS 14 只是编译部署下限，不是验证过的最低版本；Intel/T2 和其他系统、硬件组合尚未验证 |
| Android | 已签名的 ARM64 APK；需要实际可用的 StrongBox P-256 和强生物识别 | 仅满足 Android 版本不能证明硬件兼容 |
| iOS | 已有 iOS 17+ 开发设备群组，使用 Secure Enclave 与 Face ID/Touch ID | 不提供外部 iOS 安装包或 TestFlight 分发；不支持 Developer USB |
| Linux 桌面 | 本 Beta 没有受支持的手机解密配置路径 | 可移植构建或测试不能证明桌面硬件密钥支持 |

macOS 的已记录基线为运行 macOS 26.6.2 的 MacBookPro18,3。Windows/Android 和 macOS/Android 的 Developer USB、前台 Wi-Fi 有限定范围的记录；iPhone 群组使用前台 Wi-Fi。这些观察不能证明所有组合或另行发布的 Beta 2 安装包组合通过验收。使用确切发布包重复多身份回归测试仍待完成。

## 工具与访问条件

- 示例使用 age 1.3+。`rage` 是可替代的兼容客户端，无需同时安装。
- 源码安装需要 Rust 1.88+，以及 Windows MSVC C++ Build Tools/Windows SDK 或 macOS Xcode Command Line Tools。
- Developer USB 需要 Android platform-tools（`adb`）、USB 调试和明确的 ADB 授权。获准使用 ADB 的电脑对手机拥有比本应用所需更广的访问能力。
- Wi-Fi 要求应用保持前台，并连接到可互通的本地 IPv4 网络；不支持后台唤醒。
- QR 要求两端摄像头及权限正常，仍属实验性。BLE 仅保留选项，尚未实现。

将独立恢复身份保存在插件状态之外，并用可丢弃的数据验证。不要用本 Beta 保护真实秘密。接下来阅读 [Windows 安装](installation/windows.md)或 [macOS 安装](installation/macos.md)。
