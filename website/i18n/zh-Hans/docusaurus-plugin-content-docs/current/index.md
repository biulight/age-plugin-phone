---
title: "通过手机授权 age 解密"
sidebar_position: 1
slug: /
---

# 通过手机授权 age 解密

将 `age-plugin-phone` 与兼容的 age 客户端配合使用，即可向公开收件人地址加密文件，并在手机上批准解密。长期解密密钥保留在手机上，电脑只获得本次获准操作所需的文件密钥。每次解包都需要手机重新进行原生身份验证。

:::warning 有限技术测试版
本手册适用于 **0.1.0-beta.2**，该版本于 2026 年 9 月 11 日发布。协议 v2 尚未冻结。仅使用合成或可丢弃的数据，并添加经过独立验证的恢复收件人。发布不代表适合保护真实秘密，也不代表所有设备组合均受支持。
:::

## 从这里开始

1. 检查[支持范围与前置条件](support.md)。
2. 在 [Windows](installation/windows.md) 或实验性的 [macOS](installation/macos.md) 上安装。
3. 完成[第一次加密与解密](quick-start.md)，包括独立恢复验证。

加密时，将公开的**收件人地址**传给 `age -r`。解密时，将公开的**身份存根文件**传给 `age -i`，同时需要完整的已配对电脑状态和手机。仅备份存根文件不能备份配对关系或手机身份。

## 完成首次往返后

- 选择 [Developer USB、前台 Wi-Fi 或实验性 QR](guides/transports.md)。
- 比较 [phone 与 tag 收件人](guides/recipients.md)。
- 配置[日常使用与兼容应用](guides/applications.md)。
- 在更换设备之前规划[升级、撤销与恢复](guides/recovery.md)。

插件独立于 Shine。应用通过标准 age 接口接入，无需插件专用服务或密文格式。采用其他版本之前，请阅读[版本与已知限制](reference/releases.md)。
