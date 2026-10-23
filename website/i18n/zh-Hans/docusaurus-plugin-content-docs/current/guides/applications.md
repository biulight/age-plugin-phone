---
title: "日常使用与应用接入"
sidebar_position: 3
---

# 日常使用与应用接入

完成[首次往返](../quick-start.md)后，为兼容应用配置加密用的公开收件人和解密用的身份存根路径。调用程序的 `PATH` 必须能找到 `age` 和 `age-plugin-phone`。

## 直接使用 age

```sh
age -e -r '<phone-recipient>' -r '<recovery-recipient>' -o example.age example.txt
age -d -i '<identity-stub-path>' -o recovered.txt example.age
```

存根应传给 `-i`，不是收件人列表选项 `-R`。加密不需要手机授权。解密需要交互：保持手机可连接，并批准每次原生身份验证。不提供无人值守或缓存授权模式。使用新的输出文件名，检查退出状态后再使用解密数据。

可以重复 `-i` 传入多个身份文件。Beta 2 允许 age 跳过有效但不属于当前身份的 v2 phone 密文段，继续尝试后续身份。私有状态缺失或损坏仍是致命错误。一旦选中配对，取消或失败不会回退到其他配对。

## 接入 Shine 或其他兼容应用

Shine 使用标准 age CLI，不需要 `rage`。按照 [Shine 环境指南](https://biulight.github.io/shine/zh-Hans/guides/environment)和[配置参考](https://biulight.github.io/shine/zh-Hans/reference/configuration)配置公开收件人及本地身份存根路径。使用其手机引导配置流程前，先核对已安装的 Shine 版本。在加密配置中保留独立恢复收件人。

其他应用同样需要这两类值，以及可交互的 age 插件调用路径。如果使用 [tag 模式](recipients.md)，应用必须支持原生 tag 收件人，并在加密端使用 age 1.3+。接入不会引入另一套手机插件协议或密文格式。

对于图形应用，需要单独检查它继承的可执行文件路径、摄像头与网络权限以及连接设置，不能直接套用终端验证结果。USB 和 Wi-Fi 的插件提示默认静默；`AGE_PLUGIN_PHONE_MESSAGES=1` 可启用不含载荷的提示。QR 仍会显示，因为手机必须扫描请求。详情见[环境变量参考](../reference/commands.md)。

## 验证调用程序

使用可丢弃的文件，确认出现新的手机验证、恢复结果逐字节一致，并且取消会失败。另行在手机不可用时测试独立恢复。直接 CLI 测试通过不代表所有应用接入均已验证。
