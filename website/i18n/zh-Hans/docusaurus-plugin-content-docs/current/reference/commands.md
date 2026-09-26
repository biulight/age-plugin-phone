---
title: "命令与环境变量"
sidebar_position: 1
---

# 命令与环境变量

本参考适用于 **0.1.0-beta.2**。公开选项以 CLI 定义为准；日常使用优先选择托管的 `setup`。运行 `age-plugin-phone --help` 或 `age-plugin-phone <command> --help` 查看用法。不带子命令执行等同于 `status`。

## 常用命令

| 命令 | 选项与默认值 | 结果或限制 |
| --- | --- | --- |
| `status` | 无选项 | 只读报告实现状态与平台能力 |
| `setup` | `--label LABEL`；`--recipient-type phone\|tag`（默认 `phone`）；`--transport auto\|adb\|ble\|wifi\|qr`（默认 `auto`）；可选 `--adb-serial SERIAL`、`--json` | 使用托管硬件路径创建配对；新配对必须提供标签 |
| `setup --resume` | 可选 `--recipient-type`、`--json` | 仅完成已持久确认的本地操作；不能与标签、cleanup、连接方式或 ADB 序列号组合 |
| `setup --cleanup` | 无 JSON 输出 | 确认后删除确切的未完成操作；不能与 resume、标签、连接方式或 ADB 序列号组合 |
| `recipients` | 必填 `-i` / `--identity PATH`；`--recipient-type phone\|tag`（默认 `phone`） | 输出一个公开地址，不联系手机或访问私有状态 |
| `wifi-doctor` | 可选 `--identity-stub PATH` | 一次有时限的发现检查；省略路径检查新配对模式，提供路径检查已有配对 |
| `remove-desktop-state` | 必填 `--identity-stub PATH` | 确认完整指纹后，破坏性清理确切配对 |
| `remove-orphaned-desktop-state` | 必填 `--locator PATH` | 破坏性清理孤立状态；要求受保护根目录直接子级中的规范定位文件 |

清理前阅读[恢复指南](../guides/recovery.md)。`ble` 是不可用的保留选项。`status` 的可用性提示不代表通过真机验收。

## Setup JSON

新配对和恢复支持 `--json`。成功时 stdout 恰好包含一个对象：

```json
{"schema_version":1,"identity_path":"<public-stub-path>","recipient":"<public-recipient>"}
```

提示、QR 展示、指纹确认和警告仍使用 stderr。失败时不输出成功对象。清理没有 JSON 模式。JSON 不会绕过交互或手机原生身份验证。

## 高级诊断

以下命令不是常规文件加密解密接口；文件操作使用 age。

| 命令 | 必填选项 | 可选选项 |
| --- | --- | --- |
| `pair` | `--label`、`--desktop-state`、`--identity-output`、`--replay-state` | `--recipient-type`（默认 `phone`）、`--transport`（默认 `auto`）、`--adb-serial` |
| `unwrap` | `--identity-stub`、`--desktop-state`、`--replay-state`、`--stanza-arg`、`--stanza-body` | `--caller-hint`、`--transport`（默认 `auto`）、`--adb-serial`、`--wifi-address` |
| `qr-capture-probe` | 无 | `--label`（默认 `Desktop QR capture probe`）、`--cycles`（默认 `12`）、`--html-output PATH` |

`pair` 只创建新路径。在 Windows/macOS 上，私有电脑状态与重放状态必须是受保护配置根目录的直接子级；不能复用已有或不确定的状态。`unwrap` 处理一个密文段，而不是整个加密文件。不要在报告中收集原始密文段或请求值。`qr-capture-probe` 仅验证扫描，不完成配对或解密；不要公开其 QR 输出。隐藏的 age 协议与清理辅助命令不是用户接口。

## 环境变量

在启动 age 的进程中设置这些变量。`setup` 和显式诊断命令使用各自的连接选项。

| 变量 | 默认值 | 含义 |
| --- | --- | --- |
| `AGE_PLUGIN_PHONE_TRANSPORT` | 配对保存的选择 | 覆盖标准 age 调用的连接方式；接受 `auto`、`adb`、`wifi`、`qr` 和保留的 `ble` |
| `AGE_PLUGIN_PHONE_ADB_SERIAL` | 不显式指定设备 | 为标准 age 调用选择 Android 设备；有多台 ADB 设备时需要设置 |
| `AGE_PLUGIN_PHONE_WIFI_ADDRESS` | 符合条件时自动发现 | 诊断用私有 IPv4 端点，包含端口；通常无需指定地址 |
| `AGE_PLUGIN_PHONE_MESSAGES` | 关闭 | `1`、`true`、`yes` 或 `on` 启用不含载荷的电脑提示，不区分大小写并忽略首尾空白；关闭时仍显示 QR |
| `AGE_PLUGIN_PHONE_CONFIG_DIR` | 平台配置根目录 | 绝对路径形式的替代根目录；配对和后续 age 调用必须使用相同值 |

ADB 与 Wi-Fi 提示不能组合。显式连接提示可能跳过自动发现，且必须符合所选连接方式。不要用空值或错误格式清除覆盖，应删除环境变量。不要为更换配置根目录而移动或恢复插件状态；请参阅[恢复指南](../guides/recovery.md)。

多台 Android 设备时，PowerShell 使用 `$env:AGE_PLUGIN_PHONE_ADB_SERIAL = "SERIAL"`，完成后用 `Remove-Item Env:AGE_PLUGIN_PHONE_ADB_SERIAL` 删除。macOS 可为单次命令赋值，例如 `AGE_PLUGIN_PHONE_ADB_SERIAL=SERIAL age -d -i phone-identity.txt -o recovered.txt example.age`。在本地替换 `SERIAL`，不要将序列号写入公开报告。
