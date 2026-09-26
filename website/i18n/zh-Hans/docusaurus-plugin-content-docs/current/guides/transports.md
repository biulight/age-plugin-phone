---
title: "选择连接方式"
sidebar_position: 1
---

# 选择连接方式

开始前选择一条连接路径。任何路径都需要在配对时比较完整指纹，每次解包时重新完成手机原生身份验证。

| 路径 | 配对前 | 解密前 |
| --- | --- | --- |
| Developer USB（`adb`） | 仅 Android：先启动电脑配对，再点击 **Pair · USB** | 连接并授权 ADB；电脑会启动手机原生批准流程 |
| 前台 Wi-Fi（`wifi`） | 先点击 **Pair · Wi-Fi**，再启动电脑配对 | 启用 **Wi-Fi auto-listen**，让应用保持可见 |
| QR（`qr`） | 显式选择 QR；手机扫描电脑提议，再用电脑摄像头扫描手机响应 | 手机扫描 age 请求，电脑扫描手机响应；实验性 |

## Developer USB

```sh
adb devices -l
age-plugin-phone setup --label "Test laptop" --transport adb
```

手机配对按钮只立即尝试连接一次。电脑配对尚未就绪时点击，可能出现 `usb_transport_failed`。有多台设备时，为 setup 添加 `--adb-serial SERIAL`，并为后续 age 调用设置 `AGE_PLUGIN_PHONE_ADB_SERIAL`。不要同时指定 ADB 设备和 Wi-Fi 地址覆盖。

ADB 的权限范围大于本应用所需，仅在确实要授权的电脑上使用。连接线和 ADB 授权都不代表批准解密。

## 前台 Wi-Fi

让两端连接到可互通的本地 IPv4 网络。在手机上点击 **Pair · Wi-Fi**，然后运行：

```sh
age-plugin-phone setup --label "Test laptop" --transport wifi
```

比较两端的完整指纹。后续解密时启用 **Wi-Fi auto-listen**，并让应用保持前台。自动监听不接受新配对；它默认关闭，会记住你的开启选择。暂停监听会关闭待处理连接或验证，不会重试请求。不支持后台唤醒。

通过 `--transport wifi` 创建的配对会记住仅使用 Wi-Fi 的设置。通常无需指定地址即可发现手机。发现失败时使用 [Wi-Fi 排查步骤](../troubleshooting.md#wi-fi)；仅凭超时不能断定是防火墙问题。

## 自动选择与手动覆盖

`setup` 默认使用 `auto`。没有显式连接提示时，它先进行有时限的 Wi-Fi 发现。恰好一个符合条件的监听器会选用 Wi-Fi；没有监听器时，Windows 选择 ADB，macOS 选择 QR。响应不唯一或发现出错时停止。发送开始后，不会并行尝试、切换或静默重试其他路径。

标准 age 解密时，环境变量覆盖优先于配对保存的路径。在 PowerShell 中为已有配对尝试 QR：

```powershell
$env:AGE_PLUGIN_PHONE_TRANSPORT = "qr"
age -d -i "<identity-stub-path>" -o recovered.txt example.age
Remove-Item Env:AGE_PLUGIN_PHONE_TRANSPORT
```

或只为一次 macOS 调用设置：

```sh
AGE_PLUGIN_PHONE_TRANSPORT=qr age -d -i '<identity-stub-path>' -o recovered.txt example.age
```

先清除冲突的 `AGE_PLUGIN_PHONE_ADB_SERIAL` 或 `AGE_PLUGIN_PHONE_WIFI_ADDRESS` 覆盖。QR 仅改变连接方式，不改变配对。摄像头权限必须在实际调用程序中可用；终端成功不代表图形应用有权限。QR/tag 的真机验证仍不完整。`ble` 是保留选项，执行会报告不可用。
