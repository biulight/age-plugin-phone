---
title: "故障排查"
sidebar_position: 6
---

# 故障排查

从只读检查开始，保留配对状态。不要删除密钥、重放文件、待处理标记或日志来让失败的操作继续。

## age 找不到插件

在实际调用环境中检查 `age-plugin-phone --version`。可执行文件必须保留 `age-plugin-phone` 名称，Windows 上为 `age-plugin-phone.exe`。更改 `PATH` 后重新打开终端；图形应用需要单独检查。确认公开存根通过 `-i` 传入，而不是 `-R`。

## 硬件或手机验证不可用

运行 `age-plugin-phone status`，重新核对[平台条件](support.md)及手机应用的硬件身份状态。系统版本符合要求，不代表 TPM/StrongBox/Secure Enclave 可用。不要用软件密钥替代硬件密钥。解锁目标手机并完成原生验证。取消后必须创建新请求，不会为下一次操作授予权限。

## USB 连接失败

在本地运行 `adb devices -l`。在目标手机上解决 `unauthorized`；存在多台设备时显式指定目标。先启动电脑配对，再点击 **Pair · USB**。标准 age 调用也需要在必要时设置 `AGE_PLUGIN_PHONE_ADB_SERIAL`。iOS 不能使用此路径。报告中不要包含设备序列号。

## Wi-Fi 发现失败 {#wi-fi}

1. 保持正确的手机应用可见。新配对点击 **Pair · Wi-Fi**，自动监听仅用于已有配对。解密时，在拥有该存根对应身份的手机上启用 **Wi-Fi auto-listen**。
2. 检查设备是否处于可互通的私有 IPv4 网络。即使 SSID 相同，访客隔离、VLAN、VPN 路由和防火墙策略也可能阻止发现。
3. 删除过期的地址或 ADB 覆盖，执行一次仅发现检查：

```sh
age-plugin-phone wifi-doctor
age-plugin-phone wifi-doctor --identity-stub '<identity-stub-path>'
```

手机等待新配对时使用第一条，已有配对使用第二条。命令不创建配对或解包请求。退出码 0 表示恰好一个匹配来源，非零表示失败。多个响应属于错误，不能任意挑选一部手机。

Windows 可使用 Beta 2 ZIP 中位于可执行文件旁的 `windows-wifi-firewall.ps1`，或匹配源码版本的该脚本。在 PowerShell 中选定实际安装的可执行文件与物理接口：

```powershell
Get-Command age-plugin-phone.exe -All | Select-Object Source
Get-NetConnectionProfile
$pluginExe = (Get-Command age-plugin-phone.exe -CommandType Application).Source
$lan = '<exact physical InterfaceAlias>'
$helper = '<absolute-path-to-windows-wifi-firewall.ps1>'
& $helper -Action Inspect -Program $pluginExe -InterfaceAlias $lan
& $helper -Action Enable -Program $pluginExe -InterfaceAlias $lan -WhatIf
```

检查和预览不需要提权。确认输出范围正确后，在管理员 PowerShell 中重新设置相同的值，再执行不带 `-WhatIf` 的 Enable。规则仅允许指定程序、接口、Private 配置文件和本地子网的入站 UDP 发现响应。脚本拒绝 Public/Domain 配置文件，且不会更改网络分类。不要关闭防火墙或绕过组织策略。

```powershell
& $helper -Action Enable -Program $pluginExe -InterfaceAlias $lan
& $helper -Action Inspect -Program $pluginExe -InterfaceAlias $lan
```

撤销此放行时，先预览，再移除同一条确切规则：

```powershell
& $helper -Action Remove -Program $pluginExe -InterfaceAlias $lan -WhatIf
& $helper -Action Remove -Program $pluginExe -InterfaceAlias $lan
& $helper -Action Inspect -Program $pluginExe -InterfaceAlias $lan
```

移除后应报告 `Present=False`。规则存在不代表有效策略允许流量。如出站 UDP 47141/TCP 47140 受限，请联系网络管理员。仅凭发现超时不能确认防火墙故障。

## 配对中断或私有状态不可用

不要覆盖已有存根。使用[恢复或清理](guides/recovery.md)处理记录中的操作。确认配对和 age 使用同一个配置根目录。即使调用传入多个身份，私有定位文件或重放存储缺失、损坏仍是致命错误。不要恢复旧快照来绕过；原配对不可用时使用独立恢复。

## Tag 解密失败

确认加密端使用 age 1.3+，电脑和手机使用兼容的 Beta 版本。继续使用原公开存根与已配对电脑。旧手机应用会拒绝 tag 密文段。导出另一个地址不会转换已有文件，也不授权回退。请参阅[收件人选择](guides/recipients.md)。

## 报告未解决的问题

提供产品和 age 版本、系统及硬件能力类别、所选连接方式、失败步骤和脱敏后的错误类别。排除私钥、文件密钥、明文、QR 内容、原始载荷、设备序列号和私有状态路径。使用合成数据复现，并通过仓库的 [issue 列表](https://github.com/biulight/age-plugin-phone/issues)报告；安全问题遵循 [SECURITY.md](https://github.com/biulight/age-plugin-phone/blob/main/SECURITY.md)。
