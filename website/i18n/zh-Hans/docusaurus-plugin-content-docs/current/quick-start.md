---
title: "第一次加密与解密"
sidebar_position: 4
---

# 第一次加密与解密

通过 Developer USB 配对一部 Android 手机与电脑，加密可丢弃的文本，并分别验证手机解密和独立恢复解密。先完成[安装准备](support.md)。使用新的空测试目录，避免输出文件覆盖已有内容。

## 1. 配对手机

连接已授权的 Android 设备。**先**在电脑上启动以下命令，**再**在手机上选择 **Pair · USB**：

```sh
age-plugin-phone setup --label "Test laptop" --transport adb
```

同时连接多台 ADB 设备时，添加 `--adb-serial SERIAL`，将 `SERIAL` 替换为目标设备序列号。比较两端的**完整指纹**，只有完全一致时才在电脑提示中输入。设备标签只是未经信任的提示。手机的原生确认也需要你亲自完成。

保存输出的公开身份存根路径和收件人地址。确认完成后配对才成功；如中断，请使用[恢复指南](guides/recovery.md)。

如果连接了多台 ADB 设备，继续前先按照[环境变量参考](reference/commands.md)，在执行解密的终端中设置 `AGE_PLUGIN_PHONE_ADB_SERIAL`。

## 2. 在 Windows 上加密并验证

在 PowerShell 中将两个占位符替换为配对输出。下面的恢复密钥仅用于可丢弃的测试，应与插件状态分开保存。

```powershell
$identityStub = "<printed-public-identity-stub-path>"
$phoneRecipient = "<printed-recipient>"
age-keygen -o .\recovery-test-identity.txt
$recoveryRecipient = age-keygen -y .\recovery-test-identity.txt
Set-Content -NoNewline -Encoding utf8 .\probe.txt "synthetic beta probe"
age -e -r $phoneRecipient -r $recoveryRecipient -o .\probe.txt.age .\probe.txt
age -d -i $identityStub -o .\probe.phone.txt .\probe.txt.age
age -d -i .\recovery-test-identity.txt -o .\probe.recovery.txt .\probe.txt.age
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.phone.txt -Algorithm SHA256).Hash) { throw "phone digest mismatch" }
if ((Get-FileHash .\probe.txt -Algorithm SHA256).Hash -ne (Get-FileHash .\probe.recovery.txt -Algorithm SHA256).Hash) { throw "recovery digest mismatch" }
```

## 3. 或在 macOS 上验证

用以下命令代替 Windows 命令，同样替换两个占位符：

```sh
identityStub='<printed-public-identity-stub-path>'
phoneRecipient='<printed-recipient>'
age-keygen -o recovery-test-identity.txt
recoveryRecipient=$(age-keygen -y recovery-test-identity.txt)
printf '%s' 'synthetic beta probe' > probe.txt
age -e -r "$phoneRecipient" -r "$recoveryRecipient" -o probe.txt.age probe.txt
age -d -i "$identityStub" -o probe.phone.txt probe.txt.age
age -d -i recovery-test-identity.txt -o probe.recovery.txt probe.txt.age
cmp probe.txt probe.phone.txt
cmp probe.txt probe.recovery.txt
```

## 确认成功

加密不需要手机批准。手机解密必须触发新的原生身份验证。独立恢复解密必须不依赖手机。两次文件比较都应成功；文件一致时，`cmp` 成功退出且没有输出。任一命令失败都应停止，不要把后续输出当作成功证据。

再解密一次到新的输出文件，确认手机再次提示验证。另起一次操作并取消：它必须失败，且不产生可用明文。重试需要新请求和新授权。若有多台 ADB 设备，执行 age 解密前也要设置 [ADB 序列号环境变量](reference/commands.md)。

不要把这个测试用恢复私钥放入仓库、验收日志或插件状态中。仅在同一电脑上配对另一部手机，不能覆盖电脑丢失的情况。删除任何身份前，先阅读[恢复指南](guides/recovery.md)，然后了解[连接方式](guides/transports.md)或[应用接入](guides/applications.md)。
