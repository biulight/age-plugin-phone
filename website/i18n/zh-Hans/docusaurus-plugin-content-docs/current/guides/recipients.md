---
title: "选择 phone 或 tag 收件人"
sidebar_position: 2
---

# 选择 phone 或 tag 收件人

为新加密选择公开地址格式。两种格式解密时使用同一个公开身份存根，都需要完整的已配对电脑状态、手机及新的身份验证。

| 选择 | 加密端要求 | 隐私与兼容性 |
| --- | --- | --- |
| `phone`（默认） | 兼容的 age 客户端及手机插件 | phone v2 使用已配对电脑的私有选择；无歧义文件仍可读取旧 v1 格式 |
| `tag`（显式选择） | age 1.3+；加密端不需要手机插件 | 知道收件人地址的人可以测试密文段是否可能属于它；旧手机应用拒绝 tag 解密 |

## 从已有配对导出

使用[配对](../quick-start.md)得到的公开存根：

```sh
age-plugin-phone recipients -i phone-identity.txt --recipient-type tag
age-plugin-phone recipients -i phone-identity.txt --recipient-type phone
```

每次执行输出一个公开收件人地址。导出不联系手机，也不打开私有状态。已有协议 v2 配对无需仅为 tag 支持重新配对；解密 tag 前，将电脑和手机升级到兼容的 Beta 版本。

让新配对显示 tag 收件人：

```sh
age-plugin-phone setup --label "Test laptop" --recipient-type tag --json
```

此示例使用默认 `auto` 连接策略，请遵循[对应平台的操作顺序](transports.md)。仍需比较完整指纹。如果已确认配对的公开文件已经使用 tag 创建，恢复 setup 时也应重复 `--recipient-type tag`；冲突的类型会被拒绝。

## 加密并验证

将两个收件人占位符替换为已导出的公开地址。第二个必须是独立验证过的恢复收件人：

```sh
age -e -r '<tag-recipient>' -r '<recovery-recipient>' -o synthetic.age synthetic.txt
age -d -i phone-identity.txt -o recovered.txt synthetic.age
```

按照[快速入门](../quick-start.md)验证手机和恢复两条路径。tag 操作失败不会切换到 phone 模式或其他配对。导出新地址不会转换现有密文；迁移需要先解密再重新加密。更新收件人列表不会撤销对旧副本的访问；必要时轮换实际的上游凭据。
