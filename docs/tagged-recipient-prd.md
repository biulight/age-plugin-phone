# 原生 Tagged Recipient 与 `age1phone` 双模式 PRD

状态：已实现并完成签名候选的部分真机验收，以及 Shine 2.0.3 的 macOS/iPhone 集成验收；
具体范围见 [实施记录](tagged-recipient-evidence.md)。Android/iOS 完整负面验收矩阵仍未完成，
不适用于真实或生产秘密。

日期：2026-09-10

## 1. 背景与目标

本需求的目标是在 Shine 中使用手机硬件身份，同时把能力实现为任何兼容 age 客户端均可
使用的标准 age 插件。实现直接参考 `age-plugin-se` 支持 `age1tag` 的方式：同一硬件身份
导出标准 tagged recipient，加密由 age 原生完成，解密仍由原插件 identity 调用硬件私钥。
Shine 是目标使用场景和集成验收对象，不是协议参与方或插件运行依赖。

`age-plugin-phone` 当前通过标准 age 插件协议提供 `age1phone` recipient。即使加密只使用
公开材料，age 客户端看到 `age1phone` 后仍会从 `PATH` 启动 `age-plugin-phone` 的
`recipient-v1` 状态机。因此，未安装插件的 macOS、Linux、CI 或其他 Windows 主机无法为
包含 phone recipient 的完整成员列表重新加密。这会阻断共享 workspace 的 `seal`：能够用
其他身份解开旧 payload 的成员，也必须先具备每一种 recipient 插件，才能产生面向完整成员
列表的新密文。

age 1.3 原生支持 `age1tag` recipient 与 `p256tag` stanza。该类型面向私钥保存在硬件中、
解密可能要求用户在场的 P-256 身份；加密端仅依赖 age，不需要安装平台专用插件。
`age-plugin-se` 已同时支持插件专用 `se` recipient 与原生 `tag` recipient，证明同一硬件身份
可以保留专用兼容模式，同时提供跨平台加密入口。

本项目新增等价的双模式：保持现有 `age1phone` 为默认 recipient，并允许用户主动选择由
phone identity P-256 公钥派生的 `age1tag`。现有 `recipient-v1` 加密能力和历史密文解密能力
长期保留。迁移不改变手机长期私钥、不要求重新配对，也不引入 Shine 专用密文、URI、环境
变量或 RPC。

目标用户包括：在多平台团队中维护同一 recipient 列表的用户；从未安装 phone 插件的机器
执行公开加密或重新封存的用户；以及仍要求 paired-desktop 私有 stanza 选择语义的现有用户。

成功标准：

- age 1.3+ 能在未安装 `age-plugin-phone` 的加密端使用 phone `age1tag` 生成标准密文；
- 已配对桌面能通过现有 public identity stub 和手机端新鲜用户验证解开对应 `p256tag` stanza；
- 现有配对、identity stub、`age1phone` recipient 及 `phone-p256-v1/v2` 密文继续可用；
- `tag` 与 `phone` 模式的隐私、安全、兼容性和最低客户端要求对用户明确可见；
- 失败、取消或能力缺失不会触发静默降级、替代身份或第二次私有解密尝试。

## 2. 范围与非目标

本期设计包括：tagged recipient 编码与派生、标准 `p256tag` stanza 选择和解封、桌面 CLI
接口、Android/iOS 原生 HPKE 解封、兼容与迁移行为、跨语言向量、age 互操作和文档。
Shine 使用上述通用接口的集成验证单独记录，不作为标准插件能力的发布依赖。

本期不删除或弃用 `age1phone`，不改变现有 phone v1/v2 stanza 字节，不迁移或重建手机和桌面
私钥，不改变配对 transcript、持久状态编码、传输选择、签名请求、响应封装或 replay 语义。
不新增软件私钥、DPAPI、Keychain、密码、TOTP 或授权缓存回退，不让手机解析完整 age 文件、
应用配置或明文。`age1tagpq` 和后量子硬件身份另立设计，不属于本期。

### 2.1 `age-plugin-se` 参照与项目适配

以 `age-plugin-se` 的 `Sources/Plugin.swift` 和 `Sources/HPKE.swift` 为实现参照，标准字节
格式以 C2SP age 规范为准。实施时记录实际参照的上游 commit 和互操作客户端版本。

| `age-plugin-se` 已有做法 | 本项目对应实现 |
| --- | --- |
| `Recipient.ageRecipient(type:)` 将同一压缩 P-256 公钥编码为 `se` 或 `tag` | 从现有 public stub 的手机公钥导出 `tag`，保留现有配对专用 `phone` 输出 |
| `keygen` / `recipients` 提供 `--recipient-type` | `setup` / `pair` / `recipients` 提供 `phone\|tag` 选择 |
| age 1.3+ 原生加密给 `age1tag` | 无 phone 插件的加密端直接使用 age |
| `runIdentityV1()` 识别 `p256tag`，通过公开 tag 筛选后进行 HPKE 解封 | 桌面筛选，手机在既有配对和新鲜验证流程中完成 HPKE 解封 |
| 原 `AGE-PLUGIN-SE-` identity 同时解密旧 stanza 和 `p256tag` | 原 `AGE-PLUGIN-PHONE-` stub 同时接入旧 phone stanza 和 `p256tag` |

phone v2 recipient 含配对信息，不能像 SE 的纯公钥 recipient 一样只替换 HRP；tag 必须从
stub 中的手机公钥派生。复用的是 SE 的标准 recipient 编码、tag 计算和 HPKE 路径；本项目
既有的远程配对、每次手机验证、请求绑定和 replay 边界继续适用。

## 3. 用户接口与默认行为

### 3.1 Recipient 类型

新增用户可选类型 `tag | phone`：

| 类型 | 输出 | 加密端要求 | 选择与隐私语义 |
| --- | --- | --- | --- |
| `tag` | `age1tag...` | age 1.3+；不需要 phone 插件 | 标准 `p256tag`；知道 recipient 的观察者可判断目标 stanza |
| `phone` | `age1phone...` | age 客户端和 `age-plugin-phone` | 保留 v2 paired-desktop recipient 与私有 stanza selection |

`phone` 保持默认并长期支持，不标记为弃用。`tag` 是用户主动选择的跨平台加密模式，不能由
运行时自动转换或作为失败回退。命令帮助和文档必须同时说明两类 recipient 的最低版本与隐私
差异。

### 3.2 命令行

以下命令接受新选项，省略时等价于 `--recipient-type phone`：

```console
age-plugin-phone setup --label LABEL --recipient-type <tag|phone>
age-plugin-phone pair ... --recipient-type <tag|phone>
```

新增只读导出命令，使现有配对无需重新配对即可取得任一公开 recipient：

```console
age-plugin-phone recipients -i <IDENTITY_STUB> --recipient-type <tag|phone>
```

该命令只读取并严格验证 public identity stub，向标准输出写入一个 canonical recipient 和一个
换行；不得打开私有 locator、桌面硬件密钥、replay 状态或网络传输，不得联系手机或触发用户
验证。输入缺失、格式错误、版本不支持或公钥无效时不输出 recipient 并返回失败。

`setup --json` 保持 schema version 1 与既有字段：

```json
{"schema_version":1,"identity_path":"...","recipient":"age1phone1..."}
```

`recipient` 返回本次选择的类型；默认是 `age1phone...`，显式 `--recipient-type tag` 时是
`age1tag...`。消费者可通过 canonical recipient 前缀识别类型；本期不新增第二个 recipient
字段，也不同时输出两个地址。非 JSON 输出和 identity 文件首行注释展示同一选定 recipient。
identity 文件中的 `AGE-PLUGIN-PHONE-...` public stub 内容不因展示类型而改变。

### 3.3 Public identity stub API

public stub 继续保存现有 phone 基础 recipient、公钥、paired desktop 公钥、identity ID、摘要和
指纹，编码版本和字段顺序不变。基础 phone recipient 仍是 phone identity 压缩 P-256 公钥的
canonical 表示，并作为两类输出的共同来源。

实现增加明确的派生接口：

- `tag_recipient()`：将 phone identity 的 33 字节压缩 SEC1 P-256 公钥编码为 canonical
  `age1tag`；
- `phone_recipient()`：返回现有 pairing-specific v2 `age1phone` recipient；
- `recipient_for(RecipientType)`：供 CLI 选择输出。

现有含义为 v2 phone recipient 的 API 不得悄悄改成返回 tag；调用点应迁移到显式类型接口。
如需保留已发布 Rust API，旧方法继续返回原 `age1phone` 并标记清晰的兼容说明，不能用默认值
改变其语义。

## 4. 密码与数据流

### 4.1 加密

`age1tag` 的编码和 `p256tag` wrapping 完全遵循 age/C2SP tagged recipient 规范：

- recipient 负载是 phone identity 的 canonical 33 字节压缩 SEC1 P-256 公钥；
- KEM 为 DHKEM(P-256, HKDF-SHA256)；
- KDF 为 HKDF-SHA256；
- AEAD 为 ChaCha20-Poly1305；
- HPKE `info` 为 ASCII `age-encryption.org/p256tag`，AAD 为空；
- stanza tag 为 `p256tag`，参数为 canonical unpadded Base64 的 4 字节选择 tag 和 65 字节
  uncompressed encapsulated key，body 为 32 字节 HPKE ciphertext。

`age1tag` 加密由 age 1.3+ 原生完成。`age-plugin-phone` 的 `recipient-v1` 不接收也不代理
`age1tag`；它继续为默认或显式选择的 `age1phone` recipient 产生现有 v1/v2 stanza。两条
加密路径不得生成彼此格式的 stanza。

### 4.2 桌面选择

`identity-v1` 同时接受现有 `phone-p256-v1/v2` 和标准 `p256tag`。对 `p256tag`：

1. 严格检查参数个数、canonical Base64、4 字节 tag、65 字节 uncompressed P-256 enc 以及
   32 字节 body；无效的受支持 stanza 是终止错误，未知 stanza tag 继续忽略。
2. 对每个已验证 public stub，使用公开 phone P-256 公钥和 stanza encapsulated key 按标准公式
   计算选择 tag；不匹配时忽略，不打开私有状态、不选择传输、不联系手机。
3. 若同一 stanza 匹配两个不同 phone 公钥，作为 tag 歧义在任何用户提示或 replay 消费前失败。
   若多个 identity stub 对应同一 phone 公钥，按 age identity 输入顺序选择第一个配对；这是
   显式且可测试的顺序规则。
4. 匹配后才打开该 stub 的 transcript-bound locator、桌面签名状态和 replay 状态，并进入既有
   单次解封请求流程。私有操作、请求创建或 replay 消费开始后，不尝试下一个配对或其他
   recipient 类型。

4 字节 tag 只是公开预筛选，不构成解密成功。最终成功必须来自标准 HPKE 认证解封、完整请求
和响应验证以及持久 replay 消费。

### 4.3 手机解封

桌面把完整 canonical `p256tag` stanza 放入现有签名 unwrap request。请求仍绑定 paired desktop、
phone identity、请求 ID、nonce、短期 expiry、一次性响应会话公钥和完整 stanza；传输不获得
任何新增信任。

Android 和 iOS 原生边界增加标准 P-256 HPKE Open：

- 在严格解析 stanza 和验证签名、配对、expiry、nonce、replay scope 后，先持久消费请求；
- 为该次 phone identity ECDH 操作创建全新的 StrongBox `BiometricPrompt.CryptoObject` 或
  Secure Enclave/`LAContext`，不得复用认证上下文；
- 使用硬件私钥和 stanza 的 uncompressed encapsulated key 完成 P-256 ECDH，再按标准 HPKE
  key schedule、`info` 与空 AAD 验证并解开 16 字节 age file key；
- 认证失败、HPKE 失败、错误公钥、错误长度或取消均不返回 file key，也不恢复已消费请求；
- 解出的 file key 继续通过既有 request-bound 加密响应返回桌面，并按原顺序验证、持久消费和
  zeroize。

原始 stanza、共享秘密、HPKE key material、file key、请求/响应载荷和 QR 内容不得进入日志、
WebView 或安全诊断。

## 5. 兼容、迁移与失败策略

### 5.1 双读兼容

- 现有 public identity stub、locator、桌面密钥、replay 文件、Android/iOS 配对状态和协议 v2
  消息保持原编码；升级不要求重新配对。
- `identity-v1` 继续逐字节兼容 `phone-p256-v1/v2` 历史密文，并新增 `p256tag`，不改写旧文件。
- 省略 `--recipient-type` 或显式使用 `phone`，继续生成当前 pairing-specific v2 recipient
  与 stanza。
- 已配对用户运行 `recipients -i ... --recipient-type tag` 获得新公开地址；把它加入 recipient
  列表并通过仍可用的旧身份解密、重新加密，才完成密文迁移。
- recipient 配置变化不撤销历史密文访问；移除成员时仍需轮换上游真实凭据，并按独立恢复
  流程处理历史访问边界。

### 5.2 失败关闭

下列情况均终止当前解封，不得静默尝试 `age1phone`、另一 pairing、软件 identity、DPAPI、
Keychain、密码、TOTP、缓存授权或另一传输：

- malformed 或 ambiguous `p256tag`；
- phone/desktop 版本不支持 tag；
- locator、硬件密钥或 replay 状态缺失、损坏、不安全或不匹配；
- 手机拒绝、取消、超时、后台退出、断连或 HPKE 认证失败；
- 已创建请求后的发现、传输、响应或持久化失败。

旧移动应用收到不支持的 `p256tag` 请求时必须返回明确的 unsupported-recipient 错误或严格拒绝；
桌面不得把该错误解释成可回退信号。升级桌面和手机应用后，原配对状态继续有效。

### 5.3 隐私取舍

`age1tag` 按标准携带公开可测试的短 tag。知道 recipient 的观察者可以判断某个 stanza 是否可能
面向该 recipient，因此它弱于 phone v2 的私有 stanza selection。该 tag 不公开私钥、file key、
paired desktop 状态或用户授权，也不能替代 HPKE 认证。

默认 `phone` 继续避免 recipient-to-ciphertext 可测试性。需要无插件跨平台加密的用户显式使用
`--recipient-type tag`。文档不得把 `tag` 描述成在所有维度上取代或改进 `phone`；它优化的是
跨平台公开加密和部署依赖。

## 6. 版本与集成边界

tag 模式的最低加密客户端为 age 1.3。旧 age 客户端继续使用 `age1phone` 加上
`age-plugin-phone`，不能把不识别 `age1tag` 的错误降级成 phone 模式。状态和帮助输出应明确
报告 tag 能力与最低版本，但插件不负责安装或升级 age。

发布并宣传显式 tag 插件能力前必须完成以下交付：

1. desktop、Android 和 iOS 在同一兼容批次支持 `p256tag` 解封，已有配对无需重建；
2. age/rage 互操作、跨语言向量和指定真机验收完成；
3. 不安装或启动 Shine，通过插件通用 CLI 导出公开 recipient，并通过 age CLI 完成加密和
   手机授权解密；
4. 通用 CLI、`setup --json` 兼容回归和更新后的快速开始完成。

所有版本继续以 `phone` 为默认，不规划自动切换。插件发布不等待 Shine 或其他消费者同步
发布；对某个消费者的支持声明须有该消费者自己的集成证据。

Shine 通过通用 setup/recipient 导出接口取得 `age1tag` 与 identity 路径，再由标准 age 客户端
处理加解密。Shine 负责其加密路径的 age 1.3+ 要求和自身配置兼容；插件不检测 Shine、不解析
其 workspace、不增加专用参数或协议分支。`setup --json` schema 保持 v1，显式选择 tag 时
返回 `age1tag` 的消费者兼容性仍需验证。

本功能不改变项目当前实验状态。源码、软件或单平台测试通过不代表协议冻结、生产可用或所有
手机/桌面组合完成验收。

## 7. 实施顺序

1. 新增 ADR，记录 tag/phone 双模式、默认值、隐私取舍、无重配迁移和不回退策略；更新公共
   标准引用并固定互操作版本。
2. 在 core 增加 canonical `age1tag` 编码、`p256tag` 严格解析、公开 tag 计算和确定性向量；
   保持现有 phone recipient API 与向量不变。
3. 在 desktop 增加 recipient 类型 CLI、只读 `recipients` 命令、显式 stub 派生接口和
   `identity-v1` tag 选择；先完成无私钥和无用户提示的选择负面测试。
4. 在 Android 与 iOS 原生边界实现标准 HPKE Open，并接入现有 fresh-auth、请求消费和响应
   封装流程；WebView 和 Rust/Tauri 命令面不接触秘密材料。
5. 完成 age/rage、多 recipient、旧密文、升级、恢复和真机安全回归；记录精确候选制品摘要。
6. 更新 `architecture.md`、`protocol.md`、`threat-model.md`、README、roadmap、快速开始、发布
   指南和支持矩阵；发布通用显式 tag 工作流，默认值保持 `phone`。
7. 用同一候选插件验证 Shine 的实际使用路径，单独记录客户端版本和结果；问题在所属项目
   中修复，不能通过新增 Shine 专用插件接口绕过。

历史 ADR 和验收记录保持其当时含义。新 ADR 说明叠加关系，不把旧 phone v2 设计或证据改写成
已经覆盖 `p256tag`。

## 8. 测试与验收

### 8.1 确定性和互操作

- 增加 Rust/Kotlin/Swift 共用 `p256tag` 公开向量，固定 phone P-256 公私钥、ephemeral key、
  recipient、4 字节 tag、enc、body 和 16 字节 file key；逐字节匹配 age/C2SP 规范。
- Rust/Kotlin/Swift 的测试代码独立复现同一固定向量；生产代码不得使用向量私钥。
- Android StrongBox 和 iOS Secure Enclave 真机使用各自硬件生成的密钥，由标准 age 向其
  公开 recipient 加密并经真实硬件路径解封；不要求将固定向量私钥导入硬件。
- age 1.3+ 在 `PATH` 中没有 `age-plugin-phone` 时成功加密给 phone `age1tag`；对应插件 identity
  在已配对桌面完成解密。
- 与 age 1.3+ 和支持 tagged recipient 的 rage 版本分别互操作，固定并记录精确版本。

### 8.2 多 recipient 与选择

- 同一 age 文件包含 phone `age1tag`、Secure Enclave `age1tag` 和普通 age recipient，每个
  授权 identity 均能独立解密。
- 同时配置 `age-plugin-phone` 与 `age-plugin-se` identity 时，仅匹配的插件触发用户验证；
  未匹配 phone stanza 不联系手机，未匹配 SE stanza 不触发 Touch ID。
- 覆盖多个 phone identity、相同 phone 公钥的多个配对、不同 phone 公钥 tag 歧义、identity
  顺序和 stanza 顺序；行为严格符合第 4.2 节。
- 覆盖 tag 碰撞后的 HPKE 认证失败，证明 4 字节 tag 从不被当成解密成功。

### 8.3 兼容与迁移

- 回归现有 phone v1/v2 recipient/stanza 向量、public stub、locator、replay 和配对状态字节；
  省略 `--recipient-type` 与显式 `phone` 均输出 `age1phone`，加密结果保持兼容。
- 从升级前建立的配对导出 `age1tag`，不重新配对；先解开旧 phone 密文，再加密为 tag，并由
  同一手机 identity 解开。
- `setup --json` 仍是 schema v1；默认返回唯一 canonical `age1phone`，显式选择 tag 时返回
  唯一 canonical `age1tag`。
- 独立恢复 recipient 能在 phone 或 desktop 原状态不可用时恢复并重新加密；新配置不声称撤销
  历史密文。

### 8.4 负面与真机安全

- 拒绝错误 HRP、非 canonical Bech32/Base64、错误参数数目、错误 tag/enc/body 长度、无效
  P-256 点、修改的 tag/enc/body、错误 phone key、未知算法和受支持 stanza 的尾随字段。
- 未知 stanza tag 被忽略；malformed `p256tag` 在任何生物提示、网络、私有状态打开或 replay
  消费前失败。
- 覆盖错误设备、配对、签名、identity、请求摘要、nonce、expiry、响应和 replay，以及取消、
  超时、断链、后台/杀进程、持久化失败和时钟回退。
- Android 与 iOS 真机分别证明每次成功 tag 解封都创建新的系统用户验证上下文；未匹配
  stanza 无提示；失败不释放 file key、不恢复请求、不尝试另一身份。
- 执行现有 workspace locked 测试、Clippy 和格式检查；涉及手机代码时运行相应 Kotlin/Swift
  测试与构建。无安全硬件的 CI 必须记录未运行，不能以 skip 计为通过。

### 8.5 Shine 使用场景验收

- Shine 通过通用接口显式取得 `age1tag`，以标准 age recipient 保存和使用；默认 phone 路径
  保持兼容。
- 对全部 recipient 均可由 age 原生处理的 workspace，在未安装 phone 插件的机器上完成
  `seal`；若需解开旧 payload，使用该机器上已有且有效的其他 identity。
- 在已配对桌面通过 Shine 调用 age 解密，由 phone 插件和手机完成新鲜用户验证。
- 同一 recipient 和 identity 可脱离 Shine，通过 age CLI 完成对应加解密，不依赖 Shine
  进程、配置、环境变量或 RPC。

本节用于确认 Shine 中的目标体验，不改变标准插件的协议、实现完成定义或发布条件。

## 9. 完成定义

“实现完成”要求：两种 recipient CLI 和 stub 派生稳定；标准 `p256tag` 在三端通过向量；旧
phone 行为与状态回归通过；age/rage 无插件加密互操作通过；全部负面路径失败关闭；文档准确
披露隐私与版本要求。缺少 Android 或 iOS 必需真机证据时只能标记对应平台未验证。

“显式 tag 可发布”还要求第 6 节的插件交付完成；“Shine 中可用”要求第 8.5 节集成验收
完成，两者分别记录。默认 setup 继续返回 `age1phone`。实际发布、签名、上传或扩大生产
支持声明均是独立授权和验收动作，不因本文完成而自动发生。

## 10. 规范与先例

- [age 1.3+ 手册：Tagged recipients](https://github.com/FiloSottile/age/blob/main/doc/age.1.ronn#tagged-recipients)
- [C2SP age：p256tag recipient stanza](https://c2sp.org/age#the-tagged-recipient-types)
- [age-plugin-se：`tag` 与 `se` recipient](https://github.com/remko/age-plugin-se#converting-age-plugin-se-recipients-to-age-plugin-tag-recipients)
- [age-plugin-se：recipient、tag 选择和 identity 状态机](https://github.com/remko/age-plugin-se/blob/main/Sources/Plugin.swift)
- [age-plugin-se：HPKE 实现](https://github.com/remko/age-plugin-se/blob/main/Sources/HPKE.swift)
- [项目架构](architecture.md)
- [离线协议](protocol.md)
- [威胁模型](threat-model.md)
- [现有 P-256 recipient](adr/0001-experimental-p256-recipient.md)
- [标准 age 状态机](adr/0010-reference-age-state-machines.md)
- [私有 stanza selection](adr/0012-private-stanza-selection.md)
- [独立恢复与生命周期](adr/0017-lifecycle-and-recovery.md)
