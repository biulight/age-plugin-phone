# macOS 完整支持实施计划

日期：2026-09-09。状态：M3 / PR 4–5 的托管 setup、显式 pair ownership journal、resume、各类 journal 清理及入口检查已实现，
自动化和隔离硬件提交/CLI 清理测试通过，真实手机生命周期与恢复验收仍待完成，见 [M3 记录](macos-m3-evidence.md)。
本轮真机验收使用用户确认可用的 StrongBox Android，以及 iPhone 15 Pro（iOS 26.6.1）。
Android ADB 与 iPhone 前台 Wi-Fi 已分别通过 age / rage 的配对、独立原生验证、取消无明文和取消后重试；
两类手机的 age/rage QR 成功解密与逐次原生验证也已通过；Android QR 已确认使用 Mac 内建摄像头。
Android Wi-Fi 间歇发现失败尚未定位；QR 负面/权限、GUI 调用及其余生命周期矩阵仍待完成。
Android USB 拔线、自然超时、调用进程树终止，以及等待旧请求退出后的 ADB 服务重启均已通过无明文、清理和新验证恢复检查；立即启动 ADB 的首次失败记录仍保留。
独立恢复的六项 age/rage 测试已通过，见 M6 记录。
M5 的四 crate 独立归档、Rust 1.88 锁定安装、不同摘要覆盖重建、卸载及重装已通过；
原硬件引用和已消费 replay 保持不变，发布版本升级与 GUI 调用者仍待验收，见 [M5 记录](macos-m5-evidence.md)。
M4 的多网卡发现、失败处理和只读状态报告已先行实现，
完整传输/手机/调用者验收仍未完成，见 [M4 记录](macos-m4-evidence.md)。
PR 2 / M1 已实现双密钥后端与独立硬件 metadata，
验证及剩余门槛见 [M1 记录](macos-m1-evidence.md)；P3 / M2 存储实现及本机自动化已推进，
真实 APFS 满盘、SIGKILL 和实际重启后原状态验收已通过，旧状态回滚缺口已复现且仍未解决，见 [M2 记录](macos-m2-evidence.md)；PR 1 已加入隔离验证工具与 ADR 草案；M0 的 cargo install / CryptoKit 路径已通过本机验证，
本机锁屏/解锁、重启后登录重开、CLT 构建及并发/异常退出验证均已通过。
用户暂以本机为 M0 原生可行性验收基准；
跨设备和其他 OS 矩阵延期，不标记通过，也不阻塞本机后续验证与实施，
不扩大当前支持声明。见 [M0 验证记录](macos-m0-evidence.md) 和
[ADR 0025](adr/0025-macos-secure-enclave-m0.md)。
基线：`b4be976`，`0.1.0-alpha.4`。
M6 的最终候选 `cc7e120` 已通过四 crate 归档安装、硬件重装延续与 age/rage 合成互操作；
复审发现、手机制品与 age/rage 真机记录、待完成矩阵见 [M6 记录](macos-m6-evidence.md)；
源码使用步骤见 [macOS quick start](macos-quickstart.md)。M2 [范围决定](macos-replay-decision.md)
尚未批准，原要求保持有效。

## 1. 目标与交付边界

将 macOS 从软件密钥互操作原型提升为正式桌面目标：用户通过 `cargo install` 安装 CLI，完成能力检查、
配对、标准 age 加密和手机逐次授权解密，并能够升级、撤销、清理及执行独立恢复。
桌面签名和 stanza 选择私钥必须由本机 Secure Enclave 保管；手机长期 age 私钥仍只在手机，
每次 identity unwrap 仍由手机原生验证授权。Mac Touch ID 不替代手机验证，也不作为新增的
逐次桌面审批要求。是否安装 Touch ID 键盘不应决定具备 Secure Enclave 的 Mac 能否使用。

当前仅交付源码构建 CLI，不交付 `.app`、PKG 或预编译签名安装包；Developer ID、公证及
stapling 不属于本轮验收门槛。原生密钥访问若确需本地构建步骤，必须先证明其适合
普通 `cargo install` 用户，不能默认要求用户提供发布证书。

“macOS 支持完成”与“整个项目已适合生产秘密”是两个验收结论。协议冻结、公共 Alpha 和
项目级安全门槛继续遵循现有要求，不能因新增平台通过而自动宣布完成。

当前 M0 验收基准限定为 `MacBookPro18,3 / arm64 / macOS 26.6.2 (25G83)` 的
已登录用户会话。用户暂没有第二台 Mac，因此跨机复制拒绝测试延期记录，不能以本机换目录、
不同进程或不同构建代替；后续扩大支持范围前仍需补齐。首次解锁前/注销后的服务环境、
其他型号和 OS 不属于本次本机验收承诺。

硬件排期暂按 Apple Silicon 优先、Intel + T2 单独第二批验收；这是用户已确认的当前排期。
开发部署下限暂定 macOS 14.0，最终最低支持版本仍须在 M0 实测后确定，不能仅因 SDK 编译通过就宣布所有版本可用。
每个发布版本明确列出实际支持的系统版本和架构。未通过硬件验证的机器、虚拟机及旧款
Intel Mac 可以执行公共加密和说明性诊断，但不开放桌面配对/私钥操作，不降级到软件密钥。
其他 Intel 硬件若具备相关安全组件，仍须独立能力验证，不凭 CPU 架构或营销型号推定支持。

| 交付维度 | 完成标准 |
| --- | --- |
| Mac + Android | 具备合格 StrongBox 的真机完成 Wi-Fi、QR、显式 Developer USB 验收 |
| Mac + iPhone | 具备 Secure Enclave 的真机完成 Wi-Fi、QR 验收；iOS 不提供 ADB |
| 安装与调用 | `cargo install --locked` 安装 CLI；Terminal 和 GUI 应用经 age 调用均可用 |
| 密钥与状态 | 双角色硬件密钥、严格本机绑定、持久重放保护、完整失败与恢复路径 |
| CLI | `status`、`setup`、`setup --json`、resume/cleanup、显式 pair/unwrap 和两类状态清理 |
| 更新 | 源码重新编译和覆盖安装可继续使用原配对；安装或替换二进制不会自动删除密钥 |
| 实验状态退出 | macOS 产品路径不再读取旧的软件桌面私钥；旧原型用户有明确恢复说明 |

Android 与 iPhone 证据分开记录。可先交付完整的 Mac + Android 支持，但在 iPhone 实机矩阵和
适用的手机分发门槛通过前，不能宣布 Mac + iPhone 组合也已完整支持。BLE、手机后台唤醒和
非 ADB 的原生 USB 是另立项目的传输能力，不是此次平台移植所需的新传输。

## 2. 已有基础与缺口

- 已有四个发布 crate、P-256 操作接口、标准 age 协议、QR/ADB/Wi-Fi、macOS AVFoundation
  摄像头适配、Application Support 路径及 Unix 存储。
- 本次前置审查在 Apple Silicon Mac 上运行 PC 四 crate 测试：106 项通过；`status` 可运行。
  `setup --label … --json` 实测返回仅支持 Windows。这不是新增硬件后端的验收。
- `platform-keys` 只有 Windows 后端；`desktop::pairing` 的非 Windows 分支序列化两个
  桌面软件私钥。需要显式拆分 Windows、macOS 和其余实验平台的编译路径。
- setup、cleanup 和 journal 的原生持久化操作与 Windows 类型直接耦合。
- Unix 存储当前存在先检查路径后打开的顺序，重放文件与 locator 的硬链接检查也不同。
  升格产品支持前应审计并收紧，而不是只沿用 `0600`/`0700` 后声称拥有完整边界。
- 非 Windows Wi-Fi 发现目前仅向有限广播地址发送；多网卡需要单独适配和验收。
- 现有 macOS 构建、归档和历史手机互操作结果不覆盖新的硬件密钥、签名更新或完整生命周期。

来源：[架构](architecture.md)、[协议](protocol.md)、[威胁模型](threat-model.md)、
[四 crate 决策](adr/0024-four-desktop-crates.md)、[历史验证](desktop-refactor-evidence.md)。

## 3. 分阶段实施

### M0：确定 cargo install 原生密钥与支持矩阵

先完成小型、隔离状态的原生能力验证，再定后端实现，不创建用户正式配对。

- 原始 Rust/Security.framework 的 Data Protection Keychain 路径在无 entitlement 构建下失败。
  已通过本机验证的候选改为 CryptoKit 硬件封装引用，由小型 Swift 静态桥接提供，见 ADR 0025。
  隔离 Cargo 归档已验证原生构建输入完整；产品 FFI 仍应放在 `platform-keys::macos`，
  不把实验 CLI 的报告接口直接用作产品私钥操作接口。
- 验证独立 P-256 ECDSA 与 ECDH 密钥的生成、跨进程重新打开、签名、密钥协商、精确删除、
  不可导出，以及复制引用到另一台 Mac 后不可用。硬件封装引用的本地删除与硬件销毁
  必须区分：本机已观察到恢复复制的引用可恢复操作；手机撤销仍是权威边界。
- 决定 Keychain 模型、应用标识、签名要求、访问控制、禁同步/设备绑定策略及锁屏行为。
  Keychain 仅管理 Secure Enclave 项或引用，不保存可导出的桌面私钥作为替代。
- 在普通 CLI、age 子进程、GUI 应用启动的 age 子进程中验证 Keychain 行为；禁止通过扩大
  全局访问权限或接受任意调用者来消除权限问题。
- 验证两个独立源码构建及 `cargo install --force` 覆盖安装能打开同一密钥，覆盖代码哈希变化。
  先验证不依赖发布证书的 CLI 路径；若需要本地签名，明确构建步骤、权限和更新行为。
  当前 Data Protection Keychain 探针的 `-34018` 仅说明该方案受阻，不能推出所有硬件路径
  都需要 Developer ID。CryptoKit 硬件封装引用已通过无发布证书的本机重建/重装验证，
  跨设备绑定和生命周期剩余边界仍须验证，
  不得以可导出的软件私钥替代，也不能用自动回退隐藏原生失败。
- `status` 只探测非敏感能力，不创建或打开持久密钥；无法无副作用确定的能力报告为未验证。
  setup 内的实际创建和验证仍是最终门槛，探测结果不是授权。
- 建立 macOS 版本、Apple Silicon、Intel + T2、已登录用户会话、锁屏及无硬件环境矩阵。

产物：macOS 密钥/存储 ADR 草案、原生验证记录、源码安装与更新契约、最低 OS 版本决定。
出口：cargo install 形态下的双密钥持久化与重新构建/覆盖安装路径已验证；未解决的权限或硬件问题必须显式列出。

### M1：实现桌面 Secure Enclave 双密钥后端

主要落点：`crates/platform-keys`、`desktop/src/pairing.rs`、目标条件依赖。

- 实现现有 `P256Signer` 与 `P256KeyAgreement`，维持协议 v2 和四 crate 依赖方向。
  core/desktop 继续禁止 unsafe；原生句柄所有权和错误清理局限在平台包。
- ECDSA 接收已计算的 SHA-256 摘要，避免再次哈希；原生签名转为现有固定 64 字节、low-S
  `r || s`。公钥转为规范 33 字节 SEC1；ECDH 输出规范大端 32 字节结果并及时清零。
- signing 与 selection 使用不同随机密钥和角色引用，打开时核对硬件属性、公钥与本地绑定。
  不把两种角色合成一个密钥，不将 Secure Enclave 的支持范围等同于操作系统已强制角色限制。
- 本地 metadata 使用独立可识别的 macOS 硬件状态格式；只存引用和绑定信息。
  创建须 create-only；部分创建、丢失角色、引用篡改、算法错误均拒绝，打开不补建。
- 旧 `APDK2` 软件状态在 macOS 正常产品路径明确拒绝。软件实现保留在确定性测试或其他
  明确标记的实验平台中，不能通过普通 feature/env 开关恢复 Mac 产品降级路径。
- 更新依赖软件 `DesktopKeyState` 的测试边界，注入测试操作实现；不能让普通单元测试
  意外访问用户 Keychain，不能以删掉负面测试换取构建成功。

出口：双密钥独立性、不可导出、跨进程重开、错机复制、缺失/部分状态、签名与 ECDH
互操作测试通过；原有 Windows 后端行为与公开协议向量不变。

### M2：建立 macOS 私有状态与持久重放边界

主要落点：`platform-storage`、`core/src/protocol/replay.rs`、`desktop/src/locator.rs`。

- 使用 `~/Library/Application Support/age-plugin-phone` 的受保护直接子项布局；业务层继续
  拥有命名、编码、容量、scope 和状态机，存储层只处理有界字节与句柄。
- 根据 M0 结论提供显式 macOS 原语或经审计的 Unix 公共原语；不要把 Windows ACL 机械翻译为
  POSIX mode。审计 UID、ACL、类型、链接数、父目录及软链接竞争，使用相对目录句柄的安全
  打开方式/禁止跟随链接等机制实现检查与使用的一致性。
- 新建、原子替换、删除、独占锁与目录同步覆盖 replay、metadata、locator、临时文件和
  journal；验证 APFS 的实际持久化要求，包括是否需要 `F_FULLFSYNC`。
- 所有 uncertain write、同步失败、并发持有、缺失或损坏均使操作不可用；不能删除不确定
  journal 或把 replay 重建为空。准备目录不能先跟随不可信链接再修改权限。
- 明确备份排除、迁移助理和 Time Machine 恢复策略。复制到另一台设备必须因硬件绑定失败。
  同机恢复旧快照的重放回滚保证需要单独论证；备份排除或硬件密钥本身不是防回滚证明。
  若现有威胁模型要求覆盖而实现不足，必须解决或修订经审查的边界，不能将测试缺口标记通过。

出口：并发进程、硬/软链接、路径替换、ACL/权限放宽、磁盘满、同步失败、重启、时钟回退、
损坏/缺失/超限重放状态的负面测试通过；不影响其他配对，不产生可复用响应或明文输出。

### M3：完成 setup、标准 age 接入与生命周期

主要落点：`main.rs`、`setup.rs`、`cleanup_journal.rs`、`desktop_cleanup.rs`、`age_identity.rs`。

- 在 desktop 内提取小而明确的平台操作边界，复用已有 journal 状态机；密钥/存储实现
  保持各平台语义，避免扩展成通用插件框架。Windows 回归与抽取变更同时验证。
- 打通 `setup --label`、`--json`、`--resume`、`--cleanup`，自动分配路径与硬件键。
  stdout 成功时只输出现有版本 JSON；提示、完整指纹比较和恢复说明留在 stderr。
- 所有创建之前做平台及所选传输预检；完整签名 transcript 验证和双端完整指纹确认仍是
  提交前提。resume 只完成已经持久确认的提交，不恢复未确认配对。
- 显式 pair、显式 unwrap、标准 `identity-v1`、locator 打开均经过 Mac 硬件和待清理状态检查；
  公共 `recipient-v1` 加密不因本机没有硬件而被禁止。
- 实现 `remove-desktop-state` 和 `remove-orphaned-desktop-state`，保留完整指纹确认、
  精确目标、先 journal 后删除、可中断恢复与其他配对隔离。
- 验证 Keychain 丢失/锁定/重置、单角色丢失、换机、撤销、应用卸载及恢复说明。
  手机撤销与桌面删除保持不同作用域，安装器不静默删除用户密钥或配对。
- 硬件版本更新保持兼容；旧软件原型不能导入 Secure Enclave。提前说明先通过现有可用路径
  或独立恢复 recipient 恢复并重新加密，再撤销旧配对；不覆盖旧状态或假设新配对能开旧 v2 文件。

出口：完整命令闭环、每个 journal 转换点的故障注入、错误指纹/设备/身份/格式、取消/超时、
两个并发 age 进程及多配对隔离通过；软件原型状态不会被静默升级或擦除。

### M4：补齐 Mac 传输及调用环境

- Wi-Fi：实现必要的 macOS 接口枚举和定向广播，覆盖 Wi-Fi + 有线、VPN、接口变化、
  多候选、无候选、权限拒绝和断网。仍限现有 IPv4 LAN 契约，不借平台移植新建协议。
- 默认保持已定义的 `auto`：有界发现唯一匹配手机后选择 Wi-Fi；无监听才选 QR。
  权限/本地网络错误与歧义终止本次操作，不伪装成无监听。开始发送后不切换或重试通道。
- QR：验证内建与外接 UVC 摄像头、TCC 首次允许/拒绝/撤销、摄像头占用、取消和超时。
  按实际发布形态验证 usage description、必要 entitlement 和调用者权限归属。
- Android ADB：显式选择时验证设备授权状态、多设备、拔线、daemon 重启、Ctrl-C/杀进程、
  冷启动/后台自动唤醒与精确 reverse 清理；iPhone 不宣称支持该路径。
- 在 Terminal → age/rage → 插件以及 GUI 应用 → age → 插件两条链上验收网络和摄像头权限；
  不把 Terminal 成功当作 GUI 调用成功。拒绝权限时给出准确且不含敏感信息的诊断。
- 状态报告真实区分 OS、密钥后端、可用传输、未验收能力和错误，不继续输出容易被误读的
  全平台固定可用文案；BLE 继续明确不可用。

出口：支持矩阵内每条 transport/phone/caller 组合的正常及负面路径通过；手机每次仍新建
原生验证，取消、重放、超时与断链均无明文、缓存授权或传输残留。

### M5：cargo install 构建、安装和升级交付

- 首批验收 Apple Silicon 原生源码安装；Intel + T2 批次单独验收 x86_64 构建。
  不要求 universal 二进制，Rosetta 运行不替代 Intel 真机验收。
- Cargo 归档独立构建 PC 四 crate，执行最低 Rust 版本、锁定依赖和 registry 预检。
  确认所有原生构建输入包含在归档中，记录 Xcode/Command Line Tools 或桥接编译器要求，
  不依赖仓库外未声明文件、发布凭据或预装 App。
- 在干净环境验证 `cargo install --locked`、PATH、age 插件发现及首次 setup；如需要本地
  签名步骤，必须由 M0 证明可用并明确记录，不能把缺少发布证书当作预期用户环境。
- 验证独立源码重建、`cargo install --force`、版本升级和重新安装保留原配对及 replay。
  代码哈希变化不得静默重建密钥或清空状态；旧版回滚按兼容策略拒绝或给出可审查错误。
- `cargo uninstall` 只移除二进制，不删除密钥、配对或 replay；状态删除仍走显式产品命令。
- `.app`、签名 PKG、Developer ID 发布身份、公证、stapling 和 Homebrew 分发暂不在范围内；
  如以后交付预编译安装包，再单独增加对应验收。

出口：记录源码版本、工具链及实际安装二进制摘要，完成安装、覆盖升级、卸载和重新安装，
确认原键可重开且状态未被误删；源码构建通过不替代真机或安全验收。

### M6：精确制品验收、安全复审与文档

- 自动化：Rust fmt、workspace/all-target Clippy、locked workspace tests；协议向量、
  registry 归档/安装验证；涉及手机代码时增加相关 Kotlin/Swift 测试和构建。
- 原生硬件：在隔离临时状态中验证 Secure Enclave 生命周期及 源码重建后的密钥重开。
  托管 CI 若无安全硬件只能记录未运行；不能通过静默 skip 声称硬件通过。
- 真机配对：每种已声明支持的 Mac 架构、手机类型和传输均使用精确源码安装制品及摘要。
  年代/型号/OS/架构/手机版本/调用者/传输逐项记录，不能直接转用旧原型证据。
- 功能与安全：age/rage 多文件、多 recipient、多手机、两个桌面绑定同一手机、错机请求、
  跨请求响应、过期、未知版本/算法/字段、畸形支持 stanza 与忽略未知 tag。
- 原生授权：取消、验证失败后成功、锁屏、后台/杀进程、断网、超时、重启后重放。
  每次成功须观察新手机验证；已消费请求重放不得再次提示授权。
- 生命周期：逐配对撤销、正常/孤立清理、部分删除后重启、独立恢复及重新加密；新配对无法
  解开旧 v2 密文的失败行为也要验证。至少一次“原手机/原 Mac 不可用”的独立恢复演练。
- 对新增 Mac FFI、密钥属性、复制/回滚保证、持久化、更新签名和权限边界做针对性安全复审；
  原有审查没有覆盖新增实现，公共声明前需关闭新增可执行发现。
- 更新 README、architecture、protocol 中的平台说明、threat model、roadmap、相关 ADR、
  安装/发布指南与包描述；新增 macOS 快速开始、硬件矩阵、恢复指南和版本验收记录。

出口：所宣布支持范围内无未验证必需行；记录完整指纹由用户比较、手机验证由用户执行，
自动化不得替代这些产品确认。未通过的范围明确保留实验状态。

## 4. 建议 PR 顺序与依赖

| PR | 内容 | 前置与可验收结果 |
| --- | --- | --- |
| 1 | M0 原生验证与 ADR | 明确 cargo install 密钥持久化、重建升级、OS/硬件范围；早发现阻塞 |
| 2 | M1 Secure Enclave 后端 | PR 1；现有 core 接口通过原生测试，Mac 软件状态被拒绝 |
| 3 | M2 Mac 存储与 replay | PR 1；路径/ACL/原子持久化/故障测试通过 |
| 4 | M3 setup 与 age 入口 | PR 2、3；完整配对、JSON、resume/cleanup、标准 unwrap |
| 5 | M3 撤销、孤立清理、恢复 | PR 4；完整 journal 故障矩阵及升级/旧原型处理 |
| 6 | M4 传输与 TCC 诊断 | PR 1 后可准备；与 PR 4、5 集成后做端到端验收 |
| 7 | M5 cargo install 构建、安装升级 | PR 1 确定原生路径后即可准备；使用 PR 2–6 最终代码验收 |
| 8 | M6 精确制品、安全复审与文档 | PR 2–7；通过后才扩大平台支持声明 |

关键路径：源码 CLI 硬件验证 → 密钥与存储 → 配对/解密/生命周期 → cargo install 制品 → 真机与复审。
源码构建下的密钥重开必须前置，不能在全部 Rust 功能完成后才第一次验证覆盖安装。
Intel + T2 和 iPhone 可以分批验收，但相应完整支持声明必须等待本批出口条件。

已按阶段推进 PR 1–7 的实现和本机自动化，并进入 PR 8 的复审与验收准备；仍不等于完整 macOS 产品验收完成。当前计划不承诺固定日历工期；根据硬件、原生构建路径、OS
矩阵和手机可用性估算。额外真机和用户在场的原生确认是外部依赖，可先完成全部
不依赖它们的实现与测试，剩余门槛保持明确的未完成状态。

## 5. Apple 原始资料与待验证事项

- Apple 说明 Secure Enclave 支持 P-256 签名/ECDH 且不能导入既有明文私钥；这支持复用当前
  P-256 操作接口，也意味着旧软件私钥不能直接转换为硬件密钥。
  [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- Apple 的硬件安全概览列出 Apple Silicon 和带 T2 的 Mac；是否可用于本项目仍由原生能力
  与签名环境实测确定。[Hardware security overview](https://support.apple.com/guide/security/hardware-security-overview-secf020d1074/web)
- macOS Keychain 的访问模型与 entitlements 相关，应通过最终 CLI 构建形态验证。
  [Sharing access to keychain items](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
- macOS 对 Terminal/SSH 命令行与 GUI 发起的子进程有不同局域网权限处理；此处计划据此
  要求两条调用链独立验收。[TN3179](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy)
- 以下 Developer ID、公证资料仅供未来预编译包分发参考，不是当前 cargo install 的门槛。
  本轮原生访问属性、最低系统和构建要求仍由 M0 实测确定。
  [Developer ID](https://developer.apple.com/developer-id/)、
  [Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
