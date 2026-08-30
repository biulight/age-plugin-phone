# Android StrongBox P-256 ECDH PoC

状态：Result A 已通过，`strongbox_p256_auth_per_use: supported`。本 PoC 只验证设备能力，
不处理真实 age identity、file key 或业务明文。

## 1. 目标

验证 Android 手机能否提供下面这条生产候选路径：

```text
StrongBox 中不可导出的 P-256 私钥
    ↓
每次 ECDH 运算都绑定独立 BiometricPrompt
    ↓
用户批准后仅执行当前一次私钥运算
    ↓
未来用于解开单个 age tagged-recipient stanza
```

只有完整通过本 PoC，项目才进入 P-256 age tagged recipient、QR 配对和桌面插件联调。
“设备声明 StrongBox”“可以生成 EC 密钥”或“单独弹出过生物认证”都不等价于通过。

## 2. 已知测试基线

2026-08-24 已通过 ADB 确认：

| 项目 | 结果 |
| --- | --- |
| 设备 | Samsung `SM-F9660` |
| Android | 16 |
| API level | 36 |
| `android.hardware.strongbox_keystore` | `true` |
| CPU/Android target | `aarch64-linux-android` |
| Tauri App ID | `io.github.biulight.age_plugin_phone` |
| Tauri/Vite 开发启动 | 已成功 |
| 构建 JDK | 必须使用 JDK 17；默认 JDK 26 与当前 Gradle/Groovy 不兼容 |

开发启动命令：

```bash
mise install
cd apps/mobile
mise exec -- bun run tauri android dev
```

在 shell 中启用 `mise activate` 后，进入仓库时会自动设置 `JAVA_HOME`，也可以省略
`mise exec --` 前缀。IDE 需要继承该环境，或在配置变更后从已激活的终端重新启动。

Android 官方文档说明 StrongBox 的算法集合包含 P-256 ECDH，Android Keystore 提供
`PURPOSE_AGREE_KEY`、每次使用认证和 `KeyInfo` 安全级别查询。但
`BiometricPrompt.CryptoObject(KeyAgreement)` 属于较新的平台能力，必须在当前系统镜像上
实际编译和运行，不能根据 API level 推断成功：

- [Android Keystore](https://developer.android.com/privacy-and-security/keystore)
- [KeyGenParameterSpec.Builder](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder)
- [KeyInfo](https://developer.android.com/reference/android/security/keystore/KeyInfo)
- [BiometricPrompt.CryptoObject](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.CryptoObject)

## 3. 非目标

本轮不实现：

- age tagged recipient 或完整 age 文件解密；
- 手机与 Windows 配对；
- QR、BLE、NFC 或 USB 协议；
- iOS Secure Enclave；
- 密钥备份、恢复、同步或跨手机迁移；
- Google Passkey、Google Authenticator 或在线服务；
- Android 硬件密钥远程认证服务；
- TEE/软件密钥的自动降级；
- 任何真实秘密的保存、传输或显示。

## 4. 安全判定边界

PoC 必须同时证明：

1. P-256 私钥由 Android Keystore 生成且不可导出。
2. `KeyInfo.securityLevel` 明确为 `STRONGBOX`。
3. 密钥用途包含 `PURPOSE_AGREE_KEY`。
4. 用户认证为 auth-per-use，缓存时长为零。
5. ECDH `KeyAgreement` 本身被交给 `BiometricPrompt.CryptoObject`，而不是先弹一个与运算无关的认证框。
6. 每次 `generateSecret()` 前都必须完成新的系统认证。
7. 取消、超时、切后台、错误公钥和重复调用均失败关闭。
8. ECDH shared secret 不离开 Kotlin/Rust 可信边界，不进入 WebView、日志或测试输出。

通用 Tauri biometric 插件只能返回“认证成功”，不能证明后续私钥运算绑定了该认证，因此
不能作为本 PoC 的密码学实现。必须使用原生 Kotlin Tauri plugin 调用 Android Keystore 和
`BiometricPrompt`。

## 5. 代码结构

新增独立的 App 内部 Tauri plugin，建议结构：

```text
plugins/tauri-plugin-phone-identity/
├── Cargo.toml
├── src/
│   ├── lib.rs                 # Tauri plugin 注册和安全的结果模型
│   ├── mobile.rs              # Rust → Kotlin 调用边界
│   └── models.rs              # 非敏感 Doctor 输出
├── android/
│   ├── build.gradle.kts
│   └── src/main/java/.../
│       ├── PhoneIdentityPlugin.kt
│       ├── StrongBoxDoctor.kt
│       └── ProbeKeyStore.kt
└── permissions/
    └── default.toml
```

Tauri WebView 只展示以下非敏感状态：

- 设备/API 能力；
- StrongBox/认证配置检查结果；
- 每次操作成功、取消或错误类型；
- 临时探针密钥是否已删除。

WebView 不得接收：

- 私钥、公钥编码以外的密钥材料；
- ECDH shared secret 或其可离线利用的派生值；
- `CryptoObject`、operation handle 或 Android 认证 token；
- 原始协议负载；
- 探针密钥 alias 的完整随机部分。

## 6. Tauri 命令边界

PoC 暴露四个命令即可：

```text
doctor_capabilities() -> CapabilityReport
doctor_create_probe() -> ProbeKeyReport
doctor_run_agreement() -> AgreementReport
doctor_cleanup() -> CleanupReport
```

命令语义：

### `doctor_capabilities`

只读检查：

- Android release、API level 和 SDK extension level；
- `FEATURE_STRONGBOX_KEYSTORE`；
- `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)`；
- 设备是否设置安全锁屏；
- 当前平台/AndroidX 是否暴露 `CryptoObject(KeyAgreement)`。

不得用 `FEATURE_STRONGBOX_KEYSTORE=true` 直接推导 ECDH 一定成功。

### `doctor_create_probe`

生成一个随机且可精确清理的临时 alias：

```text
age-plugin-phone-poc-<random UUID>
```

建议的密钥参数：

```kotlin
KeyGenParameterSpec.Builder(
    alias,
    KeyProperties.PURPOSE_AGREE_KEY,
)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setIsStrongBoxBacked(true)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(
        0,
        KeyProperties.AUTH_BIOMETRIC_STRONG,
    )
    .setInvalidatedByBiometricEnrollment(true)
    .build()
```

第一轮仅接受 `AUTH_BIOMETRIC_STRONG`，避免把设备凭据 fallback 与 ECDH CryptoObject 支持
混在同一个结论里。PIN/图案/密码支持应在主路径通过后单独探测。

不得捕获 `StrongBoxUnavailableException` 后自动去掉 `.setIsStrongBoxBacked(true)` 重试。
该异常是明确的负向结果。

生成后通过 `KeyInfo` 返回以下布尔/枚举值：

```text
generated
security_level
origin_generated
purpose_agree_key
user_authentication_required
auth_per_use
authentication_type
auth_enforced_by_secure_hardware
private_key_format_is_null
private_key_encoded_is_null
```

通过要求：

- `security_level == STRONGBOX`；
- `origin == GENERATED`；
- `PURPOSE_AGREE_KEY` 存在；
- `isUserAuthenticationRequired == true`；
- 有效期为 auth-per-use，而不是正数授权窗口；
- `privateKey.format == null` 且 `privateKey.encoded == null`。

### `doctor_run_agreement`

每次调用都在 Kotlin 原生层完成：

1. 生成一个仅用于本次测试的软件临时 P-256 peer key pair。
2. 从 Android Keystore 读取探针私钥。
3. 初始化 `KeyAgreement.getInstance("ECDH", "AndroidKeyStore")`。
4. 用探针私钥初始化 `KeyAgreement`。
5. 将该 `KeyAgreement` 包装为 `BiometricPrompt.CryptoObject`。
6. 显示系统认证 UI。
7. 只从 `onAuthenticationSucceeded` 返回的 `CryptoObject` 继续执行 `doPhase()` 和
   `generateSecret()`。
8. 用 peer 私钥和探针公钥在原生层计算反向结果。
9. 使用常量时间比较确认两端 ECDH 结果一致。
10. 立即清除两个临时 shared secret 和 peer 私钥引用。
11. 只向 Rust/WebView 返回 `agreement_match: true/false` 和错误分类。

禁止将 shared secret 做 Base64、十六进制、hash 后返回。即使 hash 不是原秘密，也没有
必要让可重复验证材料进入 WebView 或日志。

### `doctor_cleanup`

只删除当前 PoC 进程创建并记录的、前缀和 UUID 均通过严格校验的 alias。不得枚举后按
模糊前缀批量删除，也不得删除未来的生产 identity。

返回：

```text
probe_key_existed
probe_key_deleted
probe_key_absent_after_delete
```

App 启动时如果发现上次崩溃遗留的 PoC alias，应显示“可清理”状态，但仍需用户明确操作。

## 7. Doctor UI

增加一个只在开发构建显示的 `Device Doctor` 页面：

```text
Android StrongBox Doctor

Device
  Android 16 / API 36
  StrongBox feature                 yes
  Strong biometric                 available
  KeyAgreement CryptoObject        unknown

Disposable probe key
  [Create probe key]

Private operation
  [Run approval #1]
  [Run approval #2]
  [Run and cancel]

Lifecycle
  [Verify after app restart]
  [Delete probe key]
```

按钮必须串行执行。认证进行中时禁止启动第二次操作。切后台、旋转屏幕、Activity 重建或
Tauri command 被取消时，未完成的请求必须失败并释放状态。

调用方名称、按钮文字和页面状态都不是安全输入。真正绑定认证的是 Android
`CryptoObject` 中的 `KeyAgreement`。

## 8. 测试矩阵

### A. 静态能力

| 用例 | 预期 |
| --- | --- |
| StrongBox feature 查询 | `true` |
| `BIOMETRIC_STRONG` 查询 | 可用，否则主路径阻塞 |
| 生成 P-256 `PURPOSE_AGREE_KEY` | 成功且无 fallback |
| `KeyInfo.securityLevel` | `STRONGBOX` |
| 私钥导出 | `format == null`, `encoded == null` |
| auth timeout | 每次使用，不是时间窗口 |

### B. 用户确认

| 用例 | 预期 |
| --- | --- |
| 第一次批准 | 出现系统认证，ECDH 匹配 |
| 紧接着第二次批准 | 再次出现独立系统认证，ECDH 匹配 |
| 用户取消 | 返回稳定的 `user_cancelled`，不执行/返回 ECDH 结果 |
| 认证失败 | 密钥运算不可继续 |
| 认证超时 | 失败关闭 |
| Prompt 显示时切后台 | 失败关闭 |
| 同时发起第二个请求 | 第二个请求被拒绝，不排队继承授权 |

### C. 生命周期

| 用例 | 预期 |
| --- | --- |
| App 重启后再次使用探针密钥 | 密钥仍存在，但必须重新认证 |
| 手机锁定再解锁 | 不产生授权缓存 |
| 新增/删除生物信息 | 按配置使探针密钥永久失效 |
| 删除探针密钥 | alias 不再存在 |
| 删除后再次运算 | `key_not_found`，不得新建或 fallback |

### D. 负向输入

| 用例 | 预期 |
| --- | --- |
| 非 P-256 peer 公钥 | `invalid_peer_key` |
| 无效编码/无穷远点/错误曲线点 | 在私钥运算前拒绝 |
| 旧 operation handle | 拒绝 |
| Activity 重建后的旧 callback | 拒绝 |
| 软件或 TEE 密钥 | 报告准确安全级别，不计为 StrongBox 通过 |

## 9. 验收标准

只有满足全部条件才记为 `strongbox_p256_auth_per_use: supported`：

- disposable StrongBox P-256 ECDH key 创建成功；
- `KeyInfo` 证明密钥位于 `STRONGBOX` 且用途、来源、认证配置正确；
- 两次连续成功操作各自显示独立系统认证；
- 两次 ECDH 均在原生层得到匹配结果；
- 用户取消稳定失败且没有任何可用输出；
- App 重启后仍然要求新认证；
- 私钥、shared secret 和认证材料未进入 JS、日志、argv、环境变量或文件；
- 清理只删除 PoC 自己的 alias，并验证删除完成。

下面任一情况都不能算通过：

- 只返回 `FEATURE_STRONGBOX_KEYSTORE=true`；
- 密钥实际位于 TEE 或软件层；
- 生物认证和 ECDH 是两个独立步骤；
- 第二次操作复用第一次认证；
- 取消后仍能执行 `generateSecret()`；
- 为了成功而自动切换密钥用途、认证窗口或安全级别。

## 10. 决策树

### 结果 A：完整通过

选择硬件 P-256 主路径：

```text
StrongBox P-256 identity
    ↓
age tagged recipient
    ↓
手机只解开当前 stanza/file key
```

下一份 PoC 实现 age tagged recipient 测试向量和桌面/手机两端 unwrap，不立即加入 QR。

### 结果 B：StrongBox P-256 ECDH 可用，但无法绑定每次认证

不得使用未绑定认证的 ECDH。评估备选：

```text
StrongBox AES-GCM auth-per-use key
    ↓
包装手机本地 X25519 age identity
    ↓
BiometricPrompt(Cipher) 每次解包
    ↓
X25519 identity 只短暂进入手机原生内存
```

该备选需要独立 PoC 和威胁模型，不能在本 PoC 中静默启用。

### 结果 C：只有 TEE 成功

报告 `strongbox: unsupported, tee: available`，由产品策略明确决定是否接受 TEE。
PoC 不自动降级，也不能把 TEE 结果显示为 StrongBox 成功。

### 结果 D：认证无法和任何合适的私钥运算绑定

停止 Android 本地硬件主路径，保留失败记录，不进入 QR/BLE 开发。

## 11. 日志和错误分类

允许输出：

```text
unsupported_api
strongbox_unavailable
strong_biometric_unavailable
key_generation_failed
wrong_security_level
user_cancelled
authentication_failed
authentication_timeout
invalid_peer_key
key_permanently_invalidated
key_not_found
agreement_failed
agreement_mismatch
cleanup_failed
```

禁止输出：

- 完整 alias UUID；
- 私钥或 shared secret；
- peer 私钥；
- 原始公钥之外的调试密钥数据；
- Android authentication token；
- 可重放 operation handle；
- QR/协议 payload；
- 用户生物特征或锁屏信息。

错误必须保留根因供本地 UI 分类，但 release 日志不能包含底层异常中可能携带的敏感参数。

## 12. PoC 完成物

- 原生 Kotlin Tauri plugin；
- 开发构建中的 `Device Doctor` 页面；
- 非敏感、可复制的 Doctor 报告；
- 本文测试矩阵的逐项结果；
- 探针密钥清理证明；
- 根据结果 A/B/C/D 更新 `docs/architecture.md` 和 `docs/roadmap.md`；
- 若选择生产密码结构，新增独立 ADR/设计文档和公开测试向量。

在本 PoC 完成前，不实现 QR、BLE，也不使用真实 age identity 或业务秘密。

## 13. 实施记录

2026-08-24 已完成：

- 独立 `tauri-plugin-phone-identity` Rust/Kotlin 插件和四个 Doctor 命令；
- 严格限定 disposable UUID alias 的创建、持久记录和精确清理；
- StrongBox、`KeyInfo`、不可导出性和 auth-per-use 配置报告；
- 通过运行时反射探测 Android 36.1 `CryptoObject(KeyAgreement)`，缺失时明确返回
  `unsupported_api`，不采用分离认证或 TEE fallback；
- 认证成功回调中的同一个 `KeyAgreement` 才能继续 ECDH，shared secret 仅在 Kotlin
  内存中常量时间比较并立即清零；
- 取消、认证失败、60 秒超时、切后台、Activity 销毁、并发请求和旧 callback 均失败关闭；
- 仅在 debug 构建注册的 Device Doctor 页面和可复制非敏感报告；
- alias、错误公钥、取消和超时分类的负向单元测试。

已通过的非设备验证：

- `cargo fmt --check`；
- `cargo clippy --workspace --all-targets -- -D warnings`；
- `cargo test --workspace`；
- `bun run build`；
- Kotlin debug 编译和 `testDebugUnitTest`；
- arm64 debug APK 组装和安装。

同日已在 Samsung `SM-F9660`（Android 16、API 36、SDK extension 21）完成 Result A
设备验收：

| 验收项 | 设备结果 |
| --- | --- |
| StrongBox / strong biometric / secure lock screen | 均可用 |
| `CryptoObject(KeyAgreement)` | 可用 |
| P-256 探针密钥 | `STRONGBOX`、`GENERATED`、`PURPOSE_AGREE_KEY`、auth-per-use |
| 私钥不可导出 | `format == null`、`encoded == null` |
| 连续批准两次 | 每次均出现独立系统认证，原生 ECDH 均匹配 |
| 用户取消 | `user_cancelled`，无 ECDH 结果 |
| App 强制停止并重启 | 探针密钥仍存在；再次运算重新显示系统认证且 ECDH 匹配 |
| 精确清理 | 仅删除已记录的探针 alias，删除后确认不存在 |
| 删除后运算 | `key_not_found`，未重建且未 fallback |
| 进程日志敏感词检查 | 未发现 alias、私钥、shared secret、raw payload 或 operation handle |

因此本机结论为：

```text
strongbox_p256_auth_per_use: supported
decision: Result A
```

认证失败、60 秒自然超时、Prompt 期间切后台、并发请求、锁屏后解锁、生物信息变更和全部
畸形曲线点等扩展场景尚未逐项做设备手工验证；相应失败关闭逻辑及可自动化的负向用例已由
代码和单元测试覆盖。这些项目继续作为生产化前的扩展设备矩阵，不影响第 9 节 Result A
核心验收结论。

### Tagged-recipient 纵向扩展

2026-08-24 在同一设备上进一步验证了
[`ADR 0001`](adr/0001-experimental-p256-recipient.md) 的实验构造：

1. Kotlin 与 Rust 使用同一公开确定性向量，压缩 P-256 公钥、stanza argument、body 和解包
   结果逐字节一致。
2. Doctor 在 Kotlin 原生层生成随机 synthetic file key 和一次性 P-256 ephemeral key，按
   ADR 执行 ECDH、HKDF-SHA256 和 ChaCha20-Poly1305 stanza 包装。
3. Doctor 在原生内存中构造并校验规范 CBOR 签名请求；同一个 stanza 只能在系统生物认证
   成功回调返回的 StrongBox `KeyAgreement` 完成后解包。
4. 解包结果不会裸露给调用方，而是通过一次性 desktop session key 封装为绑定 desktop、
   identity、request digest 和 nonce 的加密响应，并由 Doctor 的模拟桌面端解密比对。
5. 设备报告 `authenticated: true`、`agreementMatch: true`、`responseEnvelopeMatch: true`；file
   key、shared secret 和 wrapping key 均未返回 WebView。
6. disposable 探针随后精确删除并确认不存在；限定 App PID 的日志扫描未发现禁止材料。

该扩展仍是随机合成数据的 Doctor 验证，不是生产 identity、真实 age 文件或桌面传输实现。

### 配对状态与重放 scope 扩展

同日按 [`ADR 0004`](adr/0004-android-pairing-state.md) 实现 Android 原生配对状态边界：公开
配对记录与 request replay entries 共同存入 `Context.noBackupFilesDir` 下的单个规范 CBOR
文件，并以独占锁、同目录临时文件、文件 `fsync`、原子替换和目录 `fsync` 提交。打开缺失、
错误 scope、损坏、非规范、权限过宽、容量耗尽、时钟回退或写入不确定的状态都会在系统认证
前失败关闭。

新增的存储 Doctor 只使用新生成的 synthetic 软件密钥和 file key，验证创建、验签后持久
consume、关闭并重开后的 replay 拒绝、错误 scope、删除后缺失以及精确清理。WebView 仅接收
非敏感布尔结果和错误分类；路径、标识符、alias、请求、stanza 与 QR 内容均不返回。

原生 pairing confirmation session 进一步把规范 signed offer/response 的完整验签、完整
transcript fingerprint 展示模型和原子创建串成一次性状态机。fingerprint 不匹配、取消、重复
确认、已有配对或落盘失败都会关闭 session；重试必须重新扫描。原始 signed transcript 只由
未来的原生 QR transport controller 传入，不作为 Tauri command 参数，也不进入 WebView。

按 [`ADR 0005`](adr/0005-qr-framing.md) 增加原生 QR framing：规范 CBOR + unpadded base64url
文本帧，最多 64 KiB、128 帧、每 chunk 600 bytes，首帧起 30 秒超时。乱序和相同重复帧可
重组；冲突、超时、时钟回退、布局/长度或完整消息 digest 错误会清空并 poison assembly，
必须显式 reset。Doctor 使用多帧 synthetic pairing transcript 验证乱序重复重组、损坏拒绝
与超时拒绝，然后才进入 pairing confirmation；原始 QR 字符串不返回或记录。

同日在 Samsung `SM-F9660` 真机逐步复测。最终报告中 QR 分片、逆序重复重组、损坏拒绝、
超时拒绝，transcript 验证、错误 fingerprint 拒绝、取消拒绝、确认提交、重复确认拒绝，以及
原子状态创建、consume 前验签、重启后 replay 拒绝、错误 scope 拒绝、删除后缺失、清理完成和
no-backup 存储共十六项全部为 `true`，`errorCategory == null`。随后通过应用沙箱独立确认
Doctor 专用目录不存在；限定本次 App PID 的完整日志过滤未发现 key、payload、stanza、QR、
alias、signed transcript 或 encoded frame 等禁止材料标记，崩溃日志过滤也为空。

### 原生相机 QR capture 扩展

2026-08-25 按 [`ADR 0006`](adr/0006-native-qr-capture.md) 在同一设备验证 CameraX + 离线
ML Kit 连续扫码控制器。系统相机授权成功；显式取消返回 `user_cancelled`，整体扫描 deadline
返回 `scan_timeout`。桌面使用 disposable P-256 签名 offer 和 80-byte chunk 生成三帧本地
SVG 动画，手机在八次帧观测后完成重组和验签，报告 `messageVerified: true`、预期的不可信
desktop label、与桌面完全一致的 offer digest，且 `errorCategory == null`。

完成后 CameraService 的 active client 列表为空。限定本次 App PID 的日志扫描未发现 QR
前缀、raw frame、signed offer、key 或 payload，修复版进程无崩溃标记，Doctor 目录仍不存在。
该扩展只验证 signed offer capture，不生成 phone response，也不创建真实配对。
