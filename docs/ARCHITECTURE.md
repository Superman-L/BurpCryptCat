# BurpCryptCat · 架构与实现细节

本文是 [README](../README.md) 的技术展开：模块划分、关键算法、Burp 集成点、以及几个绕不开的设计取舍。
代码级索引按"类 / 方法"给出，方便直接跳读。

---

## 0. 一张图

```
                        ┌─────────────────────────── BurpCryptCat ───────────────────────────┐
   密文请求 ──►  Proxy   │  CryptoProxyHandler.handleRequestReceived   (解密 → 历史/编辑器明文)  │
                        │  CryptoProxyHandler.handleRequestToBeSent   (加密 → 线上密文)          │
                        │                                                                       │
   Repeater/Intruder ──►│  CryptoHttpHandler.handleHttpRequestToBeSent (明文 → 加密)             │
   Scanner/其它插件  ──►│                                                                       │
                        │  CryptoHttpHandler.handleHttpResponseReceived (密文 → 解密)            │
   密文响应 ◄────────── │  CryptoProxyHandler.handleResponseReceived  (解密 → 历史明文)          │
                        │  CryptoProxyHandler.handleResponseToBeSent  (加密 → 客户端密文)        │
                        │                                                                       │
                        │  UI: MainTab / ProfilePanel / RulePanel / LogPanel / SettingsPanel     │
                        │      CryptoEditors(明文页签) / CryptoMenu(右键) / MessagePrinter        │
                        └───────────────────────────────────────────────────────────────────────┘
                                     │                          ▲
                      读/写  ~/.BurpCrypto/config                │ 只读同一份配置
                                     ▼                          │
                        ┌───────────────────────────┐   ┌───────────────────────────────────┐
                        │ ConfigFile / ConfigStore  │   │ xia SQL 3.3 + xiabridge 桥接层     │
                        └───────────────────────────┘   │ 入口解密 → 注入 → 发包加密         │
                                                        └───────────────────────────────────┘
```

---

## 1. 主插件

### 1.1 包结构

| 包 | 职责 | 关键类 |
|---|---|---|
| `burp` | 入口装配 | `BurpExtender` |
| `burp.crypto` | 纯算法层（不依赖 Burp） | `CipherSpec` `CipherCatalog` `KeyMaterial` `Codec` `SymmetricEngine` `Sm4` `BlockModes` `Padding` `CryptoEngine` |
| `burp.script` | 四阶段脚本接口（JS / 外部命令） | `ScriptStage` `ScriptCall` `ScriptOutcome` `ScriptRuntime` `JsScriptRunner` `CmdScriptRunner` `ScriptUtils` |
| `burp.config` | 配置模型与持久化 | `AppConfig` `Profile` `Rule` `ConfigFile` `ConfigStore` |
| `burp.transform` | 业务转换层（不依赖 Burp） | `MessageTransform` `BodyTransformer` `TargetResolver` `CryptoService` `TransformResult` `PlaintextLog` `JsonField` `BodyCodec` `PlainTextFormatter` |
| `burp.http` | Burp 集成 | `CryptoHttpHandler` `CryptoProxyHandler` `HandoffCache` `ToolGroups` |
| `burp.ui` | 界面 | `MainTab` `ProfilePanel` `RulePanel` `LogPanel` `SettingsPanel` `CryptoEditors` `MessagePrinter` `CryptoMenu` `Ui` `UiContext` |
| `burp.support` | 日志/诊断 | `Log` `StatusFile` |

分层原则：`crypto` / `transform` **不 import 任何 `burp.api.*`**，因此可以被单元测试直接覆盖；
只有 `http` / `ui` / 入口类接触 Burp。

### 1.2 配置层

**模型**：`AppConfig{ masterEnabled, fallbackProfileId, tools, logLimit, proxyEnabled,
proxyReencryptRequest, proxyReencryptResponse, debug, beautifyJson, profiles[], rules[] }`

**INI 格式**（`~/.BurpCrypto/config`）：

```ini
# 文件头：路径 + 时间（扩展保存时重写）
[global]
master=true
tools=PROXY,REPEATER,INTRUDER,OTHER      # 也接受简写 tools=ALL
proxyEnabled=true  proxyReencryptRequest=true  proxyReencryptResponse=true
[profile]      # 可重复
id=sample  name=示例  cipher=AES/CBC/PKCS5Padding  key=…  keyFormat=UTF8
iv=…  ivFormat=UTF8  ivMode=AUTO  bodyEncoding=BASE64  bodyScope=WHOLE
jsonField=data  charset=UTF-8  onRequest=true  onResponse=true
[rule]         # 可重复，顺序即优先级
enabled=true  matchType=HOST|URL_GLOB|URL_REGEX  pattern=*  profile=<id>
onRequest=true  onResponse=true
```

* 值支持 `\n`/`\\` 转义（Key 里带换行也不会坏）
* `ConfigFile.write`：**写临时文件 → `ATOMIC_MOVE` 替换**，替换前把旧文件留成 `config.bak`
* `ConfigFile` 还会尽力把目录/文件权限收紧到 `700/600`（POSIX；Windows 忽略）
* `ConfigStore` 只在 Burp Preferences 里存**一个目录指针**（`burpcrypto.config.dir`），
  并从旧版键 `burpcrypto.body.config.ini` **一次性迁移**（迁移后删除旧键，避免"复活"覆盖新文件）

### 1.3 三种加解密方式（Engine）

`Profile.engine`：`BUILTIN`（内置算法）/ `SCRIPT_JS`（Rhino 脚本）/ `SCRIPT_CMD`（外部命令）。
分派点在 `MessageTransform.apply()`：

```java
if (profile.isScript())  → ScriptRuntime.run(profile, stage, call)   // 四阶段脚本
else                     → stage.builtinEncrypt()
                              ? BodyTransformer.encrypt(...)          // 加密方向
                              : BodyTransformer.decrypt(...)          // 解密方向
```

**阶段与脚本接口的映射**（`CryptoService.Phase.stage()`）：

| Phase（Proxy 四阶段） | ScriptStage | 脚本函数 | 内置算法语义 |
|---|---|---|---|
| `REQUEST_DECRYPT` | `CLIENT_TO_BURP` | `clientToBurp(ctx)` | 解密 |
| `REQUEST_ENCRYPT` | `BURP_TO_SERVER` | `burpToServer(ctx)` | 加密 |
| `RESPONSE_DECRYPT` | `SERVER_TO_BURP` | `serverToBurp(ctx)` | 解密 |
| `RESPONSE_ENCRYPT` | `BURP_TO_CLIENT` | `burpToClient(ctx)` | 加密 |

脚本方式的三个设计要点：

1. **不做明密文判定**：内置算法靠"试探性解密"保证幂等；脚本模式下"改不改、怎么改"完全由脚本决定，
   插件只负责在正确的阶段调用正确的函数（脚本返回 `null` 或输出与输入相同 → 视为不改动）。
2. **fail-open**：脚本抛异常 / 超时 / 返回空 / 文件缺失 → `ScriptOutcome.failed()` → `TransformResult.failed()`，
   **Body 保持原样**，Burp 转发不受影响，日志里留一条原因。
3. **`ctx.headers` 只读**：脚本能读 Header（比如从 `X-Iv` 取 IV），但返回值目前只接受 Body；
   要改 Header 属于另一个量级的需求（要重写报文重建逻辑），暂时不做。

`JsScriptRunner` 实现要点：

* 编译结果按 `(路径, mtime, size)` 缓存；文件一改自动重编译（改脚本不用重启 Burp）
* `Context.enter()` + `optimizationLevel=-1`（解释执行）—— JDK 21 上动态字节码生成容易踩坑，解释模式最稳
* 自定义 `WrapFactory`：把 Java 方法返回的 `String/Number/Boolean` 转成 JS 原生值，
  这样脚本里 `crypto.b64Encode(x) + "|"`、`.toUpperCase()` 都能直接用（否则拿到的是 `NativeJavaObject`）
* 钩子发现：编译后检查作用域里哪几个函数名存在，界面据此显示"已实现钩子（n/4）"
* 兜底：返回值若是 `NativeJavaObject` 先 `unwrap()` 再判断；超过 16 MB 视为失败

`CmdScriptRunner` 实现要点：

* `sh -c "<command>"`（Windows 用 `cmd /c`），允许带参数/管道
* Body 走 **stdin 原始字节**，stdout 原样当新 Body（字节保真，二进制也能用）
* 环境变量传 `BC_STAGE/BC_STAGE_CODE/BC_URL/BC_METHOD/BC_IS_REQUEST/BC_CHARSET/BC_PROFILE`
* stderr 与 stdout 并发读取（避免缓冲区写满死锁）；超时（默认 5s，`scriptTimeoutMs` 可配）强制 kill
* 退出码非 0 / 超时 / 输出为空 → 不改动并报错

### 1.4 算法层

#### CipherSpec —— 算法描述解析

`CipherSpec.of("AES/CBC/PKCS5Padding")` 得到：`family/mode/padding/blockSize/keyLengths/ivLength/aead`。

| family | blockSize | 合法密钥长度 | 备注 |
|---|---|---|---|
| AES | 16 | 16/24/32 | 支持 GCM |
| DES | 8 | 8 | |
| DESede | 8 | 24 | `3DES` / `TripleDES` 归一 |
| SM4 | 16 | 16 | 走后端内置实现，不走 JCE |
| RC4 | 0（流式） | 任意 | JCE 名 `ARCFOUR`，无 IV |
| ChaCha20 | 0（流式） | 32 | nonce 12 字节 |

归一规则：`PKCS7Padding → PKCS5Padding`（对 ≥8 字节分组等价）；**流式模式（CTR/CFB/OFB/GCM/RC4/ChaCha20）强制 NoPadding**；
`ZeroPadding` 由本层自己实现（JCE 没有）。

#### KeyMaterial —— Key/IV 的"自动识别"

痛点：`1234567890123456` 既是 16 位口令，也是"8 字节 HEX"。做法是**先枚举候选解码，再用算法允许的长度筛选**：

```
候选 = [HEX(若合法), BASE64(若合法), UTF-8]
按 allowed 长度依次匹配；都不匹配则返回 UTF-8（让上层报出可读错误）
```

显式指定格式时直接解码，长度不符则报"密钥长度 8 字节，AES 需要 16/24/32 字节"。

#### SymmetricEngine —— 单次加解密

* JCE 路径：`Cipher.getInstance(spec.jceTransformation())`，GCM 用 `GCMParameterSpec(128, iv)`
* SM4 路径：`Sm4.expandKey` + `BlockModes`（ECB/CBC/CFB/OFB/CTR）+ 自实现填充
* 填充：PKCS5/ISO10126/ANSIX923/Zero；`NoPadding` 时校验分组对齐
* 错误翻译：BadPadding → "填充错误（Key/IV/算法/编码不匹配，或数据本来就不是密文）"；GCM → "GCM 校验失败"

#### CryptoEngine —— 面向上层的门面

```
encrypt(plain) / decrypt(ct)
  ├─ FIXED      : 用配置的 IV
  ├─ PREPENDED  : 随机 IV 前置（IV‖CT）
  ├─ NONE       : ECB / 流式
  └─ AUTO       : 加密→有 IV 用固定、无 IV 前置；解密→先固定，解不出可读文本再 IV‖CT
```

`AUTO` 的判定依赖 `Codec.isPlainText`：严格 UTF-8 解码 + 不含控制字符（`\t\r\n` 除外）。

### 1.5 转换层

#### BodyTransformer —— 判定 + 转换

```java
// 加密方向（明文 → 密文）
encrypt(profile, body):
    if body 为空              → SKIPPED
    if JSON_FIELD 模式        → 取字段值；已是密文 → SKIPPED；否则加密并原地替换
    if looksEncrypted(body)   → SKIPPED("Body 已是密文")     // 幂等的关键
    → ENCRYPTED(encode(engine.encrypt(body)))

// 解密方向（密文 → 明文）
decrypt(profile, body):
    if body 为空              → SKIPPED
    ct = decode(body, encoding)               // Base64/HEX/RAW，失败即 SKIPPED
    try plain = engine.decrypt(ct) catch      → SKIPPED("填充错误 …")
    if plain 不是可读文本      → SKIPPED("…若前 16 字节是随机 IV，把 IV 模式改成自动…")
    → DECRYPTED(plain)
```

`looksEncrypted` 本质是"试探性解密"：解码成功 + 解密成功 + 结果是可读文本 ⇒ 它是密文。
对分组密码有填充校验兜底；对流式模式靠"错密钥解明文只会得到乱码"这一性质。

#### TargetResolver —— 谁用哪套方案

```
若 !masterEnabled 或 !toolEnabled(tool)          → 不处理
按顺序遍历 rules：enabled && 方向允许 && 方案存在且启用 && 方向允许 && matches(host,url)
命中即返回
否则用 fallbackProfileId
```

匹配实现：`HOST`（精确 / `.x.com` 后缀 / `*.x.com` 通配）、`URL_GLOB`（`*`→`.*`、`?`→`.`）、`URL_REGEX`（`find()`）。

#### CryptoService —— 四阶段 + 流水

`Phase{ REQUEST_DECRYPT, REQUEST_ENCRYPT, RESPONSE_DECRYPT, RESPONSE_ENCRYPT }`，每阶段决定方向与
`onRequest/onResponse` 的适用性；非 SKIPPED（或开了 debug）的结果进 `PlaintextLog`。

### 1.6 Burp 集成

#### 两个处理器，互不重叠

| 处理器 | 覆盖 | 为什么 |
|---|---|---|
| `CryptoHttpHandler`（`api.http().registerHttpHandler`） | 所有工具，**跳过 PROXY** | Repeater / Intruder / Scanner / 其它插件只有这一个钩子 |
| `CryptoProxyHandler`（`api.proxy().registerRequestHandler/ResponseHandler`） | 仅 Proxy，四阶段 | Proxy 需要"历史明文 vs 线上密文"分离，交给它独占 |

#### Proxy 四阶段与"回写记账"

```java
handleRequestReceived : decrypt → mark(request, url, 明文) → 替换
handleRequestToBeSent : 仅当 reencryptRequest 且 handoff.contains(request, url, body) → encrypt
handleResponseReceived: decrypt → mark(response, url, 明文) → 替换
handleResponseToBeSent: 仅当 reencryptResponse 且 handoff.contains(response, url, body) → encrypt
```

`HandoffCache` 的键是 `(方向, URL, 明文 SHA-256)`，TTL 5 分钟、上限 5000 条。作用：**只有我们解出来的明文才会被重新加密**，
同域下本来不加密的 HTML/接口不会被误加密；内容相同的多条报文也能各自命中。

#### 幂等的三层保障

1. `BodyTransformer` 判定：已是密文 → 不加密；已是明文 → 不解密
2. `CryptoProxyHandler` 的 handoff 记账：没解过就不加密
3. xia SQL 桥接层同样复用判定：`send()` 前先 `looksCipher`

因此"Proxy 收到 → 放行 → Repeater 重发 → Intruder 变异"这一路反复经过处理器，也不会出现二次加解密。

### 1.7 界面层

#### 完整报文渲染（MessagePrinter）

```
请求：METHOD PATH HTTP/1.1
      <所有 Header，跳过 Content-Length / Transfer-Encoding / HTTP2 伪头>
      Content-Length: <按解密后 Body 重算>
      <空行>
      <明文 Body，JSON 自动缩进>
响应：HTTP/1.1 <code> <reason> … 同上
```

编辑回写：`MessagePrinter.parseRequest(original, edited)` 先用 `HttpRequest.httpRequest(service, bytes)` **整包解析**
（这样 Header 改动也生效），失败则降级为 `original.withBody(bodyOf(edited))`，不会把报文搞坏。

**只有内容真的被改过才替换**：把编辑器内容与"展示时写入的字节"逐字节比较，避免"看一眼就标脏"。

#### JSON 美化（PlainTextFormatter）

不解析语义，只重排空白；**安全阀**：美化后去掉所有空白必须与原文逐字节一致，否则（引号/括号不配对的畸形输入）
直接返回原文。空对象/空数组不换行。

#### 状态文件（StatusFile）

每次启动 / 每次保存配置刷新 `~/.BurpCrypto/status.txt`：版本、时间、开关、Proxy 三个旗标、方案列表（含自检结果）、
规则列表。**不写 Key/IV 内容**，只写长度。同时镜像一份到 `/tmp/burpcrypto-status.txt` 方便 `tail`。

### 1.8 为什么"历史明文 vs 线上密文"只能二选一

Burp 的 Proxy 历史保存的就是**最终上线/回写的那份报文**（实测：解密后再加密，历史里是密文；不加密，历史里是明文，
见 [VERIFICATION.md](VERIFICATION.md) 第 1~2 节）。扩展可用的四个钩子里，没有任何一个能"只影响历史、不影响转发"。

因此产品上给了两个「重新加密」开关：

| 开关 | 打开（默认） | 关闭 |
|---|---|---|
| 请求放行前重新加密 | 服务端收密文，历史密文 | 历史明文，服务端收明文 |
| 响应回写前重新加密 | 客户端收密文，历史密文 | 历史明文，客户端收明文 |

默认取"两端密文"，明文通过页签 / 查看器 / 右键 Repeater 阅读，兼顾安全性与可用性。

---

## 2. xia SQL 桥接补丁

### 2.1 为什么基于 3.3 字节码重建

上游 `main` 与 tag `3.3` 的源码版本号仍是 `V2.9`，而发布的 `xia.SQL.3.3.jdk8.jar` 是 `V3.3`，
且字节码里多了 `当前url的body为二进制`、`当前url的响应包为gif图片`、`diy_error` 等源码没有的逻辑。
所以用 CFR 反编译 3.3 的 jar，修掉两处反编译产物（`static_file_2` 的泛型推断、裸 `ArrayList` 的 for-each），
再打补丁、重新编译。构建脚本与产物见 `tools/xia_sql_patch/`。

### 2.2 六个钩子

| # | 位置 | 改动 |
|---|---|---|
| ① | `checkVul()` 入口 | `decryptRequest()` 求出**完整明文请求**（原 Header + 明文 Body），并生成 `bc_info` |
| ② | 5 处 `analyzeRequest(baseRequestResponse)` | 改读 `bc_info`（参数/URL/方法/Header） |
| ③ | 2 处 `baseRequestResponse.getRequest()` | 改读 `bc_req`（明文整包） |
| ④ | 3 个 `callbacks.makeHttpRequest(...)` | 改走 `send()`（按模式加密后再发） |
| ⑤ | 2 处 `saveBuffersToTempFiles(...)` | 改走 `snapshot()`：Burp 原生快照 + `setRequest(明文)`，原始报文不动 |
| ⑥ | 侧边栏 UI | 新增「加密方案」「发包加密」下拉框 + 「刷新加密方案」 |

> ⑤ 的写法是有意为之：**不自己实现 `IHttpRequestResponse`**（Burp 2024 之后该接口新增了
> `getHost/getUrl/getStatusCode` 等方法，且 `saveBuffersToTempFiles` 对非原生实现可能有兼容问题），
> 而是让 Burp 先造快照、再 `setRequest` 换成明文。

### 2.3 桥接层（`xiabridge/CatBridge`）

自包含：只依赖 JDK + Burp 旧版 API，**不引用主插件的类**（跨扩展 classloader 不可见；且 Burp 会优先用
自身的 `burp.*`，把实现放进 `burp.*` 包会被遮蔽）。

| API | 用途 |
|---|---|
| `decryptRequest(rr, helpers, cb)` | 入口：返回**完整明文请求**或 null |
| `snapshot(cb, original, plainReq)` | Burp 原生快照 + 明文 |
| `send(cb, service, base, request)` | 按模式加密后 `makeHttpRequest` |
| `decryptBody(url, body)` / `encryptBody(url, body)` | 纯函数版（测试/二次开发用） |
| `encryptWithMode(url, body)` | 三模式加密 |
| `profilesForUi()` / `selectedProfileId()` / `selectProfileId(id)` | 方案下拉框 |
| `encryptMode()` / `selectEncryptMode(m)` | 发包加密下拉框 |

**配置来源**：`~/.BurpCrypto/config`（`-Dburpcrypto.config=/path` 可覆盖），按文件 mtime 缓存，
所以主插件里改 Key/IV 后**下一次扫描**即生效。用户选择存 `~/.BurpCrypto/xia_bridge.ini`。

**解析链**：`profile=` 是 `OFF` → 不处理；是具体方案 id → 用它（方案被删/停用则退回规则）；
是 `AUTO` → 按 `[rule]` 顺序匹配，未命中用 `[global] fallback`。

**错误处理**：任何异常都原样返回；`report()` 把前 5 条错误打到 Burp Errors
（`[CatBridge] …`），之后静默，避免刷屏。

### 2.4 数据流与"不会重复加解密"的保证

```
解密（入口，一次）→ 注入（明文）→ 加密（每包一次）→ 发送
响应：主插件 HttpHandler 解密 → xia SQL 比对（明文）
```

1. 入口先 `looksCipher`，出错的模板原样放过 → 明文不会被"再解密"
2. `send()` 在 AUTO 模式下先 `looksCipher` → 已是密文就不加密
3. 即使主插件随后又跑一遍 handler，也因同样的判定而跳过

---

## 3. 测试策略

| 层 | 手段 |
|---|---|
| 算法 | 国标向量（SM4）、`openssl enc` 逐字节对照（AES/SM4）、自实现与 JCE 交叉验证 |
| 配置 | INI 往返（转义/多行/空值）、`tools=ALL` 简写、原子写 + `config.bak` + 多级目录创建 |
| 规则 | Host 通配/URL 通配/URL 正则/兜底/工具开关，含"未勾其它插件时 EXTENSIONS 不处理"的联动 |
| 转换 | 幂等（同密文不二次加密）、错误密钥不破坏报文、JSON 字段模式、Zero/NoPadding 边界 |
| 脚本 | JS 四钩子（加解密/读 Header/阶段号）、未实现阶段跳过、抛异常不改动、外部命令 stdin/stdout、非 0 退出不改动、配置往返 |
| 报文渲染 | 完整报文结构、Content-Length 重算、JSON 美化幂等与畸形输入不破坏 |
| Burp 集成 | 真机 e2e：本地加密靶站 + Burp 代理 + MCP 读历史；扩展来源请求（`ToolType=EXTENSIONS`）实测 |
| 桥接层 | 动态代理模拟 `IExtensionHelpers/IHttpRequestResponse`，用真实密文跑"入口解密 → 注入 → 发包加密 → 服务端解回" |

---

## 4. 设计取舍速查

| 问题 | 选择 | 理由 |
|---|---|---|
| 为什么不用 BouncyCastle | 内置 SM4 + JCE | 避免与 Burp 内嵌 BC 版本冲突；加脚本引擎后 jar 1.6 MB |
| 为什么自带 Rhino 而不是 GraalJS | Rhino 1.7.15，解释执行 | JRE 21 无 Nashorn；GraalJS 体积/依赖太大；Rhino 1.3 MB 够用且稳 |
| 脚本为什么不自己判定明密文 | 交给脚本 | 脚本场景本就是"规则不规整"，插件再猜只会更乱；改不改由脚本 return 决定 |
| 为什么不用 JSON 库 | 自写字段扫描器 | 只做"取一个字段/原地替换"，还要保留原报文格式与顺序 |
| 为什么不把配置放进 Burp Preferences | 本地文件 | 可换目录、可备份、可进 git；重装扩展不丢（Burp 移除扩展会清 Preferences） |
| 为什么拒绝"历史明文且线上密文" | 物理上做不到 | 见 1.7 的实测依据 |
| 为什么桥接层重写一份加解密 | 类加载器隔离 | 跨扩展无法互相引用；读同一份配置文件即可保证一致 |
| 为什么用 `withBody` 而不是手拼报文 | 让 Burp 维护细节 | Content-Length/chunked/HTTP2 由 Burp 处理，少一类 bug |
