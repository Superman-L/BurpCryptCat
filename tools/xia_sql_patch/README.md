# xia SQL × BurpCryptCat 桥接补丁

给 [smxiazi/xia_sql](https://github.com/smxiazi/xia_sql)（3.3）打一个本地补丁，让它**自动**使用
[BurpCryptCat](../..) 的配置：

* 拿到请求时 → 先把加密 Body **解密成明文**（这样它的参数列表里能看到 `username`、`password`，Payload 才打得进去）
* 发包时 → 把明文（含 Payload）**加密**后再发
* 收包时 → 由 BurpCryptCat 本体自动解密，xia SQL 的对比逻辑看到的就是明文

> 比"把 BurpCrypto 切成历史明文模式"更好：**浏览器/客户端那条链路仍然是密文**，
> 只有 xia SQL 内部看到明文。

---

## 零、关于版本：为什么不是"2.9"

上游 GitHub 的 `main` 与 tag `3.3` 里的源码**其实停在 2.9**（作者发版时没提交 3.3 的源码）：

```
tag 3.3 的 BurpExtender.java → 版本：xia SQL V2.9     ← 源码
你本地 xia.SQL.3.3.jdk8.jar  → 版本：xia SQL V3.3     ← 实际发布的字节码
```

两者方法集一致（都是 22 个方法），但 3.3 的字节码里多了几处源码没有的逻辑
（"当前url的body为二进制"、"当前url的响应包为gif图片"、`diy_error` 等）。
所以本补丁**不是在 2.9 源码上改的**，而是：

1. 用 CFR 把 `xia.SQL.3.3.jdk8.jar` 反编译成源码（顺手修了两处反编译产物：泛型推断错乱的 `static_file_2`、裸 `ArrayList` 的 for-each）
2. 在 3.3 的代码上打同一套钩子
3. 重新编译打包（`--release 17`，Burp 2024.x 自带 JRE 21 可直接跑）

产物里的版本号是 `xia SQL V3.3 +BurpCrypto`，Extension 名也是这个，方便一眼区分。

## 一、界面上多了两个选项栏

「xia SQL」页签左侧多三项：

```
加密方案(BurpCrypto):  [ 跟随规则（按 URL 自动匹配）      ▾ ]   ← 默认
发包加密:              [ 自动（默认：明文才加密）          ▾ ]   ← 新增
                       [ 刷新加密方案 ]
```

**「发包加密」三种状态**（记在 `~/.BurpCrypto/xia_bridge.ini` 的 `encrypt=`）：

| 选项 | 行为 | 什么时候用 |
|---|---|---|
| **自动（默认）** | 明文 → 加密；已经是密文 → 不动 | 绝大多数情况 |
| **总是加密** | 不做密文判定，直接按方案加密 | payload 本身长得像 base64、被"试探性解密"误判成密文时 |
| **不加密** | 只解密模板便于查看/注入，发包保持明文 | 临时对着明文接口测、或想让服务端收明文 |

* 下拉框列出 `~/.BurpCrypto/config` 里的**所有方案**（名称 + 算法），外加两个特殊项：
  * **跟随规则（按 URL 自动匹配）**：和 BurpCryptCat 本体一样按规则挑方案（默认）
  * **不处理（保持明文，不加密）**：临时关掉加解密
* 选中的方案记在 `~/.BurpCrypto/xia_bridge.ini`（`profile=<id>`），重启 Burp 还在
* **Key/IV/算法永远实时读 BurpCryptCat 的配置文件**（按 mtime 缓存），所以在 BurpCrypto 里
  改完 Key 点「保存并应用」，这边下一次扫描立刻生效，不用重载插件、不用重新选方案
* 方案被删除/停用时自动退回"跟随规则"，不会突然什么都不做

## 二、改了哪几处（共 7 类）

| # | 位置 | 改动 |
|---|---|---|
| ① | `checkVul(...)` 入口 | 求得**完整明文请求** `bc_plain_req`（请求行 + 头 + 明文 Body），并据此生成 `bc_info`（参数/URL/Header） |
| ② | 参数解析（5 处 `analyzeRequest(baseRequestResponse)`） | 改用 `bc_info`，于是参数来自**明文** |
| ③ | 原始请求字节（2 处） | 改用 `bc_req`（明文） |
| ④ | 3 个 `callbacks.makeHttpRequest(...)` | 改成 `CatBridge.send(...)`，发出前加密 |
| ⑤ | 2 处 `saveBuffersToTempFiles(...)` | 走 `CatBridge.snapshot(...)`：快照仍是 Burp 原生对象，只是内容换成明文，**原始报文不动** |
| ⑥ | UI 侧边栏 | 新增「加密方案」「发包加密」两个下拉框 + 「刷新加密方案」按钮 |
| ⑦ | 版本标识 | `xia SQL V3.3 +BurpCrypto`（Extension 名同步） |

完整 diff 见 `xia_sql-3.3-cryptcat.diff`（235 行），打好的源码是 `BurpExtender.3.3.java.patched`。

关键一行（入口）：

```java
byte[] bc_plain_req = xiabridge.CatBridge.decryptRequest(baseRequestResponse, helpers, callbacks);
final IRequestInfo bc_info = bc_plain_req != null
        ? helpers.analyzeRequest(baseRequestResponse.getHttpService(), bc_plain_req)
        : helpers.analyzeRequest(baseRequestResponse);
final byte[] bc_req = bc_plain_req != null ? bc_plain_req : baseRequestResponse.getRequest();
```

`decryptRequest` 返回的是**整条请求**（`helpers.buildHttpMessage(原 headers, 明文 body)`），
不是裸 Body —— 这一点务必注意：`analyzeRequest` / `updateParameter` 都要整条请求。

---

## 二、桥接层做了什么（`xiabridge/CatBridge.java`）

自包含（只依赖 JDK + Burp 旧版 API，**不依赖 BurpCrypto 的类**，避免跨扩展 classloader 问题），
直接读 BurpCryptCat 的配置文件，所以两边永远一致：

```
~/.BurpCrypto/config                默认位置
-Dburpcrypto.config=/path/to/config  可用 JVM 参数覆盖
```

支持的组合与 BurpCryptCat 本体对齐：

| 维度 | 支持 |
|---|---|
| 算法 | AES / DES / 3DES / RC4 / ChaCha20（**SM4 不支持**，见"边界"） |
| 模式 | ECB / CBC / CFB / OFB / CTR / GCM |
| 填充 | PKCS5(7) / NoPadding / ZeroPadding |
| 密文编码 | Base64 / HEX / 原始二进制 |
| IV 模式 | 固定 IV / 随机 IV 前置（IV‖CT） / 自动（两者都试） / 无 IV |
| Body 范围 | 整个 Body / JSON 字段（只加解密该字段） |
| 规则 | Host（含 `*.x.com`）/ URL 通配 / URL 正则，按配置文件顺序第一条命中 |

判定与 BurpCrypto 一致：**试探性解密**，能解出可读文本才算密文；任何异常都原样返回，
不会把 xia SQL 自己的流程搞坏。配置按文件 mtime 缓存，**改完配置不用重启 Burp**。

---

## 三、安装（基于 3.3）

1. Burp → Extensions → Installed → 把旧的 **xia SQL**（`xia.SQL.3.3.jdk8.jar`）移除，两个都装会重复扫描
2. Add → Extension type `Java` → 选 `xia_sql_3.3_cryptcat.jar`
3. 列表里应显示 **xia SQL V3.3 +BurpCrypto**
4. **BurpCryptCat 本体也要保持加载**（收包解密是它做的）
5. Extender → Output 里会看到一行：
   `[CatBridge] 已接入 BurpCrypto 配置：…，当前命中方案「xxx」(AES/CBC/PKCS5Padding)`

然后像平常一样：Proxy/Repeater 里右键 **Send to xia SQL**（或直接扫），参数列表里应该出现
明文参数，扫描正常进行。左侧「加密方案」默认是"跟随规则"，想固定用某套方案就选它。

---

## 四、边界

* **脚本/外部命令方案**：桥接层只支持内置算法。命中脚本方案时会原样放过并在 Errors 里提示一次 ——
  这类方案请用 BurpCryptCat 的「明文」页签操作，或给 xia SQL 单独配一套内置算法方案。
* **SM4 目标**：桥接层没实现 SM4（避免再抄一份国密实现），遇到 SM4 方案会原样放过 ——
  这类目标请用 BurpCrypto 的「BurpCryptCat 明文」页签 / 解密后发到 Repeater 手动测。
* **JSON 字段模式**：支持，但字段值必须是字符串。
* **RAW（原始二进制）编码 + JSON 字段**：没有意义，会失败并原样放过。
* **响应解密依赖 BurpCryptCat 本体**：只装补丁、不装本体 → 请求能加密，但响应是密文，
  xia SQL 的差异对比会失准。
* 补丁针对 **xia SQL 3.3**；上游源码更新后需要重新套（见下）。

---

## 五、重新构建

当前主用 `BurpExtender.3.3.java.patched`（3.3 反编译 + 补丁），直接：

```bash
./build.sh                  # 用 BurpExtender.3.3.java.patched 编译打包
```

如果作者日后补交了 3.3 源码，可以：

```bash
curl -sS -o BurpExtender.java https://raw.githubusercontent.com/smxiazi/xia_sql/main/BurpExtender.java
patch -p0 < xia_sql-3.3-cryptcat.diff      # 对反编译版生成的 diff，仅供参考
./build.sh BurpExtender.java
```

`xia_sql-3.3-cryptcat.diff` 是"反编译源码 → 打补丁源码"的完整差异（235 行），
想核对改了哪些地方可以看它。

`build.sh` 会优先用 `JAVA_HOME`，否则在 `~/Library/Java/JavaVirtualMachines` 里找 17+；
Burp 的 jar 默认取 `/Applications/Burp Suite Professional.app/...`，可用 `BURP_JAR=...` 覆盖。

---

## 六、已做的验证

### 端到端（用动态代理模拟 Burp 对象，跑真实密文）

```
① 入口解密
  POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:9099\r\nContent-Type: application/json
  \r\nContent-Length: 40\r\n\r\n{"username":"admin","password":"123456"}
  Body = {"username":"admin","password":"123456"}
  是完整请求: true
  头未丢: true

② 注入 Payload（xia SQL 干的事）→ 发包前加密
  注入后明文: {"username":"admin'","password":"123456"}
  加密后    : KUUsnJuL1ZCvvIdI87Q6NGz1Ge4E5HlDZAMjGCzURtku/xj4l4Z4XgBK4MJoGTO+

③ 服务端视角：把发出去的密文解回来
  {"username":"admin'","password":"123456"}
  含 Payload: true
```

### 桥接层单独验证

桥接层单独跑过（真实配置 + 靶站抓到的真实密文）：

```
靶站收到过的请求体共 3 条：
  64   字符 → {"username":"admin","password":"123456"}
  108  字符 → KUUsnJuL1ZCvvIdI87Q6NDHGkMiE+gVJMThGtR/5fRY...='
  108  字符 → KUUsnJuL1ZCvvIdI87Q6NDHGkMiE+gVJMThGtR/5fRY...=''
```

这正是补丁要解决的两种情形：第一行是"模板密文 → 明文"（补丁后 xia SQL 看到的就是它）；
第二、三行是"未打补丁时 xia SQL 在 base64 上拼引号"的产物。加密/解密往返、
"已是密文不再二次加密"的幂等性也都验证过。

---

## 七、版权

`BurpExtender.java` 来自上游 [smxiazi/xia_sql](https://github.com/smxiazi/xia_sql)（仓库未附 LICENSE 文件），
本目录只包含**本地修改补丁**与桥接层源码，供个人测试使用，请不要对外分发打过补丁的产物。
