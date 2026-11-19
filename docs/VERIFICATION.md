# 实机验证记录（Burp 2024.3 + 本插件）

环境：Burp Suite Professional 2024.3.1.4（Montoya API 2023.12.1-5）、macOS、JDK 17/21。
靶站：`tools/test_server.py`（AES-128-CBC/PKCS5Padding，Key=IV=`0123456789abcdef`，Body 为 Base64 密文）。
验证脚本：`tools/e2e_proxy.py`（走 Burp 代理由 `127.0.0.1:8080` 打到靶站 `127.0.0.1:9099`，再用 Burp 内置 MCP 读 Proxy 历史）。

---

## 1. 透明模式（默认：两端保持密文）

配置：总开关开、规则 `URL 通配 *` 启用、`请求放行前重新加密=true`、`响应回写前重新加密=true`。

```
[i] 代理 = 127.0.0.1:8080    靶站 = 127.0.0.1:9099    期望模式 = transparent
[1] POST /api/login
   客户端发出：9WwXZi1YYQYquOSySOg0L0PvoC25jpfGhgq9RoaTaUTuIEks...（密文）
   客户端收到：CMFB8eE46PyvyI/1/tgH2ZxQjr7fvO8Qyw+Z3r5PG+pPYqrpSgeC+Ext1juFNKSf...（密文）
  ✓ 服务端收到的是密文（能按 AES 解开）
  ✓ 服务端解出的明文与客户端明文一致      {"username":"admin","password":"123456"}
  ✓ 服务端收到的不是明文（插件确实加密了）
  ✓ 客户端收到的响应是密文（插件回写前重新加密了）
  ✓ 响应内容可读且合理                  {"code": 0, "msg": "login ok", "user": "admin", ...}
[2] GET /plain（不该被处理）
  ✓ 客户端收到明文  {"hello": "world", "plain": true}
  ✓ 靶站正常响应 /plain（未被加工）
通过 7/7
```

结论：客户端与目标站之间的字节流完全没变（还是密文），插件只是在 Burp 内部把 Body 换成了明文。

---

## 2. 历史明文模式（把两个"重新加密"开关关掉）

配置：同上，但 `请求放行前重新加密=false`、`响应回写前重新加密=false`。

```
[1] POST /api/login
  ✓ 历史明文模式下：服务端收到的是明文（预期代价）   raw={"username":"admin","password":"123456"}
  ✓ 历史明文模式下：客户端收到的是明文（预期代价）
  ✓ 历史里的请求体是明文                            {"username":"admin","password":"123456"}
```

Burp 界面人工确认（Proxy → HTTP history）：

* 请求体：明文 `{"username":"admin","password":"123456"}`
* 响应体：明文 `{"code": 400, ...}` / `{"code": 0, "msg": "login ok", ...}`
* 报文备注列：插件自动打上 `BurpCryptCat 已解密` / `BurpCryptCat 已加密`

结论：**"历史显示明文"和"两端保持密文"确实是互斥的**（Burp 的 Proxy 历史保存的就是最终上线/回写的那份报文）。
本插件两种模式都实现，默认选安全的那种；切换只需要动两个勾选框。

---

## 3. Repeater（明文编辑 → 自动加密发出 → 响应自动解密）

用 MCP 新建 Repeater 页签，Body 写成**明文** `{"username":"admin","password":"123456"}`（Content-Length=40），手动点 Send。

靶站收到的请求：

```
  raw      : 9WwXZi1YYQYquOSySOg0L0PvoC25jpfGhgq9RoaTaUTuIEkswkn/q+yS/EfthL2d
  是密文吗 : True
  解出明文 : {"username":"admin","password":"123456"}
```

Repeater 里看到的响应：明文 `{"code": 0, "msg": "login ok", ...}`。

结论：Repeater 里可以完全对着明文操作，发出去的是密文；响应自动解密展示。
Intruder 走的是同一套 `HttpHandler`（每个变异包发出前单独加密、响应自动解密）。

---

## 4. 完整报文页签（保留请求头 + 美化）

「BurpCryptCat 明文」页签展示示例（人工确认）：

```http
POST /api/login HTTP/1.1
Host: 127.0.0.1:9099
Content-Type: text/plain; charset=utf-8
Connection: keep-alive
Content-Length: 40

{
  "username": "admin",
  "password": "123456"
}
```

* 请求行 / URL / Header 原样保留
* `Content-Length` 按解密后的 Body 重算，报文自洽
* JSON 自动缩进（「全局设置 → 美化 JSON」可关）
* 在这个页签里改 Body（甚至改 Header）都能生效，发送前自动加密

---

## 5. 单元测试

```
./build.sh --tests
...
通过 114 项，失败 0 项
```

覆盖：

* SM4 单分组国标向量（GB/T 32907）、SM4-CBC 与 `openssl enc -sm4-cbc` 一致
* AES-128-CBC 与 `openssl enc -aes-128-cbc` 一致
* Key/IV 的 AUTO 解析歧义（`1234567890123456` 是 16 位口令还是 8 字节 HEX）
* NoPadding 对齐、ZeroPadding、PKCS7→PKCS5 归一、GCM/CTR 的 IV 长度
* 配置 INI 往返（含多行/`=` 转义、代理开关、日志条数）
* 规则匹配（Host 通配 / URL 通配 / URL 正则 / 兜底 / 工具开关）
* Body 转换幂等（同一密文不会被二次加密）、错误密钥不破坏报文、JSON 字段模式
* 完整报文渲染 / Body 提取 / JSON 美化（含畸形输入不破坏）

---

## 6. 排错用状态文件

每次启动、每次保存配置都会刷新 `/tmp/burpcrypto-status.txt`（不含 Key/IV 内容）：

```
BurpCryptCat 1.0.3
时间      : 2026-11-18 23:43:56
事件      : 配置已保存：切换规则启用状态
状态      : 运行中，规则 1 条，配置方案 1 个
总开关    : true
生效工具  : [Proxy, Repeater, Intruder]
Proxy     : 参与=true  请求回写加密=true  响应回写加密=true
明文美化  : true
兜底方案  : （未设置）
...
```


---

## 7. 真实样本：小程序 IV‖CT（AES-128-CBC）

用户提供的广东移动小程序报文（Base64 Body，Key `ysIEuRgXG/SMp4HqZL1BEw=`）：

* CT1 解码后 176 字节 = 16 字节 IV + 160 字节密文
* CT2 解码后 848 字节 = 16 字节 IV + 832 字节密文

| 假设 | 结果 |
|---|---|
| 固定 IV = ASCII `63cef27c4a68b8f4` | 首个 16 字节乱码，其后 JSON 完整（CBC：IV 只影响第一分组） |
| IV = hex(`63cef27c4a68b8f4`) 补零 / 重复两次 / md5(key) | 首个分组乱码，其后完整 |
| **前 16 字节当 IV** | **完全正确**：`{"result":{...},"success":true,"__abp":true}` |

CT2 用同样方式解出：`{"result":{"prodchinfolist":{...}},"success":true,...}`

插件侧（1.1.0）：

* `IvMode.FIXED` → 判定为"解不出可读文本"，**保持原样不改报文**（不会把乱码写进流量）
* `IvMode.AUTO`（新默认）→ 自动回退到 IV‖CT，解出干净 JSON
* 单测里用 CT1 的真实字节做了回归（`ivAutoModeRealWorld`），断言固定 IV 首块乱码、
  自动模式无残留乱码

另注：用户给的 Key 只有 23 个字符（`…Ew=`），Base64 少一个 `=`；插件的 Key 解析会自动补齐，
但仍建议按真实 Key 写全。


---

## 8. 其它插件（xia SQL / Scanner）是否也走插件

问题：Burp 扩展自己发的请求（`ToolType.EXTENSIONS`）会不会触发本插件的 `HttpHandler`？

实测（v1.2.0，顶层开关「对所有工具生效」打开）：用 Burp 内置 MCP 扩展的 `send_http1_request`
发一条**明文 Body** 的请求，来源工具即 `Extensions`（与 xia SQL 同类）。

调用方发出去：

```http
POST /api/login HTTP/1.1
Content-Length: 40

{"username":"admin","password":"123456"}
```

实际到达靶站：

```
9WwXZi1YYQYquOSySOg0L0PvoC25jpfGhgq9RoaTaUTuIEkswkn/q+yS/EfthL2d
→ 密文，靶站用 AES 解出 {"username":"admin","password":"123456"}
```

调用方拿到的响应（MCP 返回的 `httpResponse`）：

```http
HTTP/1.1 200 OK
Content-Length: 64

{"code": 0, "msg": "login ok", "user": "admin", "pwd": "123456"}
```

结论：

* 扩展来源的请求 **会** 进入本插件的 `HttpHandler`：发出前加密、响应解密后再交还调用方
* Scanner 走的是同一条代码路径（`ToolType.SCANNER → ToolGroup.OTHER`），行为一致
* 但"喂给插件的请求模板"必须是明文：模板若是密文，插件只是把 Payload 塞进 base64 里，
  服务端解密后不会执行。解决办法见 README「让其它插件（xia SQL 等）也吃到加解密」


---

## 9. 配置落盘到本地文件（1.3.0）

需求：配置方案保存到本地目录，mac 为 `~/.BurpCrypto/config`，Windows 类似。

实测（1.3.0，真实 Burp）：

```
$ ls -la ~/.BurpCrypto/
drwx------  config          # 配置本体（INI）
-rw-------  config.bak      # 上一次保存的备份
-rw-r--r--  status.txt      # 当前生效状态（不含 Key）

$ head -12 ~/.BurpCrypto/config
# 本文件由 BurpCryptCat 自动维护，可直接编辑（扩展保存时会被覆盖）
# 位置：/Users/roo66t/.BurpCrypto/config
# 时间：2026-11-19 12:39:17
# BurpCryptCat 配置文件 v1
[global]
master=true
fallback=
tools=PROXY,REPEATER,INTRUDER
...
```

* 目录权限 `700`、配置文件 `600`（POSIX 生效，Windows 忽略）
* 写入是「临时文件 → 原子替换」，替换前把旧文件留成 `config.bak`
* 在界面点「保存设置」后，磁盘文件 mtime 立刻更新，开关同步落盘
  （打开顶层开关后文件里变成 `tools=PROXY,REPEATER,INTRUDER,OTHER`）
* 换目录：`全局设置 → 选择目录…`，目标目录已有 `config` 时会问「载入它 / 用当前配置覆盖」
* 手工改完文件：`全局设置 → 重新载入` 即可生效（不用重装扩展）

附带效果：以前每次 Remove/Add 扩展，Burp 会把该扩展的 Preferences 清掉，配置回到默认
（本项目前面测试时反复踩到）；改成文件后，**重装扩展、重启 Burp、换项目都不会丢配置**。

回归检查：顶层开关打开后，用扩展来源（`ToolType=EXTENSIONS`）的请求再打一次靶站 ——
请求体在线上是密文（`Content-Length: 64` 的 base64），调用方拿到的响应是解密后的
`{"code": 0, "msg": "login ok", ...}`，与 1.2.0 行为一致。


---

## 10. 与 xia SQL 联动的实测（它到底走不走本插件）

xia SQL 3.3（`xia.SQL.3.3.jdk8.jar`）反编译可见用的是**旧版 API** `callbacks.makeHttpRequest`（3 处调用），
不是 Montoya 的 `sendHttpRequest`。这决定了它会不会进入本插件的 `HttpHandler`。

实验：把一段**明文**请求 `username=admin&password=123456` 喂给 xia SQL 扫描 `127.0.0.1:9099`，
靶站日志（key 用的是插件里"广东移动小程序"方案的 `inMf+bg08z7T0wJudZSYjA==`）实际收到的三包解密结果：

```
密文长度 48  padding OK  明文: {"username":"admin","password":"123456"}     ← 模板包
密文长度 80  padding OK  明文: KUUsnJuL1ZCvvIdI87Q6NDHGkMiE+gVJMThGtR/5fRY...='
密文长度 80  padding OK  明文: KUUsnJuL1ZCvvIdI87Q6NDHGkMiE+gVJMThGtR/5fRY...=''
```

结论：

1. **xia SQL 的请求确实会进本插件并被加密**（旧版 `makeHttpRequest` 与 Montoya `sendHttpRequest`
   走同一条 handler 管线，来源被标记为 `ToolType.EXTENSIONS`）。
2. 但它发出的明文是「一段 base64 密文 + 一个单引号」—— 说明 **xia SQL 拿到的模板本身是密文**，
   它把 `'` 拼在 base64 后面，注入根本没落到明文参数上。这是工作流问题，不是插件没生效。
3. 正确姿势（照这个来就能真的扫）：
   * 规则指向正确的那套方案（本例是"广东移动小程序"，别用示例方案）；
   * 让 xia SQL 拿到**明文模板**：「全局设置」取消「请求放行前重新加密」，
     或右键「BurpCrypto：复制明文请求（完整报文）」再粘进 xia SQL；
   * 之后 xia SQL 每个变异包发出前由插件加密、响应自动解密后再交给它分析。

同一实验也说明了一个容易误判的点：**靶站解不开 ≠ 插件没加密**。这次靶站解不开是因为
两边 Key 不同（插件用广东移动的方案，靶站是示例 Key），换成匹配的 Key 就通了。
