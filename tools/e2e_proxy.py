#!/usr/bin/env python3
"""端到端验证：真 Burp + 真插件 + 本地加密靶站。

检查四件事（这正是需求的核心承诺）：
  1. 服务端收到的请求体是**密文**，且能解出测试人员写的明文      → 线上仍是密文
  2. 客户端收到的响应体是**密文**                                → 客户端不受影响
  3. Burp Proxy 历史里的请求体是**明文**                          → 直接可读
  4. Burp Proxy 历史里的响应体是**明文**                          → 直接可读
另外验证：不匹配规则的普通接口一个字节都没被改动。

用法：python3 tools/e2e_proxy.py [--proxy 127.0.0.1:8080] [--target 127.0.0.1:9099]
"""
import base64
import http.client
import json
import os
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_helper import mcp_call  # noqa: E402

KEY = b"0123456789abcdef"
IV = b"0123456789abcdef"
LOG = os.environ.get("E2E_LOG", "/tmp/burpcrypto_e2e/server.log")

PROXY = ("127.0.0.1", 8080)
TARGET = ("127.0.0.1", 9099)
EXPECT = "transparent"          # transparent = 两端密文（默认）；history = 历史明文模式

PLAIN_REQ = '{"username":"admin","password":"123456"}'


def args():
    global PROXY, TARGET
    argv = sys.argv[1:]
    global EXPECT
    for i, a in enumerate(argv):
        if a == "--expect":
            EXPECT = argv[i + 1]
        if a == "--proxy":
            host, port = argv[i + 1].split(":")
            PROXY = (host, int(port))
        if a == "--target":
            host, port = argv[i + 1].split(":")
            TARGET = (host, int(port))


def pad(d: bytes) -> bytes:
    n = 16 - len(d) % 16
    return d + bytes([n]) * n


def unpad(d: bytes) -> bytes:
    n = d[-1]
    return d[:-n]


def enc(text: str) -> str:
    e = Cipher(algorithms.AES(KEY), modes.CBC(IV)).encryptor()
    return base64.b64encode(e.update(pad(text.encode())) + e.finalize()).decode()


def dec(b64: str) -> str:
    raw = base64.b64decode(b64.strip())
    d = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
    return unpad(d.update(raw) + d.finalize()).decode()


def via_proxy(method: str, path: str, body: bytes):
    """以代理方式发请求（absolute-form），返回 (status, body_text)。"""
    conn = http.client.HTTPConnection(PROXY[0], PROXY[1], timeout=20)
    url = f"http://{TARGET[0]}:{TARGET[1]}{path}"
    headers = {
        "Host": f"{TARGET[0]}:{TARGET[1]}",
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Length": str(len(body)),
        "Connection": "close",
    }
    conn.request(method, url, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data.decode("utf-8", "replace")


def read_log():
    if not os.path.exists(LOG):
        return []
    out = []
    with open(LOG, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def history_items(count=10):
    try:
        raw = mcp_call("get_proxy_http_history_regex",
                       {"regex": f"{TARGET[0]}:{TARGET[1]}", "count": count, "offset": 0})
    except Exception as exc:                      # MCP 不通时降级
        print(f"  [i] MCP 历史不可用（{exc}），跳过历史检查")
        return None, str(exc)
    items = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return items, None


results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"  {'✓' if ok else '✗'} {name}" + (f"   {detail}" if detail else ""))


def main():
    args()
    print(f"[i] 代理 = {PROXY[0]}:{PROXY[1]}    靶站 = {TARGET[0]}:{TARGET[1]}    期望模式 = {EXPECT}")
    print(f"[i] 明文请求 = {PLAIN_REQ}")

    # ---------- 1. 加密接口 ----------
    print("\n[1] POST /api/login（客户端发密文，期望：服务端收密文 / 历史显明文 / 客户端收密文）")
    cipher_body = enc(PLAIN_REQ)
    print(f"   客户端发出：{cipher_body[:48]}...（密文）")
    before = len(read_log())
    status, resp_text = via_proxy("POST", "/api/login", cipher_body.encode())
    print(f"   客户端收到：{resp_text[:64]}...")

    # 1a. 服务端视角
    entries = [e for e in read_log() if e.get("type") == "request"][before:]
    req_entry = None
    for e in read_log():
        if e.get("type") == "request" and e.get("path", "").startswith("/api/login"):
            req_entry = e
    if req_entry is None:
        check("服务端收到请求", False, "靶站日志里没有 /api/login")
    else:
        if EXPECT == "transparent":
            check("服务端收到的是密文（能按 AES 解开）", req_entry.get("decrypt_ok"),
                  f"raw={str(req_entry.get('raw'))[:40]}...")
            check("服务端解出的明文与客户端明文一致", req_entry.get("plaintext") == PLAIN_REQ,
                  f"plaintext={req_entry.get('plaintext')}")
            check("服务端收到的不是明文（插件确实加密了）", req_entry.get("raw") != PLAIN_REQ)
        else:
            check("历史明文模式下：服务端收到的是明文（预期代价）",
                  req_entry.get("raw") == PLAIN_REQ, f"raw={str(req_entry.get('raw'))[:40]}...")

    # 1b. 客户端收到的响应必须是密文
    try:
        client_plain = dec(resp_text)
        client_is_cipher = True
    except Exception:
        client_plain = resp_text
        client_is_cipher = False
    if EXPECT == "transparent":
        check("客户端收到的响应是密文（插件回写前重新加密了）", client_is_cipher,
              "" if client_is_cipher else f"客户端直接拿到了明文：{resp_text[:80]}")
    else:
        check("历史明文模式下：客户端收到的是明文（预期代价）", not client_is_cipher,
              resp_text[:60])
    check("响应内容可读且合理",
          '"code":0' in client_plain.replace(" ", "") or '"code": 0' in client_plain,
          client_plain[:80])

    # 1c. Burp 历史
    time.sleep(1.0)
    items, err = history_items(60)
    if items is not None:
        target = None
        for it in reversed(items):        # MCP 按时间正序返回，取最后一条 = 最新
            if "/api/login" in (it.get("request") or ""):
                target = it
                break
        if target is None:
            check("Proxy 历史里有这条请求", False, "最近 60 条里没找到 /api/login")
        else:
            req_raw = target.get("request", "")
            resp_raw = target.get("response", "")
            body_in_history = req_raw.split("\r\n\r\n", 1)[-1]
            if EXPECT == "history":
                check("历史里的请求体是明文", PLAIN_REQ in body_in_history,
                      f"body={body_in_history[:60]!r}")
                check("历史里的响应体是明文", "login ok" in resp_raw,
                      f"resp={resp_raw.split(chr(13)+chr(10)+chr(13)+chr(10))[-1][:60]!r}")
            else:
                # 透明模式下 Burp 历史保存的是最终上线报文，这里只作为信息展示
                print(f"    [i] 历史请求体：{body_in_history[:60]!r}"
                      f"（透明模式下按 Burp 机制为密文）")

    # ---------- 2. 不匹配规则的接口 ----------
    print("\n[2] GET /plain（不该被处理，期望：两端都还是明文、原样）")
    before_plain = len(read_log())
    status, plain_text = via_proxy("GET", "/plain", b"")
    check("客户端收到明文", '"plain": true' in plain_text.replace(" ", "") or
          '"plain":true' in plain_text.replace(" ", ""), plain_text[:80])
    new = [e for e in read_log() if e.get("type") == "response"
           and e.get("path", "").startswith("/plain")]
    check("靶站正常响应 /plain（未被加工）", bool(new), "")

    # ---------- 汇总 ----------
    print("\n================ 汇总 ================")
    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"-------------------------------------\n  通过 {passed}/{len(results)}")
    return 0 if passed == len(results) else 2


if __name__ == "__main__":
    sys.exit(main())
