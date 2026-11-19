#!/usr/bin/env python3
"""本地"加密靶站"，用来验证 BurpCrypto 的透明加解密是否真的成立。

行为：
  POST /api/login   请求体 = Base64(AES-128-CBC/PKCS5(JSON))，响应体同样是密文
  GET  /plain       普通明文接口，用来验证"不该动的流量一点没动"

启动：python3 tools/test_server.py [端口]
每次收发都会追加一行 JSON 到 /tmp/burpcrypto_e2e/server.log
"""
import base64
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 与扩展内置示例配置一致：AES/CBC/PKCS5Padding + 16 位文本 Key/IV
KEY = b"0123456789abcdef"
IV = b"0123456789abcdef"
LOG_PATH = os.environ.get("E2E_LOG", "/tmp/burpcrypto_e2e/server.log")


def _pad(data: bytes) -> bytes:
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def _unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return data[:-n]


def encrypt(text: str) -> str:
    enc = Cipher(algorithms.AES(KEY), modes.CBC(IV)).encryptor()
    return base64.b64encode(enc.update(_pad(text.encode())) + enc.finalize()).decode()


def decrypt(b64: str) -> str:
    raw = base64.b64decode(b64.strip(), validate=False)
    dec = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
    return _unpad(dec.update(raw) + dec.finalize()).decode()


def log(obj) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    obj["ts"] = time.time()
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _reply(self, body: bytes, ctype="text/plain; charset=utf-8", status=200):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        log({"type": "response", "path": self.path, "status": status,
             "body": body.decode("utf-8", "replace")})

    def do_GET(self):
        if self.path.startswith("/plain"):
            self._reply(json.dumps({"hello": "world", "plain": True}).encode())
            return
        self._reply(b"not found", status=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        text = raw.decode("utf-8", "replace")
        entry = {"type": "request", "path": self.path, "raw": text, "length": length}
        plaintext = None
        try:
            plaintext = decrypt(text)
            entry["decrypt_ok"] = True
            entry["plaintext"] = plaintext
        except Exception as exc:              # 收到的不是密文 → 说明插件没在加密
            entry["decrypt_ok"] = False
            entry["error"] = f"{type(exc).__name__}: {exc}"
            entry["plaintext"] = text
        log(entry)

        if self.path.startswith("/api/login"):
            if entry["decrypt_ok"]:
                try:
                    data = json.loads(plaintext)
                except Exception:
                    data = {}
                reply = {"code": 0, "msg": "login ok",
                         "user": data.get("username"), "pwd": data.get("password")}
            else:
                reply = {"code": 400, "msg": "服务端只收密文，收到的不是密文"}
            self._reply(encrypt(json.dumps(reply, ensure_ascii=False)).encode())
            return
        self._reply(encrypt(json.dumps({"code": 0, "path": self.path})).encode())


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9099
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    open(LOG_PATH, "w").close()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[+] 加密靶站已启动 http://127.0.0.1:{port}   日志={LOG_PATH}", flush=True)
    print(f"[i] KEY={KEY.decode()}  IV={IV.decode()}  算法=AES/CBC/PKCS5Padding 编码=Base64", flush=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
