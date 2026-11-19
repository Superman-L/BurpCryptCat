#!/usr/bin/env python3
"""调用 Burp 内置 MCP Server（HTTP+SSE）的极简客户端，供端到端脚本使用。

默认可通过环境变量覆盖：
  BURP_MCP_URL   默认 http://127.0.0.1:9876
"""
import json
import os
import threading
import urllib.parse
import urllib.request

BASE = os.environ.get("BURP_MCP_URL", "http://127.0.0.1:9876")


class _Mcp:
    def __init__(self, base=BASE, timeout=30):
        self.base = base
        self.timeout = timeout
        self.messages = {}
        self.lock = threading.Condition()
        self._next_id = 0
        self._open()

    def _open(self):
        req = urllib.request.Request(self.base + "/", headers={"Accept": "text/event-stream"})
        self.resp = urllib.request.urlopen(req, timeout=self.timeout)
        endpoint = None
        while endpoint is None:
            line = self.resp.readline()
            if not line:
                raise RuntimeError("SSE 流在 endpoint 事件前关闭")
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if text.startswith("data:"):
                data = text[5:].strip()
                if "sessionId=" in data:
                    endpoint = data
        query = urllib.parse.parse_qs(urllib.parse.urlparse(endpoint).query)
        self.session_id = query["sessionId"][0]
        self.msg_url = self.base + "/" + endpoint.lstrip("/")
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        buf = []
        try:
            while True:
                raw = self.resp.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line == "":
                    if buf:
                        self._dispatch("\n".join(buf))
                        buf = []
                    continue
                if line.startswith("data:"):
                    buf.append(line[5:].lstrip())
        except Exception:
            pass

    def _dispatch(self, data):
        try:
            msg = json.loads(data)
        except Exception:
            return
        if isinstance(msg, dict) and "id" in msg:
            with self.lock:
                self.messages[msg["id"]] = msg
                self.lock.notify_all()

    def _post(self, payload, timeout=None):
        req = urllib.request.Request(self.msg_url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")

    def request(self, method, params=None, notify=False):
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        if notify:
            return self._post(payload)
        self._next_id += 1
        rid = self._next_id
        payload["id"] = rid
        self._post(payload)
        with self.lock:
            if not self.lock.wait_for(lambda: rid in self.messages, timeout=self.timeout):
                raise TimeoutError(f"{method} 超时")
            return self.messages.pop(rid)


def mcp_call(tool, arguments, timeout=30):
    """调用一个 MCP 工具，返回文本结果。"""
    m = _Mcp(timeout=timeout)
    m.request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                             "clientInfo": {"name": "burpcrypto-e2e", "version": "1.0"}})
    try:
        m.request("notifications/initialized", {}, notify=True)
    except Exception:
        pass
    res = m.request("tools/call", {"name": tool, "arguments": arguments})
    result = res.get("result", res)
    content = result.get("content") or []
    return "\n".join(c.get("text", "") for c in content if c.get("type") == "text")
