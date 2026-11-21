package burp.script;

import burp.support.Log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Python 脚本执行器：**常驻子进程 + JSON 行协议**。
 *
 * <pre>
 *   插件 ──一行 JSON──► python3 _burpcryptcat_driver.py 你的脚本.py
 *        ◄──一行 JSON──
 * </pre>
 *
 * <p>为什么不用 Jython：Jython 只到 Python 2.7，且没法用 pycryptodome / cryptography 这些
 * 实际在用的库。为什么不做成"每个报文起一个进程"：python 启动一次约 60ms，爆破时扛不住。
 * 所以这里维持一条常驻进程，按 (脚本, mtime, 解释器) 缓存；脚本改了自动重启。</p>
 */
public final class PythonRunner {

    private static final int MAX_SESSIONS = 4;
    private static final long IDLE_MILLIS = 10 * 60 * 1000L;
    private static final int HANDSHAKE_TIMEOUT_MS = 20000;
    private static final int MAX_REPLY_BYTES = 32 * 1024 * 1024;

    /** key = 脚本绝对路径|mtime|size|解释器 */
    private static final Map<String, Session> SESSIONS = new LinkedHashMap<>();

    /** 最近一次启动失败的原因（给界面/日志用） */
    private static volatile String lastStartError;

    private PythonRunner() {
    }

    /* ==================== 对外 ==================== */

    public static ScriptOutcome run(File script, String interpreter, int timeoutMs, ScriptCall call) {
        if (script == null || !script.isFile()) {
            return ScriptOutcome.failed("脚本文件不存在：" + (script == null ? "" : script.getPath()));
        }
        if (interpreter == null || interpreter.isBlank()) {
            return ScriptOutcome.failed("找不到可用的 Python（可在方案里手动指定解释器路径）");
        }
        String key = key(script, interpreter);
        Session session;
        try {
            synchronized (PythonRunner.class) {
                sweep();
                session = SESSIONS.get(key);
                if (session == null || !session.alive()) {
                    if (session != null) {
                        session.close();
                    }
                    session = start(script, interpreter);
                    if (session == null) {
                        return ScriptOutcome.failed("启动 Python 失败（解释器：" + interpreter + "）"
                                + (lastStartError == null ? "" : "：" + shorten(lastStartError)));
                    }
                    SESSIONS.put(key, session);
                    evictIfNeeded();
                }
            }
        } catch (Exception e) {
            return ScriptOutcome.failed("启动 Python 失败：" + e);
        }
        return call(session, key, timeoutMs, call);
    }

    /** 扩展卸载时关掉所有常驻进程。 */
    public static synchronized void shutdown() {
        for (Session s : SESSIONS.values()) {
            s.close();
        }
        SESSIONS.clear();
    }

    /* ==================== 会话 ==================== */

    private static ScriptOutcome call(Session s, String key, int timeoutMs, ScriptCall call) {
        int timeout = Math.max(1000, timeoutMs);
        synchronized (s.lock) {
            if (!s.alive()) {
                s.close();
                synchronized (PythonRunner.class) {
                    SESSIONS.remove(key);
                }
                return ScriptOutcome.failed("Python 进程已退出，下次调用会重启");
            }
            if (!s.hooks.contains(snake(call.stage.hook()))) {
                return ScriptOutcome.unchanged("脚本没有实现 " + snake(call.stage.hook()) + "()，跳过");
            }
            try {
                s.write(request(call));
            } catch (Exception e) {
                s.close();
                synchronized (PythonRunner.class) {
                    SESSIONS.remove(key);
                }
                return ScriptOutcome.failed("写入 Python 进程失败：" + e);
            }
            String line;
            try {
                line = s.queue.poll(timeout, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                line = null;
            }
            if (line == null) {
                s.close();
                synchronized (PythonRunner.class) {
                    SESSIONS.remove(key);
                }
                return ScriptOutcome.failed("Python 脚本超时（" + timeout + "ms），已重启进程");
            }
            if (s.lastError != null && !s.lastError.isBlank()) {
                Log.debug("[python] stderr: " + s.lastError);
                s.lastError = null;
            }
            return parse(line, call);
        }
    }

    private static ScriptOutcome parse(String json, ScriptCall call) {
        if (!Json.bool(json, "ok", false)) {
            String err = Json.str(json, "error");
            return ScriptOutcome.failed("Python 脚本报错：" + (err == null ? "未知错误" : shorten(err)));
        }
        String bodyB64 = Json.str(json, "body");
        if (bodyB64 == null) {
            String skipped = Json.str(json, "skipped");
            return ScriptOutcome.unchanged(skipped == null ? "脚本未改动 Body" : skipped);
        }
        byte[] out;
        try {
            out = Base64.getDecoder().decode(bodyB64);
        } catch (Exception e) {
            return ScriptOutcome.failed("Python 返回值不是合法 Base64");
        }
        if (out.length > MAX_REPLY_BYTES) {
            return ScriptOutcome.failed("Python 返回内容过大（>32MB），已忽略");
        }
        if (out.length == 0) {
            return ScriptOutcome.unchanged("脚本返回空 Body，保持原样");
        }
        if (java.util.Arrays.equals(out, call.body)) {
            return ScriptOutcome.unchanged("脚本输出与原 Body 相同");
        }
        return ScriptOutcome.changed(out, snake(call.stage.hook()) + "() 已处理");
    }

    private static String request(ScriptCall call) {
        StringBuilder sb = new StringBuilder(256 + call.body.length * 2);
        sb.append('{');
        sb.append("\"hook\":").append(Json.quote(snake(call.stage.hook()))).append(',');
        sb.append("\"stage\":").append(Json.quote(call.stage.name())).append(',');
        sb.append("\"stageCode\":").append(call.stage.code()).append(',');
        sb.append("\"stageLabel\":").append(Json.quote(call.stage.label())).append(',');
        sb.append("\"url\":").append(Json.quote(call.url)).append(',');
        sb.append("\"method\":").append(Json.quote(call.method)).append(',');
        sb.append("\"isRequest\":").append(call.isRequest).append(',');
        sb.append("\"charset\":").append(Json.quote(call.charset.name())).append(',');
        sb.append("\"profile\":").append(Json.quote(call.profileName)).append(',');
        sb.append("\"headers\":").append(Json.array(call.headers)).append(',');
        sb.append("\"body\":").append(Json.quote(Base64.getEncoder().encodeToString(call.body)));
        return sb.append('}').toString();
    }

    /* ==================== 进程 ==================== */

    private static Session start(File script, String interpreter) throws IOException {
        File driver = PythonSupport.ensureDriver();
        List<String> cmd = new ArrayList<>();
        boolean win = System.getProperty("os.name", "").toLowerCase().contains("win");
        if (win) {
            cmd.add("cmd");
            cmd.add("/c");
            cmd.add(interpreter + " \"" + driver.getAbsolutePath() + "\" \"" + script.getAbsolutePath() + "\"");
        } else {
            cmd.add("/bin/sh");
            cmd.add("-c");
            cmd.add(interpreter + " '" + driver.getAbsolutePath().replace("'", "'\\''")
                    + "' '" + script.getAbsolutePath().replace("'", "'\\''") + "'");
        }
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(false);
        pb.environment().put("PYTHONIOENCODING", "utf-8");
        pb.environment().put("PYTHONUNBUFFERED", "1");
        Process proc = pb.start();

        Session s = new Session(proc);
        s.startPumps();
        // 等握手：驱动会回一行 {"ok":true,"ready":true,"hooks":[...]}
        String hello;
        try {
            hello = s.queue.poll(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            hello = null;
        }
        if (hello == null || !Json.bool(hello, "ok", false)) {
            String err = hello == null ? null : Json.str(hello, "error");
            lastStartError = err;
            s.close();
            Log.error("启动 Python 脚本失败：" + script.getName()
                    + (err == null ? "" : "（" + shorten(err) + "）"), null);
            return null;
        }
        s.hooks = Json.strArray(hello, "hooks");
        Log.info("Python 脚本已就绪：" + script.getName() + " 钩子 " + s.hooks);
        return s;
    }

    private static final class Session {
        final Process proc;
        final BufferedWriter stdin;
        final BlockingQueue<String> queue = new LinkedBlockingQueue<>();
        final Object lock = new Object();
        volatile List<String> hooks = new ArrayList<>();
        volatile String lastError;
        volatile long lastUsed = System.currentTimeMillis();

        Session(Process proc) {
            this.proc = proc;
            this.stdin = new BufferedWriter(new OutputStreamWriter(proc.getOutputStream(), StandardCharsets.UTF_8));
        }

        void startPumps() {
            Thread out = new Thread(() -> {
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        queue.offer(line);
                    }
                } catch (Exception ignore) {
                    // 进程结束
                }
            }, "BurpCryptCat-py-out");
            out.setDaemon(true);
            out.start();

            Thread err = new Thread(() -> {
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(proc.getErrorStream(), StandardCharsets.UTF_8))) {
                    String line;
                    StringBuilder buf = new StringBuilder();
                    while ((line = r.readLine()) != null) {
                        buf.append(line).append('\n');
                        if (buf.length() > 4000) {
                            buf.setLength(4000);
                        }
                    }
                    lastError = buf.toString();
                } catch (Exception ignore) {
                    // 进程结束
                }
            }, "BurpCryptCat-py-err");
            err.setDaemon(true);
            err.start();
        }

        void write(String line) throws IOException {
            stdin.write(line);
            stdin.write('\n');
            stdin.flush();
            lastUsed = System.currentTimeMillis();
        }

        boolean alive() {
            return proc.isAlive();
        }

        void close() {
            try {
                stdin.close();
            } catch (Exception ignore) {
                // 忽略
            }
            try {
                proc.destroy();
                if (!proc.waitFor(500, TimeUnit.MILLISECONDS)) {
                    proc.destroyForcibly();
                }
            } catch (Exception ignore) {
                // 忽略
            }
        }
    }

    /* ==================== 杂项 ==================== */

    private static String key(File script, String interpreter) {
        return script.getAbsolutePath() + "|" + script.lastModified() + "|" + script.length() + "|" + interpreter;
    }

    /** 关掉闲置太久的进程，避免攒一堆 python */
    private static void sweep() {
        long now = System.currentTimeMillis();
        List<String> dead = new ArrayList<>();
        for (Map.Entry<String, Session> e : SESSIONS.entrySet()) {
            Session s = e.getValue();
            if (!s.alive() || now - s.lastUsed > IDLE_MILLIS) {
                s.close();
                dead.add(e.getKey());
            }
        }
        for (String k : dead) {
            SESSIONS.remove(k);
        }
    }

    private static void evictIfNeeded() {
        while (SESSIONS.size() > MAX_SESSIONS) {
            String oldest = null;
            long ts = Long.MAX_VALUE;
            for (Map.Entry<String, Session> e : SESSIONS.entrySet()) {
                if (e.getValue().lastUsed < ts) {
                    ts = e.getValue().lastUsed;
                    oldest = e.getKey();
                }
            }
            if (oldest == null) {
                return;
            }
            Session s = SESSIONS.remove(oldest);
            if (s != null) {
                s.close();
            }
        }
    }

    private static String snake(String camel) {
        return PythonSupport.camelToSnake(camel);
    }

    private static String shorten(String s) {
        if (s == null) {
            return "";
        }
        String one = s.replace("\r", "").trim();
        int nl = one.indexOf('\n');
        String head = nl > 0 ? one.substring(0, nl) : one;
        String last = one.substring(one.lastIndexOf('\n') + 1).trim();
        String text = head.equals(last) ? head : head + " … " + last;
        return text.length() > 300 ? text.substring(0, 300) + "…" : text;
    }
}
