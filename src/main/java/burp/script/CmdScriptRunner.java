package burp.script;

import burp.support.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 外部命令模式的执行器：把 Body 从 stdin 喂给脚本，把 stdout 当新 Body。
 *
 * <p>为什么要有这个模式：Burp 跑在 JRE 上，能内置的脚本引擎有限；而大多数人想用
 * <b>Python / Node / 现成的 CLI</b> 写加解密。外部命令模式让你用任何语言、任何已有的
 * 工具，只要能读 stdin 写 stdout。</p>
 *
 * <pre>
 *   配置示例： python3 /Users/me/.BurpCrypto/scripts/gm.py
 *   环境变量： BC_STAGE / BC_STAGE_CODE / BC_URL / BC_METHOD / BC_IS_REQUEST / BC_CHARSET / BC_PROFILE
 *   stdin   ： 原始 Body 字节
 *   stdout  ： 新的 Body 字节（退出码非 0 或超时 → 不改动并报错）
 * </pre>
 */
public final class CmdScriptRunner {

    private static final int MAX_OUTPUT = 16 * 1024 * 1024;
    private static final int MAX_ERROR_SHOWN = 2000;

    private CmdScriptRunner() {
    }

    public static ScriptOutcome run(String command, int timeoutMs, ScriptCall call) {
        if (command == null || command.isBlank()) {
            return ScriptOutcome.failed("外部命令为空");
        }
        long start = System.currentTimeMillis();
        Process proc = null;
        try {
            List<String> cmd = new ArrayList<>();
            if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
                cmd.add("cmd");
                cmd.add("/c");
            } else {
                cmd.add("/bin/sh");
                cmd.add("-c");
            }
            cmd.add(command.trim());

            ProcessBuilder pb = new ProcessBuilder(cmd);
            Map<String, String> env = pb.environment();
            env.put("BC_STAGE", call.stage.name());
            env.put("BC_STAGE_CODE", String.valueOf(call.stage.code()));
            env.put("BC_STAGE_LABEL", encodeEnv(call.stage.label()));
            env.put("BC_URL", call.url);
            env.put("BC_METHOD", call.method);
            env.put("BC_IS_REQUEST", String.valueOf(call.isRequest));
            env.put("BC_CHARSET", call.charset.name());
            env.put("BC_PROFILE", encodeEnv(call.profileName));

            proc = pb.start();
            // 先读走 stderr，避免脚本写满缓冲区阻塞
            ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
            Thread errPump = pump(proc.getErrorStream(), errBuf, 64 * 1024, false);
            ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
            Thread outPump = pump(proc.getInputStream(), outBuf, MAX_OUTPUT, true);

            try (OutputStream stdin = proc.getOutputStream()) {
                stdin.write(call.body);
                stdin.flush();
            } catch (Exception ignore) {
                // 脚本可能不读 stdin，忽略
            }

            int timeout = Math.max(500, timeoutMs);
            boolean finished = proc.waitFor(timeout, TimeUnit.MILLISECONDS);
            if (!finished) {
                proc.destroyForcibly();
                return ScriptOutcome.failed("外部命令超时（" + timeout + "ms）：" + command.trim());
            }
            joinQuietly(errPump, 500);
            joinQuietly(outPump, 2000);

            int code = proc.exitValue();
            String err = new String(errBuf.toByteArray(), StandardCharsets.UTF_8).trim();
            if (code != 0) {
                return ScriptOutcome.failed("外部命令退出码 " + code
                        + (err.isEmpty() ? "" : "：" + truncate(err)));
            }
            byte[] out = outBuf.toByteArray();
            if (out.length == 0) {
                return ScriptOutcome.unchanged("外部命令没有输出，保持原样"
                        + (err.isEmpty() ? "" : "（stderr：" + truncate(err) + "）"));
            }
            if (java.util.Arrays.equals(out, call.body)) {
                return ScriptOutcome.unchanged("外部命令输出与原 Body 相同");
            }
            long cost = System.currentTimeMillis() - start;
            return ScriptOutcome.changed(out, call.stage.hook() + " 由外部命令处理（" + cost + "ms）");
        } catch (Exception e) {
            Log.error("外部命令执行失败：" + command, e);
            return ScriptOutcome.failed("外部命令执行失败：" + e);
        } finally {
            if (proc != null && proc.isAlive()) {
                proc.destroyForcibly();
            }
        }
    }

    private static Thread pump(InputStream in, ByteArrayOutputStream out, int limit, boolean keepGoing) {
        Thread t = new Thread(() -> {
            byte[] buf = new byte[8192];
            int n;
            try {
                while ((n = in.read(buf)) > 0) {
                    int can = limit - out.size();
                    if (can <= 0) {
                        if (!keepGoing) {
                            break;
                        }
                        continue;                 // 超限后丢弃多余输出，避免爆内存
                    }
                    out.write(buf, 0, Math.min(n, can));
                }
            } catch (Exception ignore) {
                // 进程被杀/流关闭，正常
            }
        }, "BurpCryptCat-cmd-pump");
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static void joinQuietly(Thread t, long ms) {
        try {
            t.join(ms);
        } catch (InterruptedException ignore) {
            Thread.currentThread().interrupt();
        }
    }

    private static String truncate(String s) {
        return s.length() <= MAX_ERROR_SHOWN ? s : s.substring(0, MAX_ERROR_SHOWN) + "…";
    }

    /** 环境变量里不能保证 UTF-8，非 ASCII 的标签转成 \\uXXXX，脚本可自行还原 */
    private static String encodeEnv(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c < 0x80) {
                sb.append(c);
            } else {
                sb.append(String.format("\\u%04x", (int) c));
            }
        }
        return sb.toString();
    }
}
