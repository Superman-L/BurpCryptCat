package burp.script;

import burp.config.Profile;
import burp.support.Log;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.List;

/**
 * 脚本方式的总入口：按方案的 {@link Profile.Engine} 分发到 JS 或外部命令，并处理路径/模板。
 *
 * <p>脚本目录：{@code ~/.BurpCrypto/scripts/}（相对路径的脚本名都在这儿找）。</p>
 */
public final class ScriptRuntime {

    private ScriptRuntime() {
    }

    /** 默认脚本目录 ~/.BurpCrypto/scripts */
    public static File scriptsDir() {
        return new File(new File(System.getProperty("user.home", "."), ".BurpCrypto"), "scripts");
    }

    /** 解析方案的脚本路径：绝对路径直接用，否则在脚本目录下找。 */
    public static File resolve(Profile p) {
        if (p == null || p.scriptPath == null || p.scriptPath.isBlank()) {
            return null;
        }
        File f = new File(p.scriptPath.trim());
        if (!f.isAbsolute()) {
            f = new File(scriptsDir(), p.scriptPath.trim());
        }
        return f;
    }

    /** 该方案实现了哪些钩子（界面显示用）。 */
    public static List<String> hooks(Profile p) {
        if (p == null) {
            return Collections.emptyList();
        }
        if (p.engine == Profile.Engine.SCRIPT_JS) {
            File f = resolve(p);
            return f == null ? Collections.emptyList() : JsScriptRunner.hooksOf(f);
        }
        if (p.engine == Profile.Engine.SCRIPT_PY) {
            File f = resolve(p);
            return PythonSupport.hooksOf(f);
        }
        if (p.engine == Profile.Engine.SCRIPT_CMD) {
            return Collections.nCopies(4, "cmd");
        }
        return Collections.emptyList();
    }

    /** 执行一次脚本。任何失败都返回"不改动"。 */
    public static ScriptOutcome run(Profile p, ScriptStage stage, ScriptCall call) {
        if (p == null || stage == null || call == null) {
            return ScriptOutcome.unchanged("缺少参数");
        }
        try {
            switch (p.engine) {
                case SCRIPT_JS -> {
                    File f = resolve(p);
                    if (f == null || !f.isFile()) {
                        return ScriptOutcome.failed("脚本文件不存在：" + p.scriptPath);
                    }
                    return JsScriptRunner.run(f, call);
                }
                case SCRIPT_PY -> {
                    File f = resolve(p);
                    if (f == null || !f.isFile()) {
                        return ScriptOutcome.failed("脚本文件不存在：" + p.scriptPath);
                    }
                    String py = PythonSupport.resolveInterpreter(ScriptSettings.pythonCommand());
                    if (py == null) {
                        return ScriptOutcome.failed("找不到可用的 Python，请在方案里指定解释器路径");
                    }
                    return PythonRunner.run(f, py, p.scriptTimeoutMs, call);
                }
                case SCRIPT_CMD -> {
                    return CmdScriptRunner.run(p.scriptPath, p.scriptTimeoutMs, call);
                }
                default -> {
                    return ScriptOutcome.unchanged("当前方案不是脚本模式");
                }
            }
        } catch (Throwable e) {
            Log.error("脚本执行异常", e);
            return ScriptOutcome.failed("脚本执行异常：" + e);
        }
    }

    /* ==================== 模板 ==================== */

    /** 生成一份带四个接口的 JS 模板（界面里"生成模板"按钮用）。 */
    public static File writeTemplate(String fileNameHint) throws IOException {
        return writeTemplate(fileNameHint, Profile.Engine.SCRIPT_JS);
    }

    /** 按引擎生成模板：JS 或 Python。 */
    public static File writeTemplate(String fileNameHint, Profile.Engine engine) throws IOException {
        File dir = scriptsDir();
        if (!dir.isDirectory()) {
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
        }
        boolean py = engine == Profile.Engine.SCRIPT_PY;
        String name = (fileNameHint == null || fileNameHint.isBlank() ? "my-crypto" : fileNameHint)
                .replaceAll("[\\\\/:*?\"<>|\\s]+", "-") + (py ? ".py" : ".js");
        File f = new File(dir, name);
        if (!f.isFile()) {
            Files.writeString(f.toPath(), py ? PythonSupport.template() : template(), StandardCharsets.UTF_8);
            try {
                Files.setPosixFilePermissions(f.toPath(),
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            } catch (Exception ignore) {
                // Windows 忽略
            }
        }
        return f;
    }

    /** 四个接口的模板源码。 */
    public static String template() {
        return """
                // ============================================================================
                // BurpCryptCat 脚本模板 —— 四个接口对应 Burp 的四个处理阶段
                //
                //   ① clientToBurp(ctx)  客户端 → Burp     Proxy 收到请求时（一般：解密）
                //   ② burpToServer(ctx)  Burp → 服务端     请求放行前   （一般：加密）
                //   ③ serverToBurp(ctx)  服务端 → Burp     收到响应时   （一般：解密）
                //   ④ burpToClient(ctx)  Burp → 客户端     响应回写前   （一般：加密）
                //
                // ctx 上有：
                //   ctx.stage / stageCode / stageLabel / hook    当前阶段
                //   ctx.url / method / isRequest                 请求信息
                //   ctx.headers                                  全部 Header（"Name: value" 数组）
                //   ctx.header("x-iv")                           取某个 Header（大小写不敏感）
                //   ctx.body                                     当前 Body 文本（按方案字符集解码）
                //   ctx.charset / profile                        字符集 / 方案名
                //   ctx.log("...")                               打到 Extender → Output
                //
                // 返回值：
                //   "新的 Body 字符串"    → 用新 Body
                //   null / 不 return      → 不改动
                //   { body: "..." }       → 也可以
                //
                // 现成的工具（crypto.*，全部内置，不用引第三方库）：
                //   编码：b64Encode / b64Decode / b64EncodeRaw / b64DecodeRaw
                //         b64UrlEncode / b64UrlDecode / hexEncode / hexUpper / hexDecode
                //         urlEncode / urlDecode
                //   摘要：md5 / sha1 / sha256 / sha512；hmacMd5 / hmacSha1 / hmacSha256
                //   对称：
                //     aesCbcEncrypt(key, iv, plain)        → Base64 密文
                //     aesCbcDecrypt(key, iv, cipherB64)    → 明文
                //     aesCbcEncryptPrependIv / aesCbcDecryptPrependIv   // 密文前 16 字节是 IV
                //     aesEcbEncrypt / aesEcbDecrypt
                //     sm4CbcEncrypt / sm4CbcDecrypt / sm4CbcDecryptPrependIv
                //     desCbcEncrypt / desCbcDecrypt / des3CbcEncrypt / des3CbcDecrypt
                //   杂项：randomHex(n) / randomBytes(n) / uuid() / now()
                //
                // 只实现你需要的接口即可，没实现的阶段会被跳过。
                // ============================================================================

                var KEY = "ysIEuRgXG/SMp4HqZL1BEw==";   // 例：Base64 的 AES Key
                var IV  = "63cef27c4a68b8f4";          // 例：16 字节 IV（也可以是 Base64）

                // ① 客户端 → Burp：把密文解成明文，Burp 里才看得懂
                function clientToBurp(ctx) {
                    // 密文前 16 字节就是随机 IV 的写法，一行搞定：
                    var plain = crypto.aesCbcDecryptPrependIv(KEY, ctx.body);
                    if (plain === null) {
                        // 固定 IV 的写法：crypto.aesCbcDecrypt(KEY, IV, ctx.body)
                        plain = crypto.aesCbcDecrypt(KEY, IV, ctx.body);
                    }
                    ctx.log("clientToBurp: " + (plain === null ? "解不开，保持原样" : "已解密"));
                    return plain;      // null 表示不改动
                }

                // ② Burp → 服务端：把明文（可能是你改过的）加密回去
                function burpToServer(ctx) {
                    return crypto.aesCbcEncrypt(KEY, IV, ctx.body);
                }

                // ③ 服务端 → Burp：响应解密
                function serverToBurp(ctx) {
                    var plain = crypto.aesCbcDecryptPrependIv(KEY, ctx.body);
                    return plain === null ? crypto.aesCbcDecrypt(KEY, IV, ctx.body) : plain;
                }

                // ④ Burp → 客户端：响应加密
                function burpToClient(ctx) {
                    return crypto.aesCbcEncrypt(KEY, IV, ctx.body);
                }

                // —— 不处理的阶段，直接删掉对应函数即可 ——
                """;
    }
}
