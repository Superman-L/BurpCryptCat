package burp.transform;

import burp.config.Profile;
import burp.crypto.Codec;
import burp.script.ScriptCall;
import burp.script.ScriptOutcome;
import burp.script.ScriptRuntime;
import burp.script.ScriptStage;

import java.nio.charset.Charset;
import java.util.List;

/**
 * 统一入口：按方案的「加解密方式」把一个阶段的 Body 交给内置算法或脚本处理。
 *
 * <p>四个阶段与脚本四接口一一对应：</p>
 * <pre>
 *   REQUEST_DECRYPT  (Proxy 收到请求)      → clientToBurp   / 内置·解密
 *   REQUEST_ENCRYPT  (Proxy 放行请求)      → burpToServer   / 内置·加密
 *   RESPONSE_DECRYPT (Proxy 收到响应)      → serverToBurp   / 内置·解密
 *   RESPONSE_ENCRYPT (Proxy 回写响应)      → burpToClient   / 内置·加密
 * </pre>
 */
public final class MessageTransform {

    private MessageTransform() {
    }

    public static TransformResult apply(Profile profile, ScriptStage stage, String url, String method,
                                        List<String> headers, byte[] body) {
        if (profile == null || stage == null) {
            return TransformResult.skipped("缺少方案");
        }
        if (profile.isScript()) {
            return script(profile, stage, url, method, headers, body);
        }
        return stage.builtinEncrypt()
                ? BodyTransformer.encrypt(profile, body)
                : BodyTransformer.decrypt(profile, body);
    }

    /* ==================== 脚本方式 ==================== */

    private static TransformResult script(Profile profile, ScriptStage stage, String url, String method,
                                          List<String> headers, byte[] body) {
        Charset cs = Codec.charset(profile.charset);
        ScriptCall call = new ScriptCall(stage, url, method, stage.isRequest(), headers, body, cs,
                profile.name);
        ScriptOutcome out = ScriptRuntime.run(profile, stage, call);

        if (out.failed) {
            return TransformResult.failed(out.detail);
        }
        if (!out.changed()) {
            return TransformResult.skipped(out.detail);
        }
        if (stage.builtinEncrypt()) {
            // 发往目标方向：脚本产出的是密文
            return TransformResult.encrypted(out.body, Codec.preview(new String(body, cs), 200));
        }
        return TransformResult.decrypted(out.body, Codec.preview(new String(out.body, cs), 200));
    }
}
