package burp.transform;

import burp.config.Profile;
import burp.crypto.Codec;
import burp.crypto.CryptoEngine;
import burp.crypto.CryptoException;

import java.nio.charset.Charset;

/**
 * Body 加解密核心：判断"这段 Body 到底是明文还是密文"，然后执行转换。
 *
 * <p>设计原则：<b>幂等 + 可失败即不动</b>。因为 Burp 的请求/响应会在多个阶段
 * 被反复处理（Proxy Received → ToBeSent、Repeater 发送 → 响应），同一个 Body
 * 可能被问很多次"要不要加密/解密"。</p>
 *
 * <p>判定方式统一为"试探性解密"：能解出可读文本 → 认为它是密文；否则认为它是明文。
 * 对分组密码（CBC/ECB）来说填充校验本身就极可靠；对流式模式（CTR/CFB/OFB/RC4）
 * 来说，用错误密钥"解"明文只会得到乱码，判据同样成立。</p>
 */
public final class BodyTransformer {

    private BodyTransformer() {
    }

    /* ==================== 对外 ==================== */

    /** 明文 → 密文。已是密文则原样跳过。 */
    public static TransformResult encrypt(Profile profile, byte[] body) {
        try {
            return doEncrypt(profile, body);
        } catch (CryptoException e) {
            return TransformResult.failed(e.getMessage());
        } catch (RuntimeException e) {
            return TransformResult.failed("异常：" + e);
        }
    }

    /** 密文 → 明文。不是密文则原样跳过。 */
    public static TransformResult decrypt(Profile profile, byte[] body) {
        try {
            return doDecrypt(profile, body);
        } catch (CryptoException e) {
            return TransformResult.failed(e.getMessage());
        } catch (RuntimeException e) {
            return TransformResult.failed("异常：" + e);
        }
    }

    /** 只做判定，不转换。 */
    public static boolean looksEncrypted(Profile profile, byte[] body) {
        try {
            if (body == null || body.length == 0) {
                return false;
            }
            CryptoEngine engine = profile.toEngine();
            if (profile.bodyScope == Profile.BodyScope.JSON_FIELD) {
                String text = new String(body, engine.charset());
                String value = JsonField.get(text, profile.jsonField);
                if (value == null || value.isEmpty()) {
                    return false;
                }
                return isCipherText(engine, profile, value);
            }
            return isCipherBytes(engine, profile, rawBytesToCipher(engine, profile, body));
        } catch (Exception e) {
            return false;
        }
    }

    /* ==================== 实现 ==================== */

    private static TransformResult doEncrypt(Profile profile, byte[] body) throws CryptoException {
        if (body == null || body.length == 0) {
            return TransformResult.skipped("Body 为空");
        }
        CryptoEngine engine = profile.toEngine();
        Charset cs = engine.charset();

        if (profile.bodyScope == Profile.BodyScope.JSON_FIELD) {
            String text = new String(body, cs);
            String value = JsonField.get(text, profile.jsonField);
            if (value == null) {
                return TransformResult.skipped("Body 中没有 JSON 字段 \"" + profile.jsonField + "\"");
            }
            if (isCipherText(engine, profile, value)) {
                return TransformResult.skipped("字段已是密文", value);
            }
            byte[] ct = engine.encrypt(value.getBytes(cs));
            String newText = JsonField.set(text, profile.jsonField,
                    BodyCodec.fromCipherBytes(ct, profile.bodyEncoding));
            if (newText == null) {
                return TransformResult.skipped("字段替换失败", value);
            }
            return TransformResult.encrypted(newText.getBytes(cs), value);
        }

        if (isCipherBytes(engine, profile, rawBytesToCipher(engine, profile, body))) {
            return TransformResult.skipped("Body 已是密文", Codec.preview(safeText(body, cs), 200));
        }
        byte[] ct = engine.encrypt(body);
        return TransformResult.encrypted(encodeBody(profile, ct, cs), Codec.preview(safeText(body, cs), 200));
    }

    private static TransformResult doDecrypt(Profile profile, byte[] body) throws CryptoException {
        if (body == null || body.length == 0) {
            return TransformResult.skipped("Body 为空");
        }
        CryptoEngine engine = profile.toEngine();
        Charset cs = engine.charset();

        if (profile.bodyScope == Profile.BodyScope.JSON_FIELD) {
            String text = new String(body, cs);
            String value = JsonField.get(text, profile.jsonField);
            if (value == null) {
                return TransformResult.skipped("Body 中没有 JSON 字段 \"" + profile.jsonField + "\"");
            }
            byte[] ct = BodyCodec.toCipherBytes(value, profile.bodyEncoding);
            if (ct == null) {
                return TransformResult.skipped("字段值不是合法的 " + profile.bodyEncoding.label());
            }
            byte[] plain = engine.decrypt(ct);
            String plainText = Codec.decodeStrict(plain, cs);
            if (plainText == null) {
                return TransformResult.skipped("解密结果不是 " + cs.name()
                        + " 文本（若密文前 16 字节是随机 IV，把 IV 模式改成「自动」或「随机 IV 前置」）");
            }
            String newText = JsonField.set(text, profile.jsonField, plainText);
            if (newText == null) {
                return TransformResult.skipped("字段替换失败");
            }
            return TransformResult.decrypted(newText.getBytes(cs), plainText);
        }

        byte[] ct = rawBytesToCipher(engine, profile, body);
        if (ct == null) {
            return TransformResult.skipped("Body 不是合法的 " + profile.bodyEncoding.label() + " 密文");
        }
        byte[] plain;
        try {
            plain = engine.decrypt(ct);
        } catch (CryptoException e) {
            return TransformResult.skipped(e.getMessage());
        }
        String plainText = Codec.decodeStrict(plain, cs);
        if (plainText == null || plainText.isBlank()) {
            return TransformResult.skipped("解密结果不是可读文本，已保持原样"
                    + "（若密文前 " + engine.blockSize()
                    + " 字节就是随机 IV，把 IV 模式改成「自动」或「随机 IV 前置」）");
        }
        if (profile.bodyEncoding == Profile.BodyEncoding.RAW) {
            // 原始二进制模式下直接替换为明文字节，不再做文本校验之外的约束
            return TransformResult.decrypted(plain, Codec.preview(plainText, 200));
        }
        return TransformResult.decrypted(plainText.getBytes(cs), Codec.preview(plainText, 200));
    }

    /** 判定一段"载体文本"是否是密文。 */
    private static boolean isCipherText(CryptoEngine engine, Profile profile, String text) {
        byte[] ct = BodyCodec.toCipherBytes(text, profile.bodyEncoding);
        return isCipherBytes(engine, profile, ct);
    }

    /** 判定一段"密文字节"是否真的能解出可读明文。 */
    private static boolean isCipherBytes(CryptoEngine engine, Profile profile, byte[] ct) {
        if (ct == null || ct.length == 0) {
            return false;
        }
        if (profile.bodyEncoding != Profile.BodyEncoding.RAW && ct.length < 8) {
            return false;
        }
        try {
            byte[] plain = engine.decrypt(ct);
            if (plain.length == 0) {
                return false;
            }
            if (Codec.isPlainText(plain)) {
                return true;
            }
            // RAW 模式：明文可能不是 UTF-8（例如 JSON 里有 GBK 字节），退一步看它是否"不像随机数据"
            return profile.bodyEncoding == Profile.BodyEncoding.RAW && looksStructured(plain);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean looksStructured(byte[] data) {
        for (byte b : data) {
            int v = b & 0xFF;
            if (v == 0) {
                return false;
            }
        }
        return true;
    }

    /** Body 字节 → 密文字节（按配置的编码解码）。RAW 模式直接当密文。 */
    private static byte[] rawBytesToCipher(CryptoEngine engine, Profile profile, byte[] body) {
        if (profile.bodyEncoding == Profile.BodyEncoding.RAW) {
            return body;
        }
        return BodyCodec.toCipherBytes(new String(body, engine.charset()), profile.bodyEncoding);
    }

    /** 密文字节 → 要写回 Body 的字节。 */
    private static byte[] encodeBody(Profile profile, byte[] cipher, Charset cs) {
        if (profile.bodyEncoding == Profile.BodyEncoding.RAW) {
            return cipher;
        }
        return BodyCodec.fromCipherBytes(cipher, profile.bodyEncoding).getBytes(cs);
    }

    private static String safeText(byte[] body, Charset cs) {
        String s = Codec.decodeLenient(body, cs);
        return s;
    }
}
