package burp.script;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * 暴露给脚本的工具对象（JS 里叫 {@code crypto}，外部命令模式自己用语言自带的库）。
 *
 * <p>目的是让脚本"几行就能干活"：Base64/HEX、AES-CBC 一把梭、摘要。</p>
 *
 * <pre>
 *   // 典型脚本（每包随机 IV 前置的场景）
 *   function clientToBurp(ctx) {
 *       var b = crypto.b64Decode(ctx.body);
 *       var iv = b.substring(0, 16);
 *       return crypto.aesCbcDecryptWithIv(crypto.b64Encode(iv), crypto.b64Encode(b.substring(16)));
 *   }
 * </pre>
 */
public final class ScriptUtils {

    /* ==================== 编码 ==================== */

    public String b64Encode(String text) {
        return Base64.getEncoder().encodeToString(
                (text == null ? "" : text).getBytes(StandardCharsets.UTF_8));
    }

    public String b64Decode(String text) {
        try {
            return new String(Base64.getDecoder().decode(cleanBase64(text)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /** Base64 解成"原始字节的字符串形式"（ISO-8859-1，一个字符一个字节） */
    public String b64DecodeRaw(String text) {
        try {
            return new String(Base64.getDecoder().decode(cleanBase64(text)), StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            return null;
        }
    }

    public String b64EncodeRaw(String raw) {
        return Base64.getEncoder().encodeToString(
                (raw == null ? "" : raw).getBytes(StandardCharsets.ISO_8859_1));
    }

    public String hexEncode(String text) {
        byte[] d = (text == null ? "" : text).getBytes(StandardCharsets.ISO_8859_1);
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte b : d) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public String hexDecode(String hex) {
        try {
            String t = (hex == null ? "" : hex).replaceAll("[\\s:-]", "");
            if (t.length() % 2 != 0) {
                return null;
            }
            byte[] out = new byte[t.length() / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(t.substring(i * 2, i * 2 + 2), 16);
            }
            return new String(out, StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            return null;
        }
    }

    /* ==================== 摘要 ==================== */

    public String md5(String text) {
        return digest("MD5", text);
    }

    public String sha256(String text) {
        return digest("SHA-256", text);
    }

    private String digest(String algo, String text) {
        try {
            MessageDigest md = MessageDigest.getInstance(algo);
            byte[] d = md.digest((text == null ? "" : text).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    /* ==================== AES-CBC（最常用的一把梭） ==================== */

    /**
     * AES-CBC/PKCS5 加密。
     *
     * @param keyText Base64 或 UTF-8 文本都可以（16/24/32 字节）
     * @param ivText  Base64 或 UTF-8 文本（16 字节）
     * @param plain   明文
     * @return Base64 密文；失败返回 null
     */
    public String aesCbcEncrypt(String keyText, String ivText, String plain) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes(keyText), "AES"),
                    new IvParameterSpec(ivBytes(ivText)));
            byte[] ct = c.doFinal((plain == null ? "" : plain).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            return null;
        }
    }

    /** AES-CBC/PKCS5 解密：入参/出参都是 Base64 文本 */
    public String aesCbcDecrypt(String keyText, String ivText, String cipherB64) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes(keyText), "AES"),
                    new IvParameterSpec(ivBytes(ivText)));
            byte[] pt = c.doFinal(Base64.getDecoder().decode(cleanBase64(cipherB64)));
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /** 同上，但 IV 是密文前 16 字节（IV‖CT 结构） */
    public String aesCbcDecryptPrependIv(String keyText, String cipherB64) {
        try {
            byte[] all = Base64.getDecoder().decode(cleanBase64(cipherB64));
            if (all.length <= 16) {
                return null;
            }
            byte[] iv = java.util.Arrays.copyOf(all, 16);
            byte[] ct = java.util.Arrays.copyOfRange(all, 16, all.length);
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes(keyText), "AES"),
                    new IvParameterSpec(iv));
            return new String(c.doFinal(ct), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /* ==================== 杂项 ==================== */

    public long now() {
        return System.currentTimeMillis();
    }

    public String toUpperCase(String s) {
        return s == null ? null : s.toUpperCase();
    }

    public String toLowerCase(String s) {
        return s == null ? null : s.toLowerCase();
    }

    /* ==================== 内部 ==================== */

    /** Base64 文本 → 密钥字节：优先 Base64，失败则按 UTF-8 */
    static byte[] keyBytes(String text) {
        if (text == null) {
            return new byte[0];
        }
        try {
            byte[] b = Base64.getDecoder().decode(cleanBase64(text));
            if (b.length == 16 || b.length == 24 || b.length == 32) {
                return b;
            }
        } catch (Exception ignore) {
            // 落到 UTF-8
        }
        return text.getBytes(StandardCharsets.UTF_8);
    }

    /** IV 文本 → 16 字节：优先 Base64，失败则按 UTF-8 */
    static byte[] ivBytes(String text) {
        if (text == null) {
            return new byte[16];
        }
        try {
            byte[] b = Base64.getDecoder().decode(cleanBase64(text));
            if (b.length == 16) {
                return b;
            }
        } catch (Exception ignore) {
            // 落到 UTF-8
        }
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static String cleanBase64(String s) {
        return (s == null ? "" : s).replaceAll("\\s", "");
    }
}
