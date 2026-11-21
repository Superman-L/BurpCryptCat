package burp.script;

import burp.crypto.Sm4;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 暴露给脚本的工具对象（JS 里叫 {@code crypto}）：把"写脚本最常用的那一堆"都内置好，
 * 不用自己拼 Base64、不用引第三方库。Python 侧有同名模块（{@code crypto}），
 * 方法一一对应（Python 用 snake_case）。
 *
 * <pre>
 *   编码：b64Encode/b64Decode、b64UrlEncode/b64UrlDecode、b64EncodeRaw/b64DecodeRaw、
 *         hexEncode/hexDecode/hexUpper、urlEncode/urlDecode
 *   摘要：md5 / sha1 / sha256 / sha512，hmacMd5 / hmacSha1 / hmacSha256
 *   对称：aesCbcEncrypt/Decrypt（+ PrependIv）、aesEcbEncrypt/Decrypt、
 *         sm4CbcEncrypt/Decrypt（+ PrependIv）、desCbcEncrypt/Decrypt、des3CbcEncrypt/Decrypt
 *   杂项：randomHex / randomBytes / uuid / now / toUpperCase / toLowerCase
 * </pre>
 *
 * <p>Key/IV 支持两种写法：Base64 文本（长度对得上时按 Base64 解）或直接 UTF-8 文本。
 * 所有方法失败返回 {@code null}（脚本里判空即可），不会抛异常打断报文处理。</p>
 */
public final class ScriptUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    /* ==================== 编码 ==================== */

    public String b64Encode(String text) {
        return b64((text == null ? "" : text).getBytes(StandardCharsets.UTF_8));
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
        return b64((raw == null ? "" : raw).getBytes(StandardCharsets.ISO_8859_1));
    }

    /** URL-safe Base64（+ / 换成 - _，去掉 = 填充） */
    public String b64UrlEncode(String text) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString((text == null ? "" : text).getBytes(StandardCharsets.UTF_8));
    }

    public String b64UrlDecode(String text) {
        try {
            return new String(Base64.getUrlDecoder().decode(cleanBase64(text)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public String hexEncode(String text) {
        return hex((text == null ? "" : text).getBytes(StandardCharsets.ISO_8859_1), false);
    }

    /** 大写十六进制（很多签名要求大写） */
    public String hexUpper(String text) {
        return hex((text == null ? "" : text).getBytes(StandardCharsets.ISO_8859_1), true);
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

    public String urlEncode(String text) {
        try {
            return URLEncoder.encode(text == null ? "" : text, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public String urlDecode(String text) {
        try {
            return URLDecoder.decode(text == null ? "" : text, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /* ==================== 摘要 / HMAC ==================== */

    public String md5(String text) {
        return digest("MD5", text);
    }

    public String sha1(String text) {
        return digest("SHA-1", text);
    }

    public String sha256(String text) {
        return digest("SHA-256", text);
    }

    public String sha512(String text) {
        return digest("SHA-512", text);
    }

    public String hmacMd5(String keyText, String text) {
        return hmac("HmacMD5", keyText, text);
    }

    public String hmacSha1(String keyText, String text) {
        return hmac("HmacSHA1", keyText, text);
    }

    public String hmacSha256(String keyText, String text) {
        return hmac("HmacSHA256", keyText, text);
    }

    private String digest(String algo, String text) {
        try {
            MessageDigest md = MessageDigest.getInstance(algo);
            return hex(md.digest((text == null ? "" : text).getBytes(StandardCharsets.UTF_8)), false);
        } catch (Exception e) {
            return null;
        }
    }

    private String hmac(String algo, String keyText, String text) {
        try {
            Mac mac = Mac.getInstance(algo);
            mac.init(new SecretKeySpec((keyText == null ? "" : keyText).getBytes(StandardCharsets.UTF_8), algo));
            return hex(mac.doFinal((text == null ? "" : text).getBytes(StandardCharsets.UTF_8)), false);
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
        return encrypt("AES/CBC/PKCS5Padding", keyText, ivText, plain);
    }

    /** AES-CBC/PKCS5 解密：入参/出参都是 Base64 文本 */
    public String aesCbcDecrypt(String keyText, String ivText, String cipherB64) {
        return decrypt("AES/CBC/PKCS5Padding", keyText, ivText, cipherB64);
    }

    /** 加密并随机生成 IV，返回 Base64(IV‖CT)（多数小程序就是这么发的） */
    public String aesCbcEncryptPrependIv(String keyText, String plain) {
        try {
            byte[] iv = new byte[16];
            RANDOM.nextBytes(iv);
            String ct = encrypt("AES/CBC/PKCS5Padding", keyText, b64(iv), plain);
            if (ct == null) {
                return null;
            }
            return b64(concat(iv, Base64.getDecoder().decode(cleanBase64(ct))));
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
            return decrypt("AES/CBC/PKCS5Padding", keyText, b64(iv), b64(ct));
        } catch (Exception e) {
            return null;
        }
    }

    /** AES-ECB/PKCS5 加密（无 IV，常见于老接口） */
    public String aesEcbEncrypt(String keyText, String plain) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyOf(keyText, 16, 24, 32), "AES"));
            return b64(c.doFinal((plain == null ? "" : plain).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return null;
        }
    }

    public String aesEcbDecrypt(String keyText, String cipherB64) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyOf(keyText, 16, 24, 32), "AES"));
            return new String(c.doFinal(Base64.getDecoder().decode(cleanBase64(cipherB64))),
                    StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /* ==================== SM4（国密，GB/T 32907） ==================== */

    public String sm4CbcEncrypt(String keyText, String ivText, String plain) {
        try {
            byte[] key = keyOf(keyText, 16);
            byte[] iv = ivOf(ivText, 16);
            int[] rk = Sm4.expandKey(key);
            byte[] data = pkcs7((plain == null ? "" : plain).getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[data.length];
            byte[] prev = iv;
            for (int i = 0; i < data.length; i += 16) {
                byte[] blk = new byte[16];
                for (int j = 0; j < 16; j++) {
                    blk[j] = (byte) (data[i + j] ^ prev[j]);
                }
                byte[] ct = new byte[16];
                Sm4.encryptBlock(rk, blk, 0, ct, 0);
                System.arraycopy(ct, 0, out, i, 16);
                prev = ct;
            }
            return b64(out);
        } catch (Exception e) {
            return null;
        }
    }

    public String sm4CbcDecrypt(String keyText, String ivText, String cipherB64) {
        try {
            byte[] key = keyOf(keyText, 16);
            byte[] iv = ivOf(ivText, 16);
            byte[] data = Base64.getDecoder().decode(cleanBase64(cipherB64));
            if (data.length == 0 || data.length % 16 != 0) {
                return null;
            }
            int[] rk = Sm4.expandKey(key);
            byte[] out = new byte[data.length];
            byte[] prev = iv;
            for (int i = 0; i < data.length; i += 16) {
                byte[] blk = java.util.Arrays.copyOfRange(data, i, i + 16);
                byte[] pt = new byte[16];
                Sm4.decryptBlock(rk, blk, 0, pt, 0);
                for (int j = 0; j < 16; j++) {
                    out[i + j] = (byte) (pt[j] ^ prev[j]);
                }
                prev = blk;
            }
            return new String(unpad(out), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /** 加密并随机生成 IV，返回 Base64(IV‖CT)（SM4 版） */
    public String sm4CbcEncryptPrependIv(String keyText, String plain) {
        try {
            byte[] iv = new byte[16];
            RANDOM.nextBytes(iv);
            String ct = sm4CbcEncrypt(keyText, b64(iv), plain);
            if (ct == null) {
                return null;
            }
            return b64(concat(iv, Base64.getDecoder().decode(cleanBase64(ct))));
        } catch (Exception e) {
            return null;
        }
    }

    public String sm4CbcDecryptPrependIv(String keyText, String cipherB64) {
        try {
            byte[] all = Base64.getDecoder().decode(cleanBase64(cipherB64));
            if (all.length <= 16) {
                return null;
            }
            byte[] iv = java.util.Arrays.copyOf(all, 16);
            byte[] ct = java.util.Arrays.copyOfRange(all, 16, all.length);
            return sm4CbcDecrypt(keyText, b64(iv), b64(ct));
        } catch (Exception e) {
            return null;
        }
    }

    /* ==================== DES / 3DES ==================== */

    public String desCbcEncrypt(String keyText, String ivText, String plain) {
        return encrypt("DES/CBC/PKCS5Padding", keyText, ivText, plain, 8);
    }

    public String desCbcDecrypt(String keyText, String ivText, String cipherB64) {
        return decrypt("DES/CBC/PKCS5Padding", keyText, ivText, cipherB64, 8);
    }

    public String des3CbcEncrypt(String keyText, String ivText, String plain) {
        return encrypt("DESede/CBC/PKCS5Padding", keyText, ivText, plain, 24);
    }

    public String des3CbcDecrypt(String keyText, String ivText, String cipherB64) {
        return decrypt("DESede/CBC/PKCS5Padding", keyText, ivText, cipherB64, 24);
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

    /** n 个随机字节（ISO-8859-1 字符串，配 hexEncode 变成十六进制） */
    public String randomBytes(int n) {
        byte[] b = new byte[Math.max(0, n)];
        RANDOM.nextBytes(b);
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    /** n 字节随机数的十六进制（常用于 nonce / IV） */
    public String randomHex(int n) {
        byte[] b = new byte[Math.max(0, n)];
        RANDOM.nextBytes(b);
        return hex(b, false);
    }

    public String uuid() {
        return java.util.UUID.randomUUID().toString();
    }

    /* ==================== 内部 ==================== */

    private String encrypt(String transformation, String keyText, String ivText, String plain, int... keySizes) {
        try {
            int[] sizes = keySizes.length == 0 ? new int[]{16, 24, 32} : keySizes;
            Cipher c = Cipher.getInstance(transformation);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyOf(keyText, sizes), algorithm(transformation)),
                    new IvParameterSpec(ivOf(ivText, ivLength(transformation))));
            return b64(c.doFinal((plain == null ? "" : plain).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return null;
        }
    }

    private String decrypt(String transformation, String keyText, String ivText, String cipherB64, int... keySizes) {
        try {
            int[] sizes = keySizes.length == 0 ? new int[]{16, 24, 32} : keySizes;
            Cipher c = Cipher.getInstance(transformation);
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyOf(keyText, sizes), algorithm(transformation)),
                    new IvParameterSpec(ivOf(ivText, ivLength(transformation))));
            return new String(c.doFinal(Base64.getDecoder().decode(cleanBase64(cipherB64))),
                    StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static String algorithm(String transformation) {
        int i = transformation.indexOf('/');
        return i < 0 ? transformation : transformation.substring(0, i);
    }

    private static int ivLength(String transformation) {
        return transformation.startsWith("DES") ? 8 : 16;   // DES / DESede 的 IV 都是 8 字节
    }

    /** Base64 文本 → 密钥字节：优先 Base64，失败则按 UTF-8 */
    static byte[] keyBytes(String text) {
        return keyOf(text, 16, 24, 32);
    }

    /** Base64 文本 → 16 字节 IV：优先 Base64，失败则按 UTF-8 */
    static byte[] ivBytes(String text) {
        return ivOf(text, 16);
    }

    /** 键/IV 通用解析：先试 Base64（长度命中其一），再按 UTF-8 原文。 */
    static byte[] keyOf(String text, int... lengths) {
        if (text == null) {
            return new byte[0];
        }
        try {
            byte[] b = Base64.getDecoder().decode(cleanBase64(text));
            for (int n : lengths) {
                if (b.length == n) {
                    return b;
                }
            }
        } catch (Exception ignore) {
            // 落到 UTF-8
        }
        return text.getBytes(StandardCharsets.UTF_8);
    }

    static byte[] ivOf(String text, int length) {
        if (text == null || text.isEmpty()) {
            return new byte[length];
        }
        try {
            byte[] b = Base64.getDecoder().decode(cleanBase64(text));
            if (b.length == length) {
                return b;
            }
        } catch (Exception ignore) {
            // 落到 UTF-8
        }
        byte[] u = text.getBytes(StandardCharsets.UTF_8);
        return u.length == length ? u : java.util.Arrays.copyOf(u, length);
    }

    private static byte[] pkcs7(byte[] data) {
        int n = 16 - data.length % 16;
        byte[] out = java.util.Arrays.copyOf(data, data.length + n);
        for (int i = data.length; i < out.length; i++) {
            out[i] = (byte) n;
        }
        return out;
    }

    private static byte[] unpad(byte[] data) {
        if (data.length == 0) {
            return data;
        }
        int n = data[data.length - 1] & 0xFF;
        if (n < 1 || n > 16 || n > data.length) {
            return data;
        }
        for (int i = data.length - n; i < data.length; i++) {
            if ((data[i] & 0xFF) != n) {
                return data;
            }
        }
        return java.util.Arrays.copyOf(data, data.length - n);
    }

    private static String b64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static String hex(byte[] data, boolean upper) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            String h = String.format("%02x", b & 0xff);
            sb.append(upper ? h.toUpperCase() : h);
        }
        return sb.toString();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = java.util.Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String cleanBase64(String s) {
        return (s == null ? "" : s).replaceAll("\\s", "");
    }
}
