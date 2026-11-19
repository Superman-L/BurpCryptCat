package burp.transform;

import burp.config.Profile;
import burp.crypto.Codec;

/**
 * 密文在 HTTP Body 里的"表示层"转换：真实密文字节 ↔ 载体文本（Base64 / HEX / 原始二进制）。
 *
 * <p>所有方法都保持"要么成功、要么原样返回 null"，方便上层做试探性判定。</p>
 */
public final class BodyCodec {

    private BodyCodec() {
    }

    /** 载体文本 → 密文字节；不是合法的该编码时返回 null。 */
    public static byte[] toCipherBytes(String text, Profile.BodyEncoding encoding) {
        if (text == null) {
            return null;
        }
        String s = text.trim();
        if (s.isEmpty()) {
            return null;
        }
        return switch (encoding) {
            case BASE64 -> Codec.fromBase64(s);
            case HEX -> Codec.fromHex(s);
            case RAW -> s.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        };
    }

    /** 密文字节 → 载体文本。 */
    public static String fromCipherBytes(byte[] cipher, Profile.BodyEncoding encoding) {
        return switch (encoding) {
            case BASE64 -> Codec.toBase64(cipher);
            case HEX -> Codec.toHex(cipher);
            case RAW -> new String(cipher, java.nio.charset.StandardCharsets.ISO_8859_1);
        };
    }
}
