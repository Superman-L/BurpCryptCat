package burp.crypto;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 基础编解码工具：Hex / Base64 / 严格 UTF-8 解码 / 可打印文本判定。
 *
 * <p>这里的 base64/hex 解码都是"严格"的：失败返回 null，而不是抛异常，
 * 因为透明加解密管线里需要频繁做"这串东西到底是不是密文"的试探判断。</p>
 */
public final class Codec {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Codec() {
    }

    /* ==================== Hex ==================== */

    public static String toHex(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /** 严格 hex 解码；非法输入返回 null。允许空格/换行分隔。 */
    public static byte[] fromHex(String text) {
        if (text == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ':' || c == '-') {
                continue;
            }
            sb.append(c);
        }
        if (sb.length() == 0 || sb.length() % 2 != 0) {
            return null;
        }
        byte[] out = new byte[sb.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = hexVal(sb.charAt(i * 2));
            int lo = hexVal(sb.charAt(i * 2 + 1));
            if (hi < 0 || lo < 0) {
                return null;
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static boolean isHex(String text) {
        return fromHex(text) != null;
    }

    private static int hexVal(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    /* ==================== Base64 ==================== */

    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /** 严格 base64 解码（支持无 padding、忽略换行）；非法输入返回 null。 */
    public static byte[] fromBase64(String text) {
        if (text == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
                continue;
            }
            sb.append(c);
        }
        while (sb.length() > 0 && sb.charAt(sb.length() - 1) == '=') {
            sb.setLength(sb.length() - 1);
        }
        if (sb.length() < 2 || sb.length() % 4 == 1) {
            return null;
        }
        for (int i = 0; i < sb.length(); i++) {
            char c = sb.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '+' || c == '/';
            if (!ok) {
                return null;
            }
        }
        int pad = (4 - sb.length() % 4) % 4;
        for (int i = 0; i < pad; i++) {
            sb.append('=');
        }
        try {
            return Base64.getDecoder().decode(sb.toString());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /* ==================== 文本 ==================== */

    public static Charset charset(String name) {
        if (name == null || name.isBlank()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(name.trim());
        } catch (Exception e) {
            return StandardCharsets.UTF_8;
        }
    }

    /** 严格解码：非法字节序列返回 null（而不是替换成 '?'）。 */
    public static String decodeStrict(byte[] data, Charset cs) {
        if (data == null) {
            return null;
        }
        CharsetDecoder dec = cs.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            CharBuffer cb = dec.decode(ByteBuffer.wrap(data));
            return cb.toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    /** 宽松解码：永远成功，用于日志/展示。 */
    public static String decodeLenient(byte[] data, Charset cs) {
        return data == null ? "" : new String(data, cs);
    }

    /**
     * 是否是一段"像样的明文文本"。
     *
     * <p>判定规则（用于解密试探，宁严勿松，避免把二进制误判成明文）：
     * <ul>
     *   <li>能按 UTF-8 严格解码</li>
     *   <li>不含除 \t \r \n 之外的控制字符</li>
     *   <li>不含 U+FFFD</li>
     * </ul>
     */
    public static boolean isPlainText(byte[] data) {
        String s = decodeStrict(data, StandardCharsets.UTF_8);
        if (s == null) {
            return false;
        }
        String text = s.strip();
        if (text.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\t' || c == '\r' || c == '\n') {
                continue;
            }
            if (c < 0x20 || c == 0x7F || c == '\uFFFD') {
                return false;
            }
        }
        return true;
    }

    /** 去掉不可见字符后截断，用于日志/界面展示。 */
    public static String preview(String text, int max) {
        if (text == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(Math.min(text.length(), max + 8));
        for (int i = 0; i < text.length() && sb.length() < max; i++) {
            char c = text.charAt(i);
            sb.append(c == '\r' || c == '\n' || c == '\t' ? ' ' : c);
        }
        if (text.length() > max) {
            sb.append(" …");
        }
        return sb.toString();
    }
}
