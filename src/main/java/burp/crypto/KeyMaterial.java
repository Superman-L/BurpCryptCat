package burp.crypto;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 把用户在界面上填的 Key / IV 文本解析成字节。
 *
 * <p>痛点：{@code 1234567890123456} 既是"16 位密码"也是"8 字节 HEX"，AUTO 模式
 * 如果简单按"像不像 HEX"判断，会把最常见的 16 位明文密码错当成 8 字节密钥。
 * 因此 AUTO 的策略是：**先枚举候选解码方式，再用当前算法允许的长度去筛选**，
 * 只有长度对得上的候选才会被采纳。</p>
 */
public final class KeyMaterial {

    public enum Format {
        AUTO("自动识别"),
        UTF8("文本(UTF-8)"),
        HEX("HEX"),
        BASE64("Base64");

        private final String label;

        Format(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }

        @Override
        public String toString() {
            return label;
        }

        public static Format of(String name) {
            if (name == null) {
                return AUTO;
            }
            for (Format f : values()) {
                if (f.name().equalsIgnoreCase(name.trim())) {
                    return f;
                }
            }
            return AUTO;
        }
    }

    private KeyMaterial() {
    }

    /** 解析密钥。allowed 为空表示不限制长度。 */
    public static byte[] key(String text, Format format, CipherSpec spec) throws CryptoException {
        if (text == null) {
            text = "";
        }
        if (text.isEmpty()) {
            throw new CryptoException("密钥为空");
        }
        int[] allowed = spec == null ? new int[0] : spec.keyLengths;
        byte[] out = resolve(text, format, allowed, "密钥");
        if (allowed.length > 0) {
            boolean ok = false;
            for (int len : allowed) {
                if (out.length == len) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                throw new CryptoException("密钥长度 " + out.length + " 字节，"
                        + spec.family + " 需要 " + join(allowed) + " 字节");
            }
        } else if (out.length == 0) {
            throw new CryptoException("密钥解析结果为空");
        }
        return out;
    }

    /** 解析 IV / Nonce。返回 null 表示"没有 IV"（ECB、流式算法）。 */
    public static byte[] iv(String text, Format format, CipherSpec spec) throws CryptoException {
        if (spec == null || spec.ivLength == 0) {
            return null;
        }
        if (text == null || text.isBlank()) {
            throw new CryptoException(spec.mode + " 模式需要 IV（" + spec.ivLength + " 字节）");
        }
        int[] allowed;
        if (spec.ivLength > 0) {
            allowed = spec.aead ? new int[]{spec.ivLength, 16} : new int[]{spec.ivLength};
        } else {
            allowed = new int[0];
        }
        byte[] out = resolve(text, format, allowed, "IV");
        if (allowed.length > 0) {
            boolean ok = false;
            for (int len : allowed) {
                if (out.length == len) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                throw new CryptoException("IV 长度 " + out.length + " 字节，" + spec.mode
                        + " 需要 " + join(allowed) + " 字节");
            }
        }
        return out;
    }

    /* ==================== 内部 ==================== */

    private static byte[] resolve(String text, Format format, int[] allowed, String what)
            throws CryptoException {
        String raw = text.trim();
        if (format != Format.AUTO) {
            byte[] direct = decodeExplicit(raw, format);
            if (direct == null) {
                throw new CryptoException(what + " 不是合法的 " + format.label() + " 数据");
            }
            return direct;
        }
        // AUTO：枚举候选，长度匹配的优先；顺序 HEX -> BASE64 -> UTF8
        List<byte[]> candidates = new ArrayList<>(3);
        byte[] hex = Codec.fromHex(raw);
        if (hex != null) {
            candidates.add(hex);
        }
        byte[] b64 = Codec.fromBase64(raw);
        if (b64 != null) {
            candidates.add(b64);
        }
        candidates.add(raw.getBytes(StandardCharsets.UTF_8));

        if (allowed.length > 0) {
            for (byte[] c : candidates) {
                for (int len : allowed) {
                    if (c.length == len) {
                        return c;
                    }
                }
            }
        }
        // 长度都不匹配：返回 UTF-8 原文，让上层的长度校验给出可读报错
        return candidates.get(candidates.size() - 1);
    }

    private static byte[] decodeExplicit(String raw, Format format) {
        return switch (format) {
            case UTF8 -> raw.getBytes(StandardCharsets.UTF_8);
            case HEX -> Codec.fromHex(raw);
            case BASE64 -> Codec.fromBase64(raw);
            default -> raw.getBytes(StandardCharsets.UTF_8);
        };
    }

    private static String join(int[] lengths) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lengths.length; i++) {
            if (i > 0) {
                sb.append('/');
            }
            sb.append(lengths[i]);
        }
        return sb.toString();
    }
}
