package burp.crypto;

/**
 * 一条"算法描述"，例如 {@code AES/CBC/PKCS5Padding}、{@code SM4/CBC/PKCS5Padding}、{@code RC4}。
 *
 * <p>解析之后就知道：分组长度、合法密钥长度、IV 长度、是否 AEAD、实际交给 JCE 的
 * transformation 是什么。UI 里的下拉框、配置校验、加解密引擎都围绕这个类转。</p>
 */
public final class CipherSpec {

    public static final String PKCS5 = "PKCS5Padding";
    public static final String PKCS7 = "PKCS7Padding";
    public static final String NO_PADDING = "NoPadding";
    public static final String ZERO = "ZeroPadding";
    public static final String ISO10126 = "ISO10126Padding";
    public static final String ANSIX923 = "ANSIX923Padding";

    /** 用户填写的原始描述，例如 AES/CBC/PKCS5Padding */
    public final String transformation;
    /** 算法族：AES / DES / DESede / SM4 / RC4 / ChaCha20 / 其它 */
    public final String family;
    /** 模式：CBC / ECB / CTR / CFB / OFB / GCM / NONE */
    public final String mode;
    /** 填充：PKCS5Padding / NoPadding / ZeroPadding ... */
    public final String padding;
    /** 分组长度（字节）；0 表示流式或未知 */
    public final int blockSize;
    /** 合法密钥长度（字节）；空数组表示不限制 */
    public final int[] keyLengths;
    /** 需要的 IV 长度（字节）；0 表示不需要，-1 表示交给 JCE 决定 */
    public final int ivLength;
    /** 是否 AEAD（GCM） */
    public final boolean aead;

    private CipherSpec(String transformation, String family, String mode, String padding,
                       int blockSize, int[] keyLengths, int ivLength, boolean aead) {
        this.transformation = transformation;
        this.family = family;
        this.mode = mode;
        this.padding = padding;
        this.blockSize = blockSize;
        this.keyLengths = keyLengths;
        this.ivLength = ivLength;
        this.aead = aead;
    }

    /* ==================== 解析 ==================== */

    public static CipherSpec of(String text) throws CryptoException {
        if (text == null || text.isBlank()) {
            throw new CryptoException("算法不能为空");
        }
        String raw = text.trim();
        String[] parts = raw.split("/");
        String family = normalizeFamily(parts[0]);
        String mode = parts.length > 1 && !parts[1].isBlank() ? parts[1].trim().toUpperCase() : "ECB";
        String padding = parts.length > 2 && !parts[2].isBlank()
                ? normalizePadding(parts[2]) : defaultPadding(family, mode);

        if (parts.length > 3) {
            throw new CryptoException("算法描述格式应为 算法/模式/填充，例如 AES/CBC/PKCS5Padding");
        }

        int blockSize;
        int[] keyLengths;
        switch (family) {
            case "AES" -> {
                blockSize = 16;
                keyLengths = new int[]{16, 24, 32};
            }
            case "DES" -> {
                blockSize = 8;
                keyLengths = new int[]{8};
            }
            case "DESEDE" -> {
                blockSize = 8;
                keyLengths = new int[]{24};
                family = "DESede";
            }
            case "SM4" -> {
                blockSize = 16;
                keyLengths = new int[]{16};
            }
            case "RC4", "ARCFOUR" -> {
                blockSize = 0;
                keyLengths = new int[0];
                family = "RC4";
                mode = "NONE";
                padding = NO_PADDING;
            }
            case "CHACHA20" -> {
                blockSize = 0;
                keyLengths = new int[]{32};
                family = "ChaCha20";
                mode = "NONE";
                padding = NO_PADDING;
            }
            default -> {
                blockSize = 0;
                keyLengths = new int[0];
            }
        }

        boolean streamLike = blockSize == 0 || mode.equals("CTR") || mode.equals("CFB")
                || mode.equals("OFB") || mode.equals("GCM");
        if (streamLike && !padding.equals(NO_PADDING)) {
            // 流式模式没有填充概念，静默归一到 NoPadding，避免 JCE 直接报 "Padding not supported"
            padding = NO_PADDING;
        }

        int ivLength;
        if (mode.equals("ECB") || blockSize == 0) {
            ivLength = "ChaCha20".equals(family) ? 12 : 0;
        } else if (mode.equals("GCM")) {
            ivLength = 12;
        } else {
            ivLength = blockSize;
        }

        boolean aead = mode.equals("GCM");
        String canonical = family.equals("RC4") || family.equals("ChaCha20")
                ? family
                : family + "/" + mode + "/" + padding;
        return new CipherSpec(canonical, family, mode, padding, blockSize, keyLengths, ivLength, aead);
    }

    private static String normalizeFamily(String s) {
        String f = s.trim().toUpperCase().replace("-", "").replace("_", "");
        if (f.equals("3DES") || f.equals("TRIPLEDES") || f.equals("DESEDE")) {
            return "DESEDE";
        }
        if (f.equals("AES128") || f.equals("AES192") || f.equals("AES256")) {
            return "AES";
        }
        return f;
    }

    private static String normalizePadding(String p) {
        String v = p.trim().toUpperCase().replace("-", "").replace("_", "");
        return switch (v) {
            case "PKCS5", "PKCS5PADDING", "PKCS7", "PKCS7PADDING", "PKCS", "PKCS7PAD" -> PKCS5;
            case "NONE", "NOPADDING", "NOPAD" -> NO_PADDING;
            case "ZERO", "ZEROPADDING", "ZEROSPADDING" -> ZERO;
            case "ISO10126", "ISO10126PADDING" -> ISO10126;
            case "ANSIX923", "ANSIX923PADDING" -> ANSIX923;
            default -> p.trim();
        };
    }

    private static String defaultPadding(String family, String mode) {
        if (mode.equals("CTR") || mode.equals("CFB") || mode.equals("OFB") || mode.equals("GCM")) {
            return NO_PADDING;
        }
        return PKCS5;
    }

    /* ==================== 派生信息 ==================== */

    /** 判断是否自带填充（即需要我们对齐分组长度）。 */
    public boolean hasPadding() {
        return !padding.equals(NO_PADDING);
    }

    public boolean isZeroPadding() {
        return padding.equals(ZERO);
    }

    /** 是否需要 IV。 */
    public boolean requiresIv() {
        return ivLength != 0;
    }

    /** 只在 CBC/ECB 这类"有分组结构"的模式下才需要做分组对齐检查。 */
    public boolean isBlockMode() {
        return blockSize > 0 && (mode.equals("ECB") || mode.equals("CBC"));
    }

    /** 生成 JCE 的 transformation；SM4 由内置实现处理，不走 JCE。 */
    public String jceTransformation() {
        if (family.equals("RC4")) {
            return "ARCFOUR";
        }
        if (family.equals("ChaCha20")) {
            return "ChaCha20";
        }
        String p = padding.equals(ZERO) ? NO_PADDING : padding;
        if (family.equals("AES") || family.equals("DES") || family.equals("DESede")) {
            return family + "/" + mode + "/" + p;
        }
        // 自定义算法族：原样交给 JCE，让用户自己拼
        return transformation;
    }

    /** 便于在 UI 上显示的说明文字。 */
    public String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append(family);
        if (!mode.equals("NONE")) {
            sb.append('/').append(mode);
        }
        if (!padding.equals(NO_PADDING)) {
            sb.append('/').append(padding);
        }
        if (blockSize > 0) {
            sb.append("  分组").append(blockSize).append("字节");
        } else {
            sb.append("  流式");
        }
        if (keyLengths.length > 0) {
            sb.append("，密钥");
            for (int i = 0; i < keyLengths.length; i++) {
                if (i > 0) {
                    sb.append('/');
                }
                sb.append(keyLengths[i]);
            }
            sb.append("字节");
        }
        if (ivLength > 0) {
            sb.append("，IV ").append(ivLength).append("字节");
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return transformation;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof CipherSpec other && transformation.equalsIgnoreCase(other.transformation);
    }

    @Override
    public int hashCode() {
        return transformation.toLowerCase().hashCode();
    }
}
