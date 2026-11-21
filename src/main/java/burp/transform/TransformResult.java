package burp.transform;

/**
 * 一次 Body 处理的结果。{@code body} 为 null 表示"没有改动，用原来的"。
 */
public final class TransformResult {

    public enum Kind {
        ENCRYPTED("已加密"),
        DECRYPTED("已解密"),
        SKIPPED("跳过"),
        FAILED("失败");

        private final String label;

        Kind(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public final Kind kind;
    public final byte[] body;
    /** 明文（解密成功时为明文；加密时为加密前的明文），可能为 null */
    public final String plaintext;
    /** 简短说明，进日志用 */
    public final String detail;

    private TransformResult(Kind kind, byte[] body, String plaintext, String detail) {
        this.kind = kind;
        this.body = body;
        this.plaintext = plaintext;
        this.detail = detail;
    }

    public static TransformResult encrypted(byte[] body, String plaintext) {
        return new TransformResult(Kind.ENCRYPTED, body, plaintext, "已加密");
    }

    public static TransformResult decrypted(byte[] body, String plaintext) {
        return new TransformResult(Kind.DECRYPTED, body, plaintext, "已解密");
    }

    public static TransformResult skipped(String why) {
        return new TransformResult(Kind.SKIPPED, null, null, why);
    }

    public static TransformResult skipped(String why, String plaintext) {
        return new TransformResult(Kind.SKIPPED, null, plaintext, why);
    }

    public static TransformResult failed(String why) {
        return new TransformResult(Kind.FAILED, null, null, why);
    }

    public static TransformResult failed(String why, String plaintext) {
        return new TransformResult(Kind.FAILED, null, plaintext, why);
    }

    /** 仅用于日志复制（不带 Body）。 */
    public static TransformResult of(Kind kind, String plaintext, String detail) {
        return new TransformResult(kind, null, plaintext, detail);
    }

    /** 是否需要替换 Body。 */
    public boolean changed() {
        return body != null;
    }

    @Override
    public String toString() {
        return kind.label() + (detail == null || detail.isEmpty() ? "" : "（" + detail + "）");
    }
}
