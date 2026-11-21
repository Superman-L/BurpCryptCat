package burp.script;

/**
 * 脚本一次执行的结果。
 */
public final class ScriptOutcome {

    /** 新 Body（null = 不改动） */
    public final byte[] body;
    /** 说明，进日志用 */
    public final String detail;
    /** 是否是"失败"（脚本报错/超时），失败时一定不改动 */
    public final boolean failed;

    private ScriptOutcome(byte[] body, String detail, boolean failed) {
        this.body = body;
        this.detail = detail;
        this.failed = failed;
    }

    public static ScriptOutcome unchanged(String why) {
        return new ScriptOutcome(null, why, false);
    }

    public static ScriptOutcome changed(byte[] body, String detail) {
        return new ScriptOutcome(body, detail, false);
    }

    public static ScriptOutcome failed(String why) {
        return new ScriptOutcome(null, why, true);
    }

    public boolean changed() {
        return body != null;
    }
}
