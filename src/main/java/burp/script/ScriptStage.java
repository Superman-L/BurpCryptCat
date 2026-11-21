package burp.script;

/**
 * 四个脚本接口 —— 与 Proxy 的四个处理阶段一一对应。
 *
 * <p>需求："插件提供四个接口分别是 客户端到burp、burp到服务端、服务端到burp、burp到客户端"。
 * 脚本里实现同名函数即可，缺哪个就跳过哪个阶段。</p>
 *
 * <pre>
 *   客户端 ──密文──► Burp ──① clientToBurp──► [Burp 内部/编辑器]
 *                              ──② burpToServer──► 服务端
 *   服务端 ──密文──► Burp ──③ serverToBurp──► [Burp 内部/编辑器]
 *                              ──④ burpToClient──► 客户端
 * </pre>
 */
public enum ScriptStage {

    /** ① 客户端 → Burp：Proxy 收到请求时（一般做解密，让 Burp 里看到明文） */
    CLIENT_TO_BURP(1, "clientToBurp", "客户端 → Burp", false),
    /** ② Burp → 服务端：请求放行前（一般做加密，让服务端收到密文） */
    BURP_TO_SERVER(2, "burpToServer", "Burp → 服务端", true),
    /** ③ 服务端 → Burp：收到响应时（一般做解密，让 Burp 里看到明文） */
    SERVER_TO_BURP(3, "serverToBurp", "服务端 → Burp", false),
    /** ④ Burp → 客户端：响应回写前（一般做加密，让客户端收到密文） */
    BURP_TO_CLIENT(4, "burpToClient", "Burp → 客户端", true);

    private final int code;
    private final String hook;
    private final String label;
    private final boolean outbound;

    ScriptStage(int code, String hook, String label, boolean outbound) {
        this.code = code;
        this.hook = hook;
        this.label = label;
        this.outbound = outbound;
    }

    public int code() {
        return code;
    }

    /** 脚本里的函数名 */
    public String hook() {
        return hook;
    }

    public String label() {
        return label;
    }

    /** true = 发往目标方向（请求放行/响应回写），false = 收进 Burp 方向 */
    public boolean outbound() {
        return outbound;
    }

    public boolean isRequest() {
        return this == CLIENT_TO_BURP || this == BURP_TO_SERVER;
    }

    /** 内置算法模式下这个阶段相当于"加密"还是"解密" */
    public boolean builtinEncrypt() {
        return outbound;
    }

    public static ScriptStage ofCode(int code) {
        for (ScriptStage s : values()) {
            if (s.code == code) {
                return s;
            }
        }
        return CLIENT_TO_BURP;
    }

    public static ScriptStage ofHook(String hook) {
        for (ScriptStage s : values()) {
            if (s.hook.equalsIgnoreCase(hook)) {
                return s;
            }
        }
        return null;
    }
}
