package burp.transform;

import burp.config.AppConfig;
import burp.config.Profile;
import burp.script.ScriptStage;

/**
 * 处理器与 UI 之间的中枢：解析配置 → 转换 Body → 记流水。
 *
 * <p>四个阶段覆盖所有工具的透明加解密需求：</p>
 * <pre>
 *   REQUEST_DECRYPT   密文请求 → 明文（Proxy 历史/编辑器里看明文、Repeater 里被解密后的请求体）
 *   REQUEST_ENCRYPT   明文请求 → 密文（真正发往服务端之前；Repeater/Intruder 每个变异包都走这里）
 *   RESPONSE_DECRYPT  密文响应 → 明文（展示给测试人员）
 *   RESPONSE_ENCRYPT  明文响应 → 密文（回写给客户端之前，保证客户端拿到的还是密文）
 * </pre>
 */
public final class CryptoService {

    public enum Phase {
        REQUEST_DECRYPT("请求解密", true, ScriptStage.CLIENT_TO_BURP),
        REQUEST_ENCRYPT("请求加密", true, ScriptStage.BURP_TO_SERVER),
        RESPONSE_DECRYPT("响应解密", false, ScriptStage.SERVER_TO_BURP),
        RESPONSE_ENCRYPT("响应加密", false, ScriptStage.BURP_TO_CLIENT);

        private final String label;
        private final boolean requestSide;
        private final ScriptStage stage;

        Phase(String label, boolean requestSide, ScriptStage stage) {
            this.label = label;
            this.requestSide = requestSide;
            this.stage = stage;
        }

        public String label() {
            return label;
        }

        public boolean requestSide() {
            return requestSide;
        }

        /** 对应的脚本接口（四接口之一） */
        public ScriptStage stage() {
            return stage;
        }
    }

    private volatile AppConfig config;
    private final PlaintextLog log;

    public CryptoService(AppConfig config, PlaintextLog log) {
        this.config = config;
        this.log = log;
        log.setLimit(config.logLimit);
        burp.script.ScriptSettings.pythonCommand(config.pythonCommand);
    }

    public AppConfig config() {
        return config;
    }

    public void update(AppConfig cfg) {
        this.config = cfg;
        log.setLimit(cfg.logLimit);
        burp.script.ScriptSettings.pythonCommand(cfg.pythonCommand);
    }

    public PlaintextLog log() {
        return log;
    }

    public boolean toolEnabled(AppConfig.ToolGroup group) {
        AppConfig c = config;
        return c.masterEnabled && c.toolEnabled(group);
    }

    /**
     * 处理一条消息的 Body。
     *
     * @param group  来源工具
     * @param phase  处理阶段
     * @param method HTTP 方法（只用于日志）
     * @param url    完整 URL（用于匹配规则）
     * @param body   原始 Body 字节
     * @return 处理结果；{@link TransformResult#changed()} 为 false 表示保持原样
     */
    public TransformResult process(AppConfig.ToolGroup group, Phase phase, String method,
                                   String url, byte[] body) {
        return process(group, phase, method, url, java.util.Collections.emptyList(), body);
    }

    public TransformResult process(AppConfig.ToolGroup group, Phase phase, String method,
                                   String url, java.util.List<String> headers, byte[] body) {
        AppConfig cfg = config;
        TargetResolver.Hit hit = TargetResolver.resolve(cfg, group, url, phase.requestSide());
        if (hit == null) {
            return TransformResult.skipped("未命中任何规则");
        }
        Profile profile = hit.profile;
        TransformResult result = MessageTransform.apply(profile, phase.stage(), url, method, headers, body);

        boolean interesting = result.kind != TransformResult.Kind.SKIPPED || cfg.debug;
        if (interesting) {
            String detail = result.detail;
            if (result.kind == TransformResult.Kind.SKIPPED && cfg.debug) {
                detail = "[" + profile.name + "/" + hit.source() + "] " + detail;
            }
            log.add(new PlaintextLog.Entry(group.label(), phase.label(), method,
                    TargetResolver.hostOf(url), url,
                    TransformResult.of(result.kind, result.plaintext, detail)));
        }
        return result;
    }
}
