package burp.config;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 全局配置 + 配置方案列表 + 规则列表。
 *
 * <p>序列化用最简单的 INI 文本（便于人工检查、导出分享），持久化交给
 * {@link ConfigStore}（Burp 的 Preferences）。</p>
 */
public final class AppConfig {

    /** Burp 里受影响的工具分组 */
    public enum ToolGroup {
        PROXY("Proxy"),
        REPEATER("Repeater"),
        INTRUDER("Intruder"),
        OTHER("其它（Scanner / 其它插件 / Extensions）");

        private final String label;

        ToolGroup(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    public static final String INI_HEADER = "BurpCryptCat 配置文件 v1";

    /** 默认生效的工具：只动这三个，避免影响其它插件 */
    public static final Set<ToolGroup> DEFAULT_TOOLS =
            EnumSet.of(ToolGroup.PROXY, ToolGroup.REPEATER, ToolGroup.INTRUDER);

    /** 总开关 */
    public boolean masterEnabled = true;
    /** 没有规则命中时使用的兜底配置方案（空 = 不处理） */
    public String fallbackProfileId = "";
    /** 生效的工具 */
    public final Set<ToolGroup> tools = EnumSet.copyOf(DEFAULT_TOOLS);
    /** 明文查看器最多保留条数 */
    public int logLimit = 1000;
    /** Proxy 是否参与透明加解密 */
    public boolean proxyEnabled = true;
    /**
     * 请求放行前是否把明文重新加密。
     *
     * <p>这里有一个 Burp 的硬限制：Proxy 历史保存的就是"最终上线/回写的报文"，
     * 所以"历史显示明文"和"线上保持密文"不可兼得。关闭本开关 = 历史里能读到明文，
     * 代价是服务端也会收到明文。</p>
     */
    public boolean proxyReencryptRequest = true;
    /** 响应回写客户端前是否重新加密（关闭 = 历史明文，但客户端收到明文） */
    public boolean proxyReencryptResponse = true;
    /** 输出更多诊断日志 */
    public boolean debug = false;
    /** 明文页签里对 JSON 做缩进美化 */
    public boolean beautifyJson = true;

    public final List<Profile> profiles = new ArrayList<>();
    public final List<Rule> rules = new ArrayList<>();

    /* ==================== 默认配置 ==================== */

    public static AppConfig defaults() {
        AppConfig c = new AppConfig();
        Profile sample = new Profile("sample", "示例 AES/CBC/PKCS5Padding");
        sample.cipher = "AES/CBC/PKCS5Padding";
        sample.key = "0123456789abcdef";
        sample.keyFormat = burp.crypto.KeyMaterial.Format.UTF8;
        sample.iv = "0123456789abcdef";
        sample.ivFormat = burp.crypto.KeyMaterial.Format.UTF8;
        sample.ivMode = burp.crypto.CryptoEngine.IvMode.AUTO;
        sample.bodyEncoding = Profile.BodyEncoding.BASE64;
        sample.comment = "示例配置：把 Key/IV 改成目标 App 的即可。默认不生效，需在规则里启用。";
        c.profiles.add(sample);

        Rule rule = new Rule("sample", Rule.MatchType.URL_GLOB, "*");
        rule.enabled = false;
        rule.comment = "默认关闭；勾选后可对全部流量生效";
        c.rules.add(rule);
        return c;
    }

    /* ==================== 查询 ==================== */

    public Profile profile(String id) {
        if (id == null || id.isEmpty()) {
            return null;
        }
        for (Profile p : profiles) {
            if (id.equals(p.id)) {
                return p;
            }
        }
        return null;
    }

    public Rule rule(String id) {
        for (Rule r : rules) {
            if (r.id.equals(id)) {
                return r;
            }
        }
        return null;
    }

    public boolean toolEnabled(ToolGroup group) {
        return tools.contains(group);
    }

    /** 是否"对所有工具生效"（含 Scanner、其它插件等） */
    public boolean allToolsEnabled() {
        return tools.containsAll(EnumSet.allOf(ToolGroup.class));
    }

    /** 顶层开关：一次性打开/关闭所有工具 */
    public void setAllTools(boolean on) {
        tools.clear();
        if (on) {
            tools.addAll(EnumSet.allOf(ToolGroup.class));
        } else {
            tools.addAll(DEFAULT_TOOLS);
        }
    }

    /** 界面顶部的一句话状态。 */
    public String statusText() {
        if (!masterEnabled) {
            return "总开关已关闭：不会对任何流量做加解密";
        }
        boolean anyEnabled = rules.stream().anyMatch(r -> r.enabled);
        if (!anyEnabled && fallbackProfileId.isBlank()) {
            return "没有任何启用的规则或兜底方案：不会生效";
        }
        if (profiles.stream().noneMatch(p -> p.enabled)) {
            return "所有配置方案都被禁用";
        }
        if (tools.isEmpty()) {
            return "所有工具都被禁用";
        }
        return "运行中，规则 " + rules.stream().filter(r -> r.enabled).count()
                + " 条，配置方案 " + profiles.size() + " 个";
    }

    public void copyFrom(AppConfig o) {
        masterEnabled = o.masterEnabled;
        fallbackProfileId = o.fallbackProfileId;
        tools.clear();
        tools.addAll(o.tools);
        logLimit = o.logLimit;
        proxyEnabled = o.proxyEnabled;
        proxyReencryptRequest = o.proxyReencryptRequest;
        proxyReencryptResponse = o.proxyReencryptResponse;
        debug = o.debug;
        beautifyJson = o.beautifyJson;
        profiles.clear();
        profiles.addAll(o.profiles);
        rules.clear();
        rules.addAll(o.rules);
    }

    /* ==================== INI 序列化 ==================== */

    public String toIni() {
        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(INI_HEADER).append('\n');
        sb.append("[global]\n");
        kv(sb, "master", String.valueOf(masterEnabled));
        kv(sb, "fallback", fallbackProfileId);
        StringBuilder t = new StringBuilder();
        for (ToolGroup g : tools) {
            if (t.length() > 0) {
                t.append(',');
            }
            t.append(g.name());
        }
        kv(sb, "tools", t.toString());
        kv(sb, "logLimit", String.valueOf(logLimit));
        kv(sb, "proxyEnabled", String.valueOf(proxyEnabled));
        kv(sb, "proxyReencryptRequest", String.valueOf(proxyReencryptRequest));
        kv(sb, "proxyReencryptResponse", String.valueOf(proxyReencryptResponse));
        kv(sb, "debug", String.valueOf(debug));
        kv(sb, "beautifyJson", String.valueOf(beautifyJson));
        sb.append('\n');
        for (Profile p : profiles) {
            sb.append("[profile]\n");
            kv(sb, "id", p.id);
            kv(sb, "name", p.name);
            kv(sb, "enabled", String.valueOf(p.enabled));
            kv(sb, "cipher", p.cipher);
            kv(sb, "key", p.key);
            kv(sb, "keyFormat", p.keyFormat.name());
            kv(sb, "iv", p.iv);
            kv(sb, "ivFormat", p.ivFormat.name());
            kv(sb, "ivMode", p.ivMode.name());
            kv(sb, "engine", p.engine.name());
            kv(sb, "script", p.scriptPath);
            kv(sb, "scriptTimeout", String.valueOf(p.scriptTimeoutMs));
            kv(sb, "bodyEncoding", p.bodyEncoding.name());
            kv(sb, "bodyScope", p.bodyScope.name());
            kv(sb, "jsonField", p.jsonField);
            kv(sb, "charset", p.charset);
            kv(sb, "onRequest", String.valueOf(p.onRequest));
            kv(sb, "onResponse", String.valueOf(p.onResponse));
            kv(sb, "comment", p.comment);
            sb.append('\n');
        }
        for (Rule r : rules) {
            sb.append("[rule]\n");
            kv(sb, "id", r.id);
            kv(sb, "enabled", String.valueOf(r.enabled));
            kv(sb, "matchType", r.matchType.name());
            kv(sb, "pattern", r.pattern);
            kv(sb, "profile", r.profileId);
            kv(sb, "onRequest", String.valueOf(r.onRequest));
            kv(sb, "onResponse", String.valueOf(r.onResponse));
            kv(sb, "comment", r.comment);
            sb.append('\n');
        }
        return sb.toString();
    }

    private static void kv(StringBuilder sb, String k, String v) {
        sb.append(k).append('=').append(escape(v == null ? "" : v)).append('\n');
    }

    private static String escape(String v) {
        return v.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n");
    }

    private static String unescape(String v) {
        StringBuilder sb = new StringBuilder(v.length());
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '\\' && i + 1 < v.length()) {
                char n = v.charAt(++i);
                switch (n) {
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case '\\' -> sb.append('\\');
                    default -> sb.append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public static AppConfig fromIni(String text) {
        AppConfig c = new AppConfig();
        c.profiles.clear();
        c.rules.clear();
        c.tools.clear();
        if (text == null || text.isBlank()) {
            return defaults();
        }
        String section = "";
        Map<String, String> cur = new LinkedHashMap<>();
        for (String rawLine : text.split("\\R")) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) {
                continue;
            }
            if (line.startsWith("[") && line.endsWith("]")) {
                flush(c, section, cur);
                section = line.substring(1, line.length() - 1).trim().toLowerCase();
                cur.clear();
                continue;
            }
            int eq = line.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            cur.put(line.substring(0, eq).trim().toLowerCase(), unescape(line.substring(eq + 1)));
        }
        flush(c, section, cur);
        if (c.profiles.isEmpty() && c.rules.isEmpty()) {
            return defaults();
        }
        return c;
    }

    private static void flush(AppConfig c, String section, Map<String, String> kv) {
        if (kv.isEmpty()) {
            return;
        }
        switch (section) {
            case "global" -> {
                c.masterEnabled = bool(kv.get("master"), true);
                c.fallbackProfileId = kv.getOrDefault("fallback", "");
                c.tools.clear();
                String tools = kv.getOrDefault("tools", "PROXY,REPEATER,INTRUDER").trim();
                if (tools.equalsIgnoreCase("ALL")) {
                    c.tools.addAll(EnumSet.allOf(ToolGroup.class));
                } else {
                    for (String t : tools.split(",")) {
                        if (t.isBlank()) {
                            continue;
                        }
                        try {
                            c.tools.add(ToolGroup.valueOf(t.trim().toUpperCase()));
                        } catch (IllegalArgumentException ignore) {
                            // 未知工具名直接忽略，保证旧配置兼容
                        }
                    }
                }
                c.logLimit = intOf(kv.get("loglimit"), 1000);
                c.proxyEnabled = bool(kv.get("proxyenabled"), true);
                c.proxyReencryptRequest = bool(kv.get("proxyreencryptrequest"), true);
                c.proxyReencryptResponse = bool(kv.get("proxyreencryptresponse"), true);
                c.debug = bool(kv.get("debug"), false);
                c.beautifyJson = bool(kv.get("beautifyjson"), true);
            }
            case "profile" -> {
                Profile p = new Profile();
                p.id = kv.getOrDefault("id", p.id);
                p.name = kv.getOrDefault("name", p.name);
                p.enabled = bool(kv.get("enabled"), true);
                p.cipher = kv.getOrDefault("cipher", p.cipher);
                p.key = kv.getOrDefault("key", "");
                p.keyFormat = burp.crypto.KeyMaterial.Format.of(kv.get("keyformat"));
                p.iv = kv.getOrDefault("iv", "");
                p.ivFormat = burp.crypto.KeyMaterial.Format.of(kv.get("ivformat"));
                p.ivMode = burp.crypto.CryptoEngine.IvMode.of(kv.get("ivmode"));
                p.engine = Profile.Engine.of(kv.get("engine"));
                p.scriptPath = kv.getOrDefault("script", "");
                p.scriptTimeoutMs = intOf(kv.get("scripttimeout"), 5000);
                p.bodyEncoding = Profile.BodyEncoding.of(kv.get("bodyencoding"));
                p.bodyScope = Profile.BodyScope.of(kv.get("bodyscope"));
                p.jsonField = kv.getOrDefault("jsonfield", "data");
                p.charset = kv.getOrDefault("charset", "UTF-8");
                p.onRequest = bool(kv.get("onrequest"), true);
                p.onResponse = bool(kv.get("onresponse"), true);
                p.comment = kv.getOrDefault("comment", "");
                c.profiles.add(p);
            }
            case "rule" -> {
                Rule r = new Rule();
                r.id = kv.getOrDefault("id", r.id);
                r.enabled = bool(kv.get("enabled"), true);
                r.matchType = Rule.MatchType.of(kv.get("matchtype"));
                r.pattern = kv.getOrDefault("pattern", "*");
                r.profileId = kv.getOrDefault("profile", "");
                r.onRequest = bool(kv.get("onrequest"), true);
                r.onResponse = bool(kv.get("onresponse"), true);
                r.comment = kv.getOrDefault("comment", "");
                c.rules.add(r);
            }
            default -> {
            }
        }
    }

    private static boolean bool(String v, boolean def) {
        if (v == null || v.isBlank()) {
            return def;
        }
        return v.trim().equalsIgnoreCase("true") || v.trim().equals("1")
                || v.trim().equalsIgnoreCase("yes");
    }

    private static int intOf(String v, int def) {
        try {
            return v == null ? def : Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }
}
