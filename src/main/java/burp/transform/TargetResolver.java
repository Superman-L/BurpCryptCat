package burp.transform;

import burp.config.AppConfig;
import burp.config.Profile;
import burp.config.Rule;

/**
 * 根据"工具 + 目标 URL"决定用哪条配置方案。
 *
 * <p>优先级：规则列表从上到下取第一条命中的 → 都没命中时用兜底方案 → 都没有则不处理。</p>
 */
public final class TargetResolver {

    /** 解析结果 */
    public static final class Hit {
        public final Profile profile;
        public final Rule rule;
        public final boolean fallback;

        Hit(Profile profile, Rule rule, boolean fallback) {
            this.profile = profile;
            this.rule = rule;
            this.fallback = fallback;
        }

        public String source() {
            if (fallback) {
                return "兜底方案";
            }
            return rule == null ? "规则" : "规则 " + rule.pattern;
        }
    }

    private TargetResolver() {
    }

    public static Hit resolve(AppConfig cfg, AppConfig.ToolGroup tool, String url,
                             boolean isRequest) {
        if (cfg == null || !cfg.masterEnabled || !cfg.toolEnabled(tool)) {
            return null;
        }
        String host = hostOf(url);
        for (Rule rule : cfg.rules) {
            if (!rule.enabled) {
                continue;
            }
            if (isRequest ? !rule.onRequest : !rule.onResponse) {
                continue;
            }
            Profile p = cfg.profile(rule.profileId);
            if (p == null || !p.enabled) {
                continue;
            }
            if (isRequest && !p.onRequest || !isRequest && !p.onResponse) {
                continue;
            }
            try {
                if (rule.matches(host, url)) {
                    return new Hit(p, rule, false);
                }
            } catch (RuntimeException ignore) {
                // 规则写错（正则非法等）不应影响其它规则
            }
        }
        Profile fb = cfg.profile(cfg.fallbackProfileId);
        if (fb != null && fb.enabled) {
            if (isRequest && fb.onRequest || !isRequest && fb.onResponse) {
                return new Hit(fb, null, true);
            }
        }
        return null;
    }

    /** 从 URL 里取 host（不含端口）。 */
    public static String hostOf(String url) {
        if (url == null) {
            return "";
        }
        int schemeIdx = url.indexOf("://");
        int start = schemeIdx >= 0 ? schemeIdx + 3 : 0;
        int end = url.length();
        for (int i = start; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c == '/' || c == '?' || c == '#') {
                end = i;
                break;
            }
        }
        String authority = url.substring(start, Math.min(end, url.length()));
        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            authority = authority.substring(at + 1);
        }
        int colon = authority.lastIndexOf(':');
        if (colon > 0 && authority.indexOf(']') < colon) {
            authority = authority.substring(0, colon);
        }
        return authority;
    }
}
