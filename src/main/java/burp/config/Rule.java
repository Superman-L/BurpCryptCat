package burp.config;

import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 作用范围规则：满足匹配条件的请求/响应才自动加解密。
 *
 * <p>匹配对象是完整 URL 与 Host，因此可以做到"只对 api.example.com 生效"或
 * "只对 /gw/ 路径生效"这类需求。</p>
 */
public final class Rule {

    public enum MatchType {
        /** 按 Host 匹配，支持 *.example.com 通配 */
        HOST("Host"),
        /** 按完整 URL glob 匹配，支持 * 与 ? */
        URL_GLOB("URL 通配"),
        /** 按完整 URL 正则匹配 */
        URL_REGEX("URL 正则"),
        /** 自定义表达式：host / path / query / url + == != ~= contains startsWith endsWith like，支持 && || ! 等 */
        CUSTOM("自定义表达式");

        private final String label;

        MatchType(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }

        @Override
        public String toString() {
            return label;
        }

        public static MatchType of(String n) {
            if (n == null) {
                return HOST;
            }
            for (MatchType e : values()) {
                if (e.name().equalsIgnoreCase(n.trim())) {
                    return e;
                }
            }
            return HOST;
        }
    }

    public String id = UUID.randomUUID().toString().substring(0, 8);
    public boolean enabled = true;
    public MatchType matchType = MatchType.HOST;
    public String pattern = "*";
    /** 命中的配置方案 id */
    public String profileId = "";
    public boolean onRequest = true;
    public boolean onResponse = true;
    public String comment = "";

    private transient Pattern compiled;
    private transient String compiledSource;
    private transient RuleExpression expression;
    private transient String expressionSource;

    public Rule() {
    }

    public Rule(String profileId, MatchType type, String pattern) {
        this.profileId = profileId;
        this.matchType = type;
        this.pattern = pattern;
    }

    public void touch() {
        compiled = null;
        compiledSource = null;
        expression = null;
        expressionSource = null;
    }

    /** 是否命中。host 不含端口，url 为完整 URL。 */
    public boolean matches(String host, String url) {
        if (pattern == null || pattern.isBlank()) {
            return false;
        }
        String p = pattern.trim();
        if (p.equals("*")) {
            return true;
        }
        return switch (matchType) {
            case HOST -> matchHost(host, p);
            case URL_GLOB -> glob(p).matcher(url == null ? "" : url).matches();
            case URL_REGEX -> {
                Pattern re = compile(p);
                yield re != null && re.matcher(url == null ? "" : url).find();
            }
            case CUSTOM -> {
                RuleExpression expr = expression(p);
                yield expr != null && expr.test(host, url);
            }
        };
    }

    private static boolean matchHost(String host, String pattern) {
        if (host == null) {
            return false;
        }
        String h = host.toLowerCase();
        String p = pattern.toLowerCase();
        if (p.startsWith("*.")) {
            String suffix = p.substring(1);       // .example.com
            return h.endsWith(suffix) || h.equals(p.substring(2));
        }
        if (p.startsWith(".")) {
            return h.endsWith(p) || h.equals(p.substring(1));
        }
        return h.equals(p) || h.endsWith("." + p);
    }

    /** 自定义表达式：编译失败返回 null（不命中，不影响其它规则）。 */
    private RuleExpression expression(String p) {
        if (expression != null && p.equals(expressionSource)) {
            return expression;
        }
        try {
            expression = RuleExpression.compile(p);
            expressionSource = p;
            return expression;
        } catch (IllegalArgumentException e) {
            expression = null;
            expressionSource = p;
            return null;
        }
    }

    private Pattern glob(String p) {
        if (compiled != null && p.equals(compiledSource)) {
            return compiled;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < p.length(); i++) {
            char c = p.charAt(i);
            switch (c) {
                case '*' -> sb.append(".*");
                case '?' -> sb.append('.');
                default -> sb.append(Pattern.quote(String.valueOf(c)));
            }
        }
        compiled = Pattern.compile("^" + sb + "$", Pattern.CASE_INSENSITIVE);
        compiledSource = p;
        return compiled;
    }

    private Pattern compile(String p) {
        if (compiled != null && p.equals(compiledSource)) {
            return compiled;
        }
        try {
            compiled = Pattern.compile(p, Pattern.CASE_INSENSITIVE);
            compiledSource = p;
            return compiled;
        } catch (PatternSyntaxException e) {
            return null;
        }
    }

    /** 规则是否可用（引用的配置还在、正则没写错）。 */
    public String validate(AppConfig config) {
        if (pattern == null || pattern.isBlank()) {
            return "匹配串为空";
        }
        if (config.profile(profileId) == null) {
            return "引用的配置方案不存在";
        }
        if (matchType == MatchType.URL_REGEX) {
            try {
                Pattern.compile(pattern);
            } catch (PatternSyntaxException e) {
                return "正则语法错误：" + e.getDescription();
            }
        }
        if (matchType == MatchType.CUSTOM) {
            try {
                RuleExpression.compile(pattern);
            } catch (IllegalArgumentException e) {
                return "自定义表达式错误：" + e.getMessage();
            }
        }
        return null;
    }

    public String describe() {
        String dir = onRequest && onResponse ? "请求+响应"
                : onRequest ? "仅请求" : onResponse ? "仅响应" : "未启用方向";
        return matchType.label() + " : " + pattern + "  →  " + dir;
    }

    @Override
    public String toString() {
        return describe();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Rule r && Objects.equals(id, r.id);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id);
    }
}
