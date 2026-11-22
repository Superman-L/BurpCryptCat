package burp.config;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 「自定义」生效规则的表达式解析与求值。
 *
 * <p>用一个小 DSL 描述复杂条件，不需要写脚本，例子：</p>
 * <pre>
 *   host == "api.example.com" &amp;&amp; path == "/api/login"
 *   host == "*.example.com" &amp;&amp; path startsWith "/gw/"
 *   url ~= "/login" &amp;&amp; query contains "from=mini"
 *   host == "wap.example.cn" &amp;&amp; (path == "/a" || path == "/b")
 *   host like "*.10086.cn" &amp;&amp; !(path contains "/public/")
 * </pre>
 *
 * <p>变量（大小写不敏感）：</p>
 * <ul>
 *   <li>{@code host} —— 主机名，不含端口（如 {@code api.example.com}）</li>
 *   <li>{@code path} —— 路径，不含 query（如 {@code /api/login}）</li>
 *   <li>{@code query} —— 原始 query（不含 {@code ?}，没有则为空串）</li>
 *   <li>{@code url} —— 完整 URL（scheme://host:port/path?query）</li>
 * </ul>
 *
 * <p>运算符：{@code ==}、{@code !=}、{@code ~=}（正则，忽略大小写，find 语义）、
 * {@code contains}、{@code startsWith}、{@code endsWith}、{@code like}（glob，支持 {@code *} 和 {@code ?}，
 * 忽略大小写）；逻辑：{@code &&}、{@code ||}、{@code !}、括号。
 * 字符串用双引号或单引号；比较默认区分大小写（{@code ~=} / {@code like} 除外）。</p>
 *
 * <p>解析失败会抛 {@link IllegalArgumentException}（带位置和原因），规则保存时会直接报错。</p>
 */
public final class RuleExpression {

    private final String source;
    private final Node root;

    private RuleExpression(String source, Node root) {
        this.source = source;
        this.root = root;
    }

    /** 编译表达式；语法错误抛 IllegalArgumentException。 */
    public static RuleExpression compile(String source) {
        if (source == null || source.isBlank()) {
            throw new IllegalArgumentException("表达式为空");
        }
        Parser parser = new Parser(source);
        Node root = parser.parseAll();
        return new RuleExpression(source, root);
    }

    /** 求值。host 不含端口，url 为完整 URL。 */
    public boolean test(String host, String url) {
        return root.test(new Env(host, url));
    }

    public String source() {
        return source;
    }

    @Override
    public String toString() {
        return source;
    }

    /* ==================== 求值环境 ==================== */

    private record Env(String host, String path, String query, String url) {
        Env(String host, String url) {
            this(host == null ? "" : host, pathOf(url), queryOf(url), url == null ? "" : url);
        }

        String var(String name) {
            return switch (name.toLowerCase()) {
                case "host" -> host;
                case "path" -> path;
                case "query" -> query;
                case "url" -> url;
                default -> "";
            };
        }

        static String pathOf(String url) {
            if (url == null) {
                return "";
            }
            int scheme = url.indexOf("://");
            int start = scheme < 0 ? 0 : scheme + 3;
            int slash = url.indexOf('/', start);
            if (slash < 0) {
                return "/";
            }
            int q = url.indexOf('?', slash);
            return q < 0 ? url.substring(slash) : url.substring(slash, q);
        }

        static String queryOf(String url) {
            if (url == null) {
                return "";
            }
            int q = url.indexOf('?');
            if (q < 0) {
                return "";
            }
            int hash = url.indexOf('#', q);
            return hash < 0 ? url.substring(q + 1) : url.substring(q + 1, hash);
        }
    }

    /* ==================== AST ==================== */

    private interface Node {
        boolean test(Env env);
    }

    private record And(Node left, Node right) implements Node {
        public boolean test(Env env) {
            return left.test(env) && right.test(env);
        }
    }

    private record Or(Node left, Node right) implements Node {
        public boolean test(Env env) {
            return left.test(env) || right.test(env);
        }
    }

    private record Not(Node inner) implements Node {
        public boolean test(Env env) {
            return !inner.test(env);
        }
    }

    /** 单个操作数：变量或字面量 */
    private record Operand(String name, boolean literal) {
        String value(Env env) {
            return literal ? name : env.var(name);
        }
    }

    private record Truthy(Operand operand) implements Node {
        public boolean test(Env env) {
            String v = operand.value(env);
            return !v.isEmpty() && !"false".equalsIgnoreCase(v);
        }
    }

    private record Compare(Operand left, String op, Operand right, Pattern regex, Pattern glob) implements Node {
        public boolean test(Env env) {
            String l = left.value(env);
            String r = right.value(env);
            return switch (op) {
                case "==" -> l.equals(r);
                case "!=" -> !l.equals(r);
                case "~=" -> regexOrCompile(r).matcher(l).find();
                case "contains" -> l.contains(r);
                case "startsWith" -> l.startsWith(r);
                case "endsWith" -> l.endsWith(r);
                case "like" -> globOrCompile(r).matcher(l).matches();
                default -> false;
            };
        }

        private Pattern regexOrCompile(String r) {
            if (regex != null) {
                return regex;
            }
            return Pattern.compile(r, Pattern.CASE_INSENSITIVE);
        }

        private Pattern globOrCompile(String r) {
            if (glob != null) {
                return glob;
            }
            return toGlob(r);
        }
    }

    /* ==================== 解析 ==================== */

    private static final class Parser {
        private final String src;
        private int pos;

        Parser(String src) {
            this.src = src;
        }

        Node parseAll() {
            Node n = parseOr();
            skipWs();
            if (pos < src.length()) {
                throw error("多余的字符 '" + src.charAt(pos) + "'");
            }
            return n;
        }

        private Node parseOr() {
            Node left = parseAnd();
            while (accept("||")) {
                left = new Or(left, parseAnd());
            }
            return left;
        }

        private Node parseAnd() {
            Node left = parseUnary();
            while (accept("&&")) {
                left = new And(left, parseUnary());
            }
            return left;
        }

        private Node parseUnary() {
            skipWs();
            if (accept("!")) {
                return new Not(parseUnary());
            }
            if (accept("(")) {
                Node inner = parseOr();
                if (!accept(")")) {
                    throw error("缺少右括号 ')'");
                }
                return inner;
            }
            return parseComparison();
        }

        private Node parseComparison() {
            Operand left = parseOperand(true);
            skipWs();
            String op = matchOperator();
            if (op == null) {
                return new Truthy(left);
            }
            Operand right = parseOperand(false);
            Pattern regex = null;
            Pattern glob = null;
            String r = right.value(new Env("", ""));
            if (right.literal()) {
                if ("~=".equals(op)) {
                    regex = compileRegex(r);
                } else if ("like".equals(op)) {
                    glob = toGlob(r);
                }
            }
            return new Compare(left, op, right, regex, glob);
        }

        private Operand parseOperand(boolean mustBeVariable) {
            skipWs();
            if (pos >= src.length()) {
                throw error("缺少操作数");
            }
            char c = src.charAt(pos);
            if (c == '"' || c == '\'') {
                return new Operand(readQuoted(c), true);
            }
            String word = readWord();
            if (word.equalsIgnoreCase("true") || word.equalsIgnoreCase("false")) {
                return new Operand(word.toLowerCase(), true);
            }
            if (mustBeVariable) {
                String lower = word.toLowerCase();
                if (!lower.equals("host") && !lower.equals("path") && !lower.equals("query")
                        && !lower.equals("url")) {
                    throw error("未知变量 '" + word + "'（可用：host / path / query / url）");
                }
                return new Operand(lower, false);
            }
            return new Operand(word, true);
        }

        private String readQuoted(char quote) {
            pos++;                                   // 跳过开引号
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == quote) {
                    return sb.toString();
                }
                if (c == '\\' && pos < src.length()) {
                    char n = src.charAt(pos++);
                    switch (n) {
                        case 'n' -> sb.append('\n');
                        case 't' -> sb.append('\t');
                        case 'r' -> sb.append('\r');
                        default -> sb.append(n);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw error("字符串没有闭合");
        }

        private String readWord() {
            int start = pos;
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (Character.isWhitespace(c) || c == '(' || c == ')' || c == '!' || c == '='
                        || c == '~' || c == '&' || c == '|') {
                    break;
                }
                pos++;
            }
            if (pos == start) {
                throw error("缺少操作数");
            }
            return src.substring(start, pos);
        }

        private String matchOperator() {
            skipWs();
            if (accept("==")) {
                return "==";
            }
            if (accept("!=")) {
                return "!=";
            }
            if (accept("~=")) {
                return "~=";
            }
            for (String kw : new String[]{"contains", "startsWith", "endsWith", "like"}) {
                if (acceptWord(kw)) {
                    return kw;
                }
            }
            return null;
        }

        private boolean accept(String token) {
            skipWs();
            if (src.startsWith(token, pos)) {
                // 避免把 "==" 的前缀 "=" 之类误判；这里只处理显式 token，足够
                pos += token.length();
                return true;
            }
            return false;
        }

        private boolean acceptWord(String word) {
            skipWs();
            if (!src.regionMatches(true, pos, word, 0, word.length())) {
                return false;
            }
            int end = pos + word.length();
            if (end < src.length()) {
                char c = src.charAt(end);
                if (Character.isLetterOrDigit(c) || c == '_') {
                    return false;
                }
            }
            pos = end;
            return true;
        }

        private void skipWs() {
            while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) {
                pos++;
            }
        }

        private IllegalArgumentException error(String why) {
            return new IllegalArgumentException("表达式第 " + (pos + 1) + " 个字符附近：" + why);
        }
    }

    /* ==================== 工具 ==================== */

    private static Pattern compileRegex(String regex) {
        try {
            return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("正则语法错误：" + e.getDescription());
        }
    }

    private static Pattern toGlob(String glob) {
        StringBuilder sb = new StringBuilder("^");
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            switch (c) {
                case '*' -> sb.append(".*");
                case '?' -> sb.append('.');
                default -> sb.append(Pattern.quote(String.valueOf(c)));
            }
        }
        sb.append('$');
        return Pattern.compile(sb.toString(), Pattern.CASE_INSENSITIVE);
    }
}
