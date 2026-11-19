package burp.transform;

/**
 * 极简 JSON 字段读写，只处理最常见的 {@code {"data":"...."}} 这种"顶层（或任意层级）
 * 字符串字段"形态。
 *
 * <p>为什么不引入 JSON 库：本插件坚持零第三方依赖（避免与 Burp 内置库冲突）。
 * 对"取一个字符串字段、替换它的值"这个场景，手写扫描器足够且不会破坏原有格式
 * （缩进、字段顺序、其它字段都原样保留）——这是直接用 JSON 库序列化做不到的。</p>
 */
public final class JsonField {

    private JsonField() {
    }

    /** 字段值在原文中的区间（不含两侧引号）；找不到返回 null。 */
    public static int[] find(String json, String field) {
        if (json == null || field == null || field.isEmpty()) {
            return null;
        }
        String quoted = "\"" + field + "\"";
        int from = 0;
        while (true) {
            int idx = json.indexOf(quoted, from);
            if (idx < 0) {
                return null;
            }
            int i = idx + quoted.length();
            i = skipWs(json, i);
            if (i >= json.length() || json.charAt(i) != ':') {
                from = idx + quoted.length();
                continue;
            }
            i = skipWs(json, i + 1);
            if (i >= json.length() || json.charAt(i) != '"') {
                // 不是字符串字段（数字/对象/数组），跳过
                from = idx + quoted.length();
                continue;
            }
            int start = i + 1;
            int j = start;
            while (j < json.length()) {
                char c = json.charAt(j);
                if (c == '\\') {
                    j += 2;
                    continue;
                }
                if (c == '"') {
                    return new int[]{start, j};
                }
                j++;
            }
            return null;
        }
    }

    public static String get(String json, String field) {
        int[] r = find(json, field);
        if (r == null) {
            return null;
        }
        return unescape(json.substring(r[0], r[1]));
    }

    /** 替换字段值（自动做 JSON 字符串转义）；字段不存在时返回 null。 */
    public static String set(String json, String field, String value) {
        int[] r = find(json, field);
        if (r == null) {
            return null;
        }
        return json.substring(0, r[0]) + escape(value) + json.substring(r[1]);
    }

    /** 判断文本是否"看起来是 JSON 对象/数组"（用于容错，不要求严格解析）。 */
    public static boolean looksLikeJson(String text) {
        if (text == null) {
            return false;
        }
        String t = text.trim();
        return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
    }

    private static int skipWs(String s, int i) {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
            i++;
        }
        return i;
    }

    static String escape(String v) {
        StringBuilder sb = new StringBuilder(v.length() + 8);
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    static String unescape(String v) {
        if (v.indexOf('\\') < 0) {
            return v;
        }
        StringBuilder sb = new StringBuilder(v.length());
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c != '\\' || i + 1 >= v.length()) {
                sb.append(c);
                continue;
            }
            char n = v.charAt(++i);
            switch (n) {
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'u' -> {
                    if (i + 4 < v.length()) {
                        try {
                            sb.append((char) Integer.parseInt(v.substring(i + 1, i + 5), 16));
                            i += 4;
                        } catch (NumberFormatException e) {
                            sb.append("\\u");
                        }
                    } else {
                        sb.append("\\u");
                    }
                }
                default -> sb.append(n);
            }
        }
        return sb.toString();
    }
}
