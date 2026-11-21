package burp.script;

import java.util.ArrayList;
import java.util.List;

/**
 * 极简 JSON 工具：只服务于"脚本进程通信"这一件事，不引第三方库。
 *
 * <p>只实现我们自己的协议需要的几个函数：拼字符串、取字符串、取布尔、取字符串数组。</p>
 */
public final class Json {

    private Json() {
    }

    /* ==================== 写 ==================== */

    public static String quote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20 || c == 0x7f) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }

    public static String array(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        if (items != null) {
            for (int i = 0; i < items.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(quote(items.get(i)));
            }
        }
        return sb.append(']').toString();
    }

    /* ==================== 读 ==================== */

    /** 取字符串字段；不存在或不是字符串返回 null。 */
    public static String str(String json, String key) {
        int i = findValue(json, key);
        if (i < 0 || i >= json.length()) {
            return null;
        }
        if (json.charAt(i) != '"') {
            return null;
        }
        return readString(json, i);
    }

    /** 取布尔字段 */
    public static boolean bool(String json, String key, boolean def) {
        int i = findValue(json, key);
        if (i < 0) {
            return def;
        }
        if (json.startsWith("true", i)) {
            return true;
        }
        if (json.startsWith("false", i)) {
            return false;
        }
        return def;
    }

    /** 取字符串数组字段 */
    public static List<String> strArray(String json, String key) {
        List<String> out = new ArrayList<>();
        int i = findValue(json, key);
        if (i < 0 || i >= json.length() || json.charAt(i) != '[') {
            return out;
        }
        int j = i + 1;
        while (j < json.length()) {
            char c = json.charAt(j);
            if (c == '"') {
                String s = readString(json, j);
                if (s == null) {
                    break;
                }
                out.add(s);
                j = skipString(json, j);
                continue;
            }
            if (c == ']') {
                break;
            }
            j++;
        }
        return out;
    }

    /** 找到 `"key"` 之后、冒号之后的第一个非空白字符位置 */
    private static int findValue(String json, String key) {
        if (json == null || key == null) {
            return -1;
        }
        String quoted = "\"" + key + "\"";
        int from = 0;
        while (true) {
            int idx = json.indexOf(quoted, from);
            if (idx < 0) {
                return -1;
            }
            int i = idx + quoted.length();
            while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
                i++;
            }
            if (i < json.length() && json.charAt(i) == ':') {
                i++;
                while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
                    i++;
                }
                return i;
            }
            from = idx + quoted.length();
        }
    }

    /** 从 `"` 开始读一个 JSON 字符串（处理转义），返回解码后的值 */
    private static String readString(String json, int start) {
        StringBuilder sb = new StringBuilder();
        for (int i = start + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') {
                return sb.toString();
            }
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            if (++i >= json.length()) {
                break;
            }
            char n = json.charAt(i);
            switch (n) {
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'u' -> {
                    if (i + 4 < json.length()) {
                        try {
                            sb.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16));
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

    /** 跳过从 start 开始的字符串，返回收尾引号之后的位置 */
    private static int skipString(String json, int start) {
        for (int i = start + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\') {
                i++;
                continue;
            }
            if (c == '"') {
                return i + 1;
            }
        }
        return json.length();
    }
}
