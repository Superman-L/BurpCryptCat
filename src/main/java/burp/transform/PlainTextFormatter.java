package burp.transform;

/**
 * 纯文本层面的小工具：从原始报文里取 Body、判断/美化 JSON、压缩空白。
 *
 * <p>刻意放在 transform 层（不依赖 Burp API），这样单元测试可以在没有 Burp 的
 * 环境里直接跑。</p>
 */
public final class PlainTextFormatter {

    private PlainTextFormatter() {
    }

    /** 取报文里的 Body 部分（第一个空行之后）。 */
    public static String bodyOf(String rawMessage) {
        if (rawMessage == null) {
            return "";
        }
        int crlf = rawMessage.indexOf("\r\n\r\n");
        if (crlf >= 0) {
            return rawMessage.substring(crlf + 4);
        }
        int lf = rawMessage.indexOf("\n\n");
        if (lf >= 0) {
            return rawMessage.substring(lf + 2);
        }
        return "";
    }

    public static boolean looksLikeJson(String text) {
        if (text == null) {
            return false;
        }
        String t = text.trim();
        return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
    }

    /**
     * 极简 JSON 缩进美化（不解析语义，只重排空白）。
     *
     * <p>安全性：美化后去掉所有空白必须与原文逐字节一致，否则说明输入畸形
     * （引号/括号不配对），直接返回原文——绝不把内容改坏。</p>
     */
    public static String beautifyJson(String text) {
        if (!looksLikeJson(text)) {
            return text;
        }
        String t = text.trim();
        StringBuilder out = new StringBuilder(t.length() + 64);
        int indent = 0;
        boolean inStr = false;
        boolean esc = false;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (inStr) {
                out.append(c);
                if (esc) {
                    esc = false;
                } else if (c == '\\') {
                    esc = true;
                } else if (c == '"') {
                    inStr = false;
                }
                continue;
            }
            switch (c) {
                case '"' -> {
                    inStr = true;
                    out.append(c);
                }
                case '{', '[' -> {
                    out.append(c);
                    if (!nextIsClosing(t, i)) {
                        indent++;
                        newline(out, indent);
                    }
                }
                case '}', ']' -> {
                    if (!prevIsOpening(t, i)) {
                        indent = Math.max(0, indent - 1);
                        newline(out, indent);
                    }
                    out.append(c);
                }
                case ',' -> {
                    out.append(c);
                    newline(out, indent);
                }
                case ':' -> out.append(": ");
                case ' ', '\t', '\r', '\n' -> {
                    // 丢弃原有空白
                }
                default -> out.append(c);
            }
        }
        String result = out.toString();
        return squeeze(result).equals(squeeze(t)) ? result : text;
    }

    private static boolean nextIsClosing(String t, int i) {
        for (int j = i + 1; j < t.length(); j++) {
            char c = t.charAt(j);
            if (Character.isWhitespace(c)) {
                continue;
            }
            return c == '}' || c == ']';
        }
        return false;
    }

    private static boolean prevIsOpening(String t, int i) {
        for (int j = i - 1; j >= 0; j--) {
            char c = t.charAt(j);
            if (Character.isWhitespace(c)) {
                continue;
            }
            return c == '{' || c == '[';
        }
        return false;
    }

    private static void newline(StringBuilder sb, int indent) {
        sb.append('\n');
        for (int i = 0; i < indent; i++) {
            sb.append("  ");
        }
    }

    /** 去掉所有空白字符。 */
    public static String squeeze(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!Character.isWhitespace(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
