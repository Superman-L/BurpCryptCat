package burp.ui;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.transform.PlainTextFormatter;

import java.nio.charset.StandardCharsets;

/**
 * 把「解密后的完整报文」渲染成可读文本，以及把用户编辑后的文本还原成报文。
 *
 * <p>需求要求"解密时保留请求头、保留完整请求包"，所以展示的是整包：
 * 请求行 + 所有 Header + 空行 + 解密后的 Body，而不是只给一段 Body。
 * 另外做两处美化：JSON 自动缩进、Content-Length 按解密后的 Body 重算
 * （否则头里的长度和看到的明文对不上，容易误导）。</p>
 */
public final class MessagePrinter {

    private MessagePrinter() {
    }

    /* ==================== 渲染 ==================== */

    public static String request(HttpRequest request, String body, boolean beautify) {
        StringBuilder sb = new StringBuilder(256 + body.length());
        String version = request.httpVersion();
        if (version == null || version.isBlank()) {
            version = "HTTP/1.1";
        }
        sb.append(request.method()).append(' ').append(request.path()).append(' ')
                .append(version).append("\r\n");
        appendHeaders(sb, request.headers());
        appendBody(sb, body, beautify);
        return sb.toString();
    }

    public static String response(HttpResponse response, String body, boolean beautify) {
        StringBuilder sb = new StringBuilder(256 + body.length());
        String version = response.httpVersion();
        if (version == null || version.isBlank()) {
            version = "HTTP/1.1";
        }
        sb.append(version).append(' ').append(response.statusCode()).append(' ')
                .append(response.reasonPhrase()).append("\r\n");
        appendHeaders(sb, response.headers());
        appendBody(sb, body, beautify);
        return sb.toString();
    }

    private static void appendHeaders(StringBuilder sb, Iterable<HttpHeader> headers) {
        for (HttpHeader h : headers) {
            String name = h.name();
            if (name == null || name.isBlank()) {
                continue;
            }
            // HTTP/2 伪头（:method/:path/:authority…）在文本里已由请求行表达
            if (name.startsWith(":")) {
                continue;
            }
            // 长度类头统一在 Body 前重新生成
            if (name.equalsIgnoreCase("Content-Length") || name.equalsIgnoreCase("Transfer-Encoding")) {
                continue;
            }
            sb.append(name).append(": ").append(h.value() == null ? "" : h.value()).append("\r\n");
        }
    }

    private static void appendBody(StringBuilder sb, String body, boolean beautify) {
        String text = body == null ? "" : body;
        sb.append("Content-Length: ").append(text.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
        sb.append("\r\n");
        sb.append(beautify && PlainTextFormatter.looksLikeJson(text)
                ? PlainTextFormatter.beautifyJson(text) : text);
    }

    /* ==================== 还原 ==================== */

    /**
     * 用户在「BurpCryptCat明文」页签里改完之后，把整段文本还原成报文。
     *
     * <p>优先按整包解析（这样连 Header 的改动都能生效）；文本坏掉时退化成"只取 Body"，
     * 保证不会因为展示层的问题把报文搞坏。</p>
     */
    public static HttpRequest parseRequest(HttpRequest original, String edited) {
        try {
            HttpRequest parsed = HttpRequest.httpRequest(original.httpService(),
                    ByteArray.byteArray(edited));
            if (parsed.method() != null && !parsed.method().isBlank()) {
                return parsed;
            }
        } catch (Exception ignore) {
            // 落到下面的兜底
        }
        return original.withBody(ByteArray.byteArray(PlainTextFormatter.bodyOf(edited)));
    }

    public static HttpResponse parseResponse(HttpResponse original, String edited) {
        try {
            HttpResponse parsed = HttpResponse.httpResponse(ByteArray.byteArray(edited));
            if (parsed.statusCode() > 0) {
                return parsed;
            }
        } catch (Exception ignore) {
            // 落到下面的兜底
        }
        return original.withBody(ByteArray.byteArray(PlainTextFormatter.bodyOf(edited)));
    }
}
