package burp.script;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 一次脚本调用的上下文（会以 JS 对象的形式传给脚本，或作为外部命令的环境变量/标准输入）。
 */
public final class ScriptCall {

    public final ScriptStage stage;
    public final String url;
    public final String method;
    public final boolean isRequest;
    /** 报文的全部 Header（"Name: value" 形式） */
    public final List<String> headers;
    /** Body 字节（原样） */
    public final byte[] body;
    /** 按哪个字符集把 body 解释成文本 */
    public final Charset charset;
    /** 方案名，便于脚本里区分 */
    public final String profileName;

    public ScriptCall(ScriptStage stage, String url, String method, boolean isRequest,
                      List<String> headers, byte[] body, Charset charset, String profileName) {
        this.stage = stage;
        this.url = url == null ? "" : url;
        this.method = method == null ? "" : method;
        this.isRequest = isRequest;
        this.headers = headers == null ? Collections.emptyList() : new ArrayList<>(headers);
        this.body = body == null ? new byte[0] : body;
        this.charset = charset == null ? Charset.forName("UTF-8") : charset;
        this.profileName = profileName == null ? "" : profileName;
    }

    public String bodyText() {
        return new String(body, charset);
    }

    /** 取某个 Header 的值（大小写不敏感）。 */
    public String header(String name) {
        if (name == null) {
            return null;
        }
        for (String h : headers) {
            int i = h.indexOf(':');
            if (i > 0 && h.substring(0, i).trim().equalsIgnoreCase(name)) {
                return h.substring(i + 1).trim();
            }
        }
        return null;
    }
}
