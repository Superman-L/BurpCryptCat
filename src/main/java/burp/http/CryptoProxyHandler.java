package burp.http;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.config.AppConfig;
import burp.support.Log;
import burp.transform.CryptoService;
import burp.transform.TransformResult;

/**
 * Proxy 的透明加解密，四步走。
 *
 * <pre>
 * 客户端 ──密文──► [① 收到请求：解密] ──► Burp 里两个版本：
 *                                          · Original request = 原始请求（密文，未经修改）
 *                                          · Edited request   = 解密后的明文（含用户在页签里的改动）
 *                                     └─► Proxy 放行阶段不改报文（Burp 里保持明文）
 *                                     └─► HttpHandler.handleHttpRequestToBeSent：加密 ──密文──► 服务端
 * 服务端 ──密文──► [③ 收到响应：解密] ──► Burp 里是明文
 *                                     └─► [④ 回写客户端前：加密] ──密文──► 客户端
 * </pre>
 *
 * <p><b>请求的「放行前加密」为什么挪到 HttpHandler</b>：Burp 会把 Proxy 放行阶段返回的报文
 * 当作这条请求的 Edited 版本。如果在这里加密，Burp 里请求又变回密文，
 * 请求编辑器的报文类型下拉（Original request / Edited request）就没有可切的第二项了。
 * 放到 HttpHandler（真正上线前的最后一站）后：Burp 里留明文、下拉可切，线上仍然是密文。</p>
 *
 * <p><b>响应侧保持"不动报文"</b>（默认）：收到响应时只做试探性解密用于页签/流水，
 * 报文原样交给 Burp —— 这样 Burp 里只有 Original response（服务端的原始响应），
 * 不会出现一个"不是明文"的 Edited response；客户端收到的也是原始字节。
 * 把「响应回写前重新加密」关掉，才会把响应换成明文（Burp/历史显示明文，客户端也收到明文）。</p>
 *
 * <p>加密时只在"这段明文确实与本扩展有关"时才动手（见 {@link HandoffCache}）：内容命中
 * （原样放行）或 messageId 命中（用户在页签里改过明文）；如果 Body 还是收到时那份原件
 * （用户把报文类型切回 Original 后直接放行），一律跳过，避免二次加密 —— 脚本方式没有幂等保证。</p>
 */
public final class CryptoProxyHandler implements ProxyRequestHandler, ProxyResponseHandler {

    private final CryptoService service;
    private final HandoffCache handoff;

    public CryptoProxyHandler(CryptoService service, HandoffCache handoff) {
        this.service = service;
        this.handoff = handoff;
    }

    private boolean enabled() {
        AppConfig cfg = service.config();
        return cfg.masterEnabled && cfg.proxyEnabled
                && cfg.toolEnabled(AppConfig.ToolGroup.PROXY);
    }

    /* ==================== 请求 ==================== */

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        if (!enabled()) {
            return ProxyRequestReceivedAction.continueWith(request);
        }
        try {
            byte[] body = bytes(request.body());
            if (body.length == 0) {
                return ProxyRequestReceivedAction.continueWith(request);
            }
            TransformResult result = service.process(AppConfig.ToolGroup.PROXY,
                    CryptoService.Phase.REQUEST_DECRYPT, request.method(), request.url(),
                    CryptoHttpHandler.headerLines(request.headers()), body);
            if (result.changed()) {
                // 记账：解出来的明文（放行时要加密）+ 收到时的原件（判断用户改没改）
                handoff.mark(true, request.url(), result.body);
                handoff.markMessage(true, request.messageId());
                handoff.markOriginal(true, request.messageId(), body);
                Log.debug("[proxy] 请求已解密（Burp 记为 auto-modified，Original 仍是原始密文）："
                        + request.url());
                // 换成明文交给 Burp：Original request / Auto-modified 两个版本都在，
                // 报文类型下拉才有得切；「BurpCryptCat明文」页签看的也是这一份
                return ProxyRequestReceivedAction.continueWith(
                        request.withBody(ByteArray.byteArray(result.body)),
                        note(request.annotations(), "BurpCryptCat 已解密"));
            }
        } catch (Exception e) {
            Log.error("Proxy 请求解密异常（已放行原始报文）", e);
        }
        return ProxyRequestReceivedAction.continueWith(request);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        // 请求加密**故意不在这里做**：Burp 记录"放行时的报文"作为请求的 Edited 版本，
        // 这里一改就又变回密文，请求侧的报文类型下拉也就没得切了。
        // 真正的加密放在 HttpHandler（{@link CryptoHttpHandler#handleHttpRequestToBeSent}），
        // 那是真正上线前的最后一站：Burp 里留明文（Original 密文 / Edited 明文），
        // 线上仍然是密文。
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    /* ==================== 响应 ==================== */

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        if (!enabled()) {
            return ProxyResponseReceivedAction.continueWith(response);
        }
        try {
            String url = urlOf(response);
            byte[] body = bytes(response.body());
            if (body.length == 0) {
                return ProxyResponseReceivedAction.continueWith(response);
            }
            TransformResult result = service.process(AppConfig.ToolGroup.PROXY,
                    CryptoService.Phase.RESPONSE_DECRYPT, methodOf(response), url,
                    CryptoHttpHandler.headerLines(response.headers()), body);
            if (result.changed()) {
                handoff.mark(false, url, result.body);
                handoff.markMessage(false, response.messageId());
                handoff.markOriginal(false, response.messageId(), body);
                if (!service.config().proxyReencryptResponse) {
                    // 关掉「回写前重新加密」= 接受客户端收到明文 → 直接把明文交给 Burp
                    Log.debug("[proxy] 响应已解密（历史显示明文）：" + url);
                    return ProxyResponseReceivedAction.continueWith(
                            response.withBody(ByteArray.byteArray(result.body)),
                            note(response.annotations(), "BurpCryptCat 已解密"));
                }
                // 默认：响应保持服务端返回的原样（Original response = 原始密文），
                // 不在 Burp 里造一个"不是明文"的 Edited response；明文只在页签/流水里看
                Log.debug("[proxy] 响应明文见「BurpCryptCat明文（响应）」页签：" + url);
                return ProxyResponseReceivedAction.continueWith(
                        response, note(response.annotations(), "BurpCryptCat 明文见页签"));
            }
        } catch (Exception e) {
            Log.error("Proxy 响应解密异常（已放行原始报文）", e);
        }
        return ProxyResponseReceivedAction.continueWith(response);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        if (!enabled() || !service.config().proxyReencryptResponse) {
            // 关闭"回写前重新加密"= 接受客户端收到明文，换取 Proxy 历史显示明文
            return ProxyResponseToBeSentAction.continueWith(response);
        }
        try {
            String url = urlOf(response);
            byte[] body = bytes(response.body());
            boolean ours = handoff.contains(false, url, body)
                    || handoff.isMarkedMessage(false, response.messageId());
            if (body.length == 0 || !ours) {
                return ProxyResponseToBeSentAction.continueWith(response);
            }
            if (handoff.isOriginal(false, response.messageId(), body)) {
                // 用户把报文类型切回 Original response 后直接放行：还是原始密文
                return ProxyResponseToBeSentAction.continueWith(response);
            }
            TransformResult result = service.process(AppConfig.ToolGroup.PROXY,
                    CryptoService.Phase.RESPONSE_ENCRYPT, methodOf(response), url,
                    CryptoHttpHandler.headerLines(response.headers()), body);
            if (result.changed()) {
                Log.debug("[proxy] 响应已还原为密文回写客户端：" + url);
                return ProxyResponseToBeSentAction.continueWith(
                        response.withBody(ByteArray.byteArray(result.body)),
                        note(response.annotations(), "BurpCryptCat 已加密"));
            }
        } catch (Exception e) {
            Log.error("Proxy 响应加密异常（已放行当前报文）", e);
        }
        return ProxyResponseToBeSentAction.continueWith(response);
    }

    /* ==================== 工具 ==================== */

    /** 保留用户已有备注，只在为空时补一条，方便在 Proxy 历史里认出被处理过的报文。 */
    private static Annotations note(Annotations current, String text) {
        if (current != null && current.hasNotes()) {
            return current;
        }
        return current == null ? Annotations.annotations(text) : current.withNotes(text);
    }

    private static String urlOf(InterceptedResponse response) {
        try {
            HttpRequest req = response.initiatingRequest();
            if (req != null) {
                String url = req.url();
                if (url != null && !url.isEmpty()) {
                    return url;
                }
            }
        } catch (Exception ignore) {
            // 某些场景（如 HTTP/2 推送）拿不到发起请求，退化为"不按 URL 精确记账"
        }
        return "";
    }

    private static String methodOf(InterceptedResponse response) {
        try {
            HttpRequest req = response.initiatingRequest();
            return req == null ? "" : req.method();
        } catch (Exception e) {
            return "";
        }
    }

    private static byte[] bytes(ByteArray array) {
        return array == null ? new byte[0] : array.getBytes();
    }
}
