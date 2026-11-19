package burp.http;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
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
 * Proxy 的透明加解密，分四步走（这是"历史里看明文、线上跑密文"的关键）：
 *
 * <pre>
 * 客户端 ──密文──► [① 收到请求：解密] ──► Burp 历史/编辑器（明文）
 *                                     └─► [② 发往服务端：加密] ──密文──► 服务端
 * 服务端 ──密文──► [③ 收到响应：解密] ──► Burp 历史（明文）
 *                                     └─► [④ 回写客户端：加密] ──密文──► 客户端
 * </pre>
 *
 * <p>②④ 只在"这段明文确实是本扩展①③解出来的"时才执行（见 {@link HandoffCache}），
 * 所以同域下本来就不加密的页面/接口不会被误加密。</p>
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
                handoff.mark(true, request.url(), result.body);
                Log.debug("[proxy] 请求已解密（历史显示明文）：" + request.url());
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
        if (!enabled() || !service.config().proxyReencryptRequest) {
            // 关闭"放行前重新加密"= 接受服务端收到明文，换取 Proxy 历史显示明文
            return ProxyRequestToBeSentAction.continueWith(request);
        }
        try {
            byte[] body = bytes(request.body());
            if (body.length == 0 || !handoff.contains(true, request.url(), body)) {
                // 不是我们解出来的明文（客户端本来就发的明文）→ 一个字节都不动
                return ProxyRequestToBeSentAction.continueWith(request);
            }
            TransformResult result = service.process(AppConfig.ToolGroup.PROXY,
                    CryptoService.Phase.REQUEST_ENCRYPT, request.method(), request.url(),
                    CryptoHttpHandler.headerLines(request.headers()), body);
            if (result.changed()) {
                Log.debug("[proxy] 请求已还原为密文上线：" + request.url());
                return ProxyRequestToBeSentAction.continueWith(
                        request.withBody(ByteArray.byteArray(result.body)),
                        note(request.annotations(), "BurpCryptCat 已加密"));
            }
        } catch (Exception e) {
            Log.error("Proxy 请求加密异常（已放行当前报文）", e);
        }
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
                Log.debug("[proxy] 响应已解密（历史显示明文）：" + url);
                return ProxyResponseReceivedAction.continueWith(
                        response.withBody(ByteArray.byteArray(result.body)),
                        note(response.annotations(), "BurpCryptCat 已解密"));
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
            if (body.length == 0 || !handoff.contains(false, url, body)) {
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
