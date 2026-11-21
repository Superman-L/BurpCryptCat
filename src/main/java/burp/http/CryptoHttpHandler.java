package burp.http;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.config.AppConfig;
import burp.support.Log;
import burp.transform.CryptoService;
import burp.transform.TransformResult;

/**
 * 全工具 HTTP 处理器（真正"发上线"前的最后一站）。
 *
 * <ul>
 *   <li><b>请求发出前</b>：Body 若是明文 → 加密。
 *       <ul>
 *         <li>Repeater / Intruder / Scanner：让"改完就发"的明文变成密文；</li>
 *         <li><b>Proxy</b>：Proxy 的报文在 {@link CryptoProxyHandler} 收到时已被换成明文，
 *             这一步才加密。放在这里而不是 Proxy 的 ToBeSent，是为了让 Burp 记录的
 *             请求版本停在明文上 —— 请求编辑器的"报文类型"下拉才有
 *             Original request（原始密文）/ Edited request（解密后的明文）可切。</li>
 *       </ul></li>
 *   <li><b>响应收到时</b>：Body 若是密文 → 解密。Repeater / Intruder 的结果面板因此直接显示明文；
 *       Proxy 的响应仍由 {@link CryptoProxyHandler} 处理（那边需要"回写前再加密"）。</li>
 * </ul>
 */
public final class CryptoHttpHandler implements HttpHandler {

    private final CryptoService service;
    private final HandoffCache handoff;

    public CryptoHttpHandler(CryptoService service, HandoffCache handoff) {
        this.service = service;
        this.handoff = handoff;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            ToolType toolType = request.toolSource() == null ? null : request.toolSource().toolType();
            AppConfig.ToolGroup group = ToolGroups.of(toolType);
            if (!service.toolEnabled(group)) {
                return RequestToBeSentAction.continueWith(request);
            }
            byte[] body = bytes(request.body());
            if (body.length == 0) {
                return RequestToBeSentAction.continueWith(request);
            }
            if (group == AppConfig.ToolGroup.PROXY) {
                return proxyRequest(request, body);
            }
            TransformResult result = service.process(group, CryptoService.Phase.REQUEST_ENCRYPT,
                    request.method(), request.url(), headerLines(request.headers()), body);
            if (result.changed()) {
                Log.debug("[http] " + group + " 请求已加密：" + request.url());
                return RequestToBeSentAction.continueWith(request.withBody(ByteArray.byteArray(result.body)));
            }
        } catch (Exception e) {
            Log.error("处理请求时异常（已放行原始报文）", e);
        }
        return RequestToBeSentAction.continueWith(request);
    }

    /**
     * Proxy 请求的加密：收到时 {@link CryptoProxyHandler} 已经把密文换成明文并记了账，
     * 这里把"我们解出来的明文"（含用户在页签里改过的）换回密文再上线。
     */
    private RequestToBeSentAction proxyRequest(HttpRequestToBeSent request, byte[] body) {
        if (!service.config().proxyReencryptRequest
                || !service.config().masterEnabled
                || !service.config().proxyEnabled) {
            return RequestToBeSentAction.continueWith(request);
        }
        boolean ours = handoff.contains(true, request.url(), body)
                || handoff.isMarkedMessage(true, request.messageId());
        if (!ours) {
            // 不是我们解出来的明文（客户端本来就发的明文）→ 一个字节都不动
            return RequestToBeSentAction.continueWith(request);
        }
        if (handoff.isOriginal(true, request.messageId(), body)) {
            // 还是收到时那份原件（用户把报文类型切回 Original 了）→ 绝不能再加密一次
            return RequestToBeSentAction.continueWith(request);
        }
        TransformResult result = service.process(AppConfig.ToolGroup.PROXY,
                CryptoService.Phase.REQUEST_ENCRYPT, request.method(), request.url(),
                headerLines(request.headers()), body);
        if (result.changed()) {
            Log.debug("[http] Proxy 请求已加密（HttpHandler，Burp 里仍是明文）：" + request.url());
            return RequestToBeSentAction.continueWith(request.withBody(ByteArray.byteArray(result.body)));
        }
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            ToolType toolType = response.toolSource() == null ? null : response.toolSource().toolType();
            AppConfig.ToolGroup group = ToolGroups.of(toolType);
            if (group == AppConfig.ToolGroup.PROXY) {
                // Proxy 响应由 CryptoProxyHandler 负责（它还要处理"回写客户端前再加密"）
                return ResponseReceivedAction.continueWith(response);
            }
            if (!service.toolEnabled(group)) {
                return ResponseReceivedAction.continueWith(response);
            }
            byte[] body = bytes(response.body());
            if (body.length == 0) {
                return ResponseReceivedAction.continueWith(response);
            }
            String url = response.initiatingRequest() == null ? "" : response.initiatingRequest().url();
            String method = response.initiatingRequest() == null ? "" : response.initiatingRequest().method();
            TransformResult result = service.process(group, CryptoService.Phase.RESPONSE_DECRYPT,
                    method, url, headerLines(response.headers()), body);
            if (result.changed()) {
                Log.debug("[http] " + group + " 响应已解密：" + url);
                return ResponseReceivedAction.continueWith(response.withBody(ByteArray.byteArray(result.body)));
            }
        } catch (Exception e) {
            Log.error("处理响应时异常（已放行原始报文）", e);
        }
        return ResponseReceivedAction.continueWith(response);
    }

    private static byte[] bytes(ByteArray array) {
        return array == null ? new byte[0] : array.getBytes();
    }

    /** Montoya Header → "Name: value" 列表（给脚本用） */
    public static java.util.List<String> headerLines(java.util.List<burp.api.montoya.http.message.HttpHeader> hs) {
        java.util.List<String> out = new java.util.ArrayList<>();
        if (hs != null) {
            for (burp.api.montoya.http.message.HttpHeader h : hs) {
                out.add(h.name() + ": " + (h.value() == null ? "" : h.value()));
            }
        }
        return out;
    }
}
