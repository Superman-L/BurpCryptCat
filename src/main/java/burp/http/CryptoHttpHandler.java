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
 * 全工具 HTTP 处理器：负责 Repeater / Intruder / Scanner 等工具里的透明加解密。
 *
 * <ul>
 *   <li><b>请求发出前</b>：Body 若是明文 → 加密。这一步让 Repeater 里"改完就发"、
 *       Intruder 里"每个变异包"都自动变成密文，测试人员始终对着明文操作。</li>
 *   <li><b>响应收到时</b>：Body 若是密文 → 解密。Repeater / Intruder 的结果面板
 *       因此直接显示明文。</li>
 * </ul>
 *
 * <p>故意<b>跳过 Proxy</b>：Proxy 需要"历史里是明文、线上是密文"的两段式处理，
 * 由 {@link CryptoProxyHandler} 专门负责，避免两套处理器互相打架。</p>
 */
public final class CryptoHttpHandler implements HttpHandler {

    private final CryptoService service;

    public CryptoHttpHandler(CryptoService service) {
        this.service = service;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            ToolType toolType = request.toolSource() == null ? null : request.toolSource().toolType();
            AppConfig.ToolGroup group = ToolGroups.of(toolType);
            if (group == AppConfig.ToolGroup.PROXY) {
                return RequestToBeSentAction.continueWith(request);
            }
            if (!service.toolEnabled(group)) {
                return RequestToBeSentAction.continueWith(request);
            }
            byte[] body = bytes(request.body());
            if (body.length == 0) {
                return RequestToBeSentAction.continueWith(request);
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

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            ToolType toolType = response.toolSource() == null ? null : response.toolSource().toolType();
            AppConfig.ToolGroup group = ToolGroups.of(toolType);
            if (group == AppConfig.ToolGroup.PROXY) {
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
