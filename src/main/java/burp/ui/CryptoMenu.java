package burp.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.config.Profile;
import burp.crypto.Codec;
import burp.http.CryptoHttpHandler;
import burp.script.ScriptStage;
import burp.support.Log;
import burp.transform.MessageTransform;
import burp.transform.TargetResolver;
import burp.transform.TransformResult;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * 右键菜单：把"透明加解密"补到 Burp 没给出钩子的地方。
 *
 * <p>为什么需要它：Proxy 历史保存的就是最终上线报文（Burp 的机制），所以默认模式下
 * 历史里是密文。测试人员的习惯是"看到明文 → 改 → 发"，于是这里提供了：</p>
 * <ul>
 *   <li><b>解密后发送到 Repeater</b>：新开的 Repeater 页签里直接是明文，改完点 Send，
 *       插件自动加密；响应自动解密显示。</li>
 *   <li><b>解密后发送到 Intruder</b>：同上，Payload 直接对着明文插。</li>
 *   <li><b>查看明文</b>：不改任何东西，只弹窗显示解出来的请求/响应 Body。</li>
 *   <li><b>在当前编辑器里解密</b>：把编辑器内容就地换成明文（仅影响这一份报文）。</li>
 * </ul>
 */
public final class CryptoMenu implements ContextMenuItemsProvider {

    private final UiContext ctx;

    public CryptoMenu(UiContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        List<HttpRequestResponse> messages = event.selectedRequestResponses();
        if (messages == null || messages.isEmpty()) {
            return items;
        }
        List<HttpRequestResponse> usable = new ArrayList<>();
        for (HttpRequestResponse rr : messages) {
            if (rr != null && rr.request() != null && profile(rr) != null) {
                usable.add(rr);
            }
        }
        if (usable.isEmpty()) {
            return items;
        }

        JMenuItem toRepeater = new JMenuItem("BurpCryptCat：解密后发送到 Repeater");
        toRepeater.addActionListener(e -> sendToRepeater(usable));
        items.add(toRepeater);

        JMenuItem toIntruder = new JMenuItem("BurpCryptCat：解密后发送到 Intruder");
        toIntruder.addActionListener(e -> sendToIntruder(usable));
        items.add(toIntruder);

        JMenuItem copyReq = new JMenuItem("BurpCryptCat：复制明文请求（完整报文）");
        copyReq.addActionListener(e -> copyPlain(usable.get(0), true, false));
        items.add(copyReq);

        JMenuItem copyAll = new JMenuItem("BurpCryptCat：复制明文请求+响应（完整报文）");
        copyAll.addActionListener(e -> copyPlain(usable.get(0), true, true));
        items.add(copyAll);

        JMenuItem view = new JMenuItem("BurpCryptCat：查看明文");
        view.addActionListener(e -> showPlaintext(usable.get(0)));
        items.add(view);

        event.messageEditorRequestResponse().ifPresent(editor -> {
            JMenuItem inplace = new JMenuItem("BurpCryptCat：在本编辑器中解密");
            inplace.addActionListener(e -> decryptInEditor(editor));
            items.add(inplace);
        });
        return items;
    }

    /* ==================== 动作 ==================== */

    private void sendToRepeater(List<HttpRequestResponse> messages) {
        int i = 0;
        for (HttpRequestResponse rr : messages) {
            try {
                HttpRequest plain = decryptRequest(rr);
                ctx.api.repeater().sendToRepeater(plain, name(rr, i++));
            } catch (Exception e) {
                Log.error("发送到 Repeater 失败", e);
            }
        }
    }

    private void sendToIntruder(List<HttpRequestResponse> messages) {
        int i = 0;
        for (HttpRequestResponse rr : messages) {
            try {
                ctx.api.intruder().sendToIntruder(decryptRequest(rr));
                i++;
            } catch (Exception e) {
                Log.error("发送到 Intruder 失败", e);
            }
        }
        if (i > 0) {
            Log.info("已把 " + i + " 条明文报文发送到 Intruder（Payload 直接对明文插，发送前自动加密）");
        }
    }

    private void decryptInEditor(MessageEditorHttpRequestResponse editor) {
        try {
            HttpRequestResponse rr = editor.requestResponse();
            if (rr == null) {
                return;
            }
            Profile profile = profile(rr);
            if (profile == null) {
                return;
            }
            boolean isRequestEditor =
                    editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST;
            if (isRequestEditor) {
                editor.setRequest(decryptRequest(rr));
            } else if (rr.response() != null) {
                TransformResult r = MessageTransform.apply(profile, ScriptStage.SERVER_TO_BURP,
                        rr.request() == null ? "" : rr.request().url(),
                        rr.request() == null ? "" : rr.request().method(),
                        CryptoHttpHandler.headerLines(rr.response().headers()),
                        rr.response().body().getBytes());
                if (r.changed()) {
                    editor.setResponse(rr.response().withBody(
                            burp.api.montoya.core.ByteArray.byteArray(r.body)));
                }
            }
        } catch (Exception e) {
            Log.error("就地解密失败", e);
        }
    }

    private void showPlaintext(HttpRequestResponse rr) {
        Profile profile = profile(rr);
        if (profile == null) {
            return;
        }
        boolean beautify = ctx.config().beautifyJson;
        StringBuilder sb = new StringBuilder();
        sb.append("──────── 请求明文（完整报文） ────────\n");
        sb.append(MessagePrinter.request(rr.request(),
                plainBody(profile, ScriptStage.CLIENT_TO_BURP, rr.request(),
                        rr.request().body() == null ? new byte[0] : rr.request().body().getBytes()),
                beautify));
        if (rr.response() != null) {
            sb.append("\n\n──────── 响应明文（完整报文） ────────\n");
            sb.append(MessagePrinter.response(rr.response(),
                    plainBody(profile, ScriptStage.SERVER_TO_BURP, rr.request(),
                            rr.response().body() == null ? new byte[0] : rr.response().body().getBytes()),
                    beautify));
        }
        Ui.showText(null, "BurpCryptCat 明文", sb.toString());
    }

    /** 把解密后的完整报文放进剪贴板（喂给 xia SQL 这类只能粘贴的工具）。 */
    private void copyPlain(HttpRequestResponse rr, boolean withRequest, boolean withResponse) {
        Profile profile = profile(rr);
        if (profile == null) {
            return;
        }
        boolean beautify = ctx.config().beautifyJson;
        StringBuilder sb = new StringBuilder();
        if (withRequest) {
            sb.append(MessagePrinter.request(rr.request(),
                    plainBody(profile, ScriptStage.CLIENT_TO_BURP, rr.request(),
                            rr.request().body() == null ? new byte[0] : rr.request().body().getBytes()),
                    beautify));
        }
        if (withResponse && rr.response() != null) {
            if (sb.length() > 0) {
                sb.append("\n\n");
            }
            sb.append(MessagePrinter.response(rr.response(),
                    plainBody(profile, ScriptStage.SERVER_TO_BURP, rr.request(),
                            rr.response().body() == null ? new byte[0] : rr.response().body().getBytes()),
                    beautify));
        }
        Ui.copy(sb.toString());
        Log.info("已复制明文报文到剪贴板（方案：" + profile.name + "）");
    }

    /* ==================== 工具 ==================== */

    private Profile profile(HttpRequestResponse rr) {
        try {
            if (rr.request() == null) {
                return null;
            }
            TargetResolver.Hit hit = TargetResolver.resolve(ctx.config(),
                    burp.config.AppConfig.ToolGroup.PROXY, rr.request().url(), true);
            return hit == null ? null : hit.profile;
        } catch (Exception e) {
            return null;
        }
    }

    private HttpRequest decryptRequest(HttpRequestResponse rr) {
        HttpRequest request = rr.request();
        Profile profile = profile(rr);
        if (profile == null || request.body() == null) {
            return request;
        }
        TransformResult r = MessageTransform.apply(profile, ScriptStage.CLIENT_TO_BURP,
                request.url(), request.method(), CryptoHttpHandler.headerLines(request.headers()),
                request.body().getBytes());
        if (!r.changed()) {
            return request;
        }
        return request.withBody(burp.api.montoya.core.ByteArray.byteArray(r.body));
    }

    private String plainBody(Profile profile, ScriptStage stage, HttpRequest request, byte[] body) {
        if (body == null || body.length == 0) {
            return "";
        }
        TransformResult r = MessageTransform.apply(profile, stage,
                request == null ? "" : request.url(),
                request == null ? "" : request.method(),
                request == null ? java.util.List.of() : CryptoHttpHandler.headerLines(request.headers()),
                body);
        if (r.changed()) {
            return Codec.decodeLenient(r.body, Codec.charset(profile.charset));
        }
        return Codec.decodeLenient(body, Codec.charset(profile.charset));
    }

    private String name(HttpRequestResponse rr, int index) {
        String url = rr.request().url();
        int q = url.indexOf('?');
        return "BurpCryptCat明文 " + (index + 1) + " " + (q > 0 ? url.substring(0, q) : url);
    }
}
