package burp.ui;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import burp.config.AppConfig;
import burp.crypto.Codec;
import burp.http.ToolGroups;
import burp.http.CryptoHttpHandler;
import burp.script.ScriptStage;
import burp.transform.MessageTransform;
import burp.transform.TargetResolver;
import burp.transform.TransformResult;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.util.Arrays;

/**
 * 报文编辑器里的「BurpCryptCat 明文」页签：显示**完整报文**（请求行 + 全部 Header +
 * 解密后的 Body），JSON 自动缩进美化，改完直接发（发送前由 HTTP 处理器加密回去）。
 *
 * <p>几个刻意的细节：</p>
 * <ul>
 *   <li>Header、URL 一律原样展示；只把 Content-Length 按解密后的 Body 重算，
 *       这样"看到的报文"是自洽的，复制出去就是一份能直接用的明文请求包。</li>
 *   <li>只有内容真的被改过才会替换报文（与展示文本逐字节比对），
 *       避免"看一眼就把报文标成已修改"。</li>
 *   <li>Body 按方案里配置的字符集解码，GBK 目标也能正常显示。</li>
 * </ul>
 */
public final class CryptoEditors {

    private CryptoEditors() {
    }

    public static HttpRequestEditorProvider requestProvider(UiContext ctx) {
        return creationContext -> new RequestEditor(ctx, groupOf(creationContext));
    }

    public static HttpResponseEditorProvider responseProvider(UiContext ctx) {
        return creationContext -> new ResponseEditor(ctx, groupOf(creationContext));
    }

    private static AppConfig.ToolGroup groupOf(EditorCreationContext context) {
        try {
            if (context != null && context.toolSource() != null) {
                return ToolGroups.of(context.toolSource().toolType());
            }
        } catch (Exception ignore) {
            // 某些上下文拿不到来源，按"其它工具"处理
        }
        return AppConfig.ToolGroup.OTHER;
    }

    /* ==================== 公共基类 ==================== */

    private abstract static class BaseEditor {
        final UiContext ctx;
        final AppConfig.ToolGroup group;
        final RawEditor editor;
        final JLabel info = new JLabel();
        final JPanel root = new JPanel(new BorderLayout());
        byte[] shown = new byte[0];

        BaseEditor(UiContext ctx, AppConfig.ToolGroup group) {
            this.ctx = ctx;
            this.group = group;
            this.editor = ctx.api.userInterface().createRawEditor();
            info.setFont(info.getFont().deriveFont(Font.PLAIN, 11f));
            info.setForeground(new Color(0x666666));
            info.setBorder(new EmptyBorder(4, 8, 4, 8));
            root.add(info, BorderLayout.NORTH);
            root.add(editor.uiComponent(), BorderLayout.CENTER);
            root.setPreferredSize(new Dimension(620, 320));
        }

        Component uiComponent() {
            return root;
        }

        Selection selectedData() {
            return editor.selection().orElse(null);
        }

        void show(String text, String infoText, Color color) {
            shown = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            editor.setContents(ByteArray.byteArray(shown));
            info.setText(infoText);
            info.setForeground(color);
        }

        /** 用户在页签里改了内容吗？（只比较内容，不依赖 Burp 的修改标记） */
        byte[] editedContents() {
            ByteArray array = editor.getContents();
            byte[] now = array == null ? new byte[0] : array.getBytes();
            return Arrays.equals(now, shown) ? null : now;
        }

        String editedText() {
            byte[] b = editedContents();
            return b == null ? null : new String(b, java.nio.charset.StandardCharsets.UTF_8);
        }

        boolean beautify() {
            return ctx.config().beautifyJson;
        }

        String decorate(TargetResolver.Hit hit, TransformResult result) {
            String status = switch (result.kind) {
                case ENCRYPTED, DECRYPTED -> "已解密";
                case FAILED -> "处理失败";
                default -> "未处理";
            };
            String color = switch (result.kind) {
                case ENCRYPTED, DECRYPTED -> "#2E7D32";
                case FAILED -> "#C62828";
                default -> "#757575";
            };
            info.setForeground(Color.decode(color));
            return "状态：" + status
                    + (result.detail == null || result.detail.isEmpty() ? "" : "（" + result.detail + "）")
                    + "    ·    方案：" + hit.profile.name
                    + "    ·    " + hit.profile.cipher
                    + "    ·    美化：" + (beautify() ? "开" : "关")
                    + "    ·    来源：" + group.label();
        }

        /** 把 Body 按方案配置的字符集解码（GBK 目标也能正确显示）。 */
        static String bodyText(byte[] body, String charset) {
            return Codec.decodeLenient(body, Codec.charset(charset));
        }
    }

    /* ==================== 请求编辑器 ==================== */

    private static final class RequestEditor extends BaseEditor
            implements ExtensionProvidedHttpRequestEditor {

        private HttpRequest request;

        RequestEditor(UiContext ctx, AppConfig.ToolGroup group) {
            super(ctx, group);
        }

        @Override
        public String caption() {
            return "BurpCryptCat 明文";
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            try {
                if (requestResponse == null || requestResponse.request() == null) {
                    return false;
                }
                return TargetResolver.resolve(ctx.config(), group,
                        requestResponse.request().url(), true) != null;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.request = requestResponse == null ? null : requestResponse.request();
            if (request == null) {
                show("", "没有请求", Color.GRAY);
                return;
            }
            byte[] body = request.body() == null ? new byte[0] : request.body().getBytes();
            TargetResolver.Hit hit = TargetResolver.resolve(ctx.config(), group, request.url(), true);
            if (hit == null) {
                show(MessagePrinter.request(request, bodyText(body, "UTF-8"), beautify()),
                        "未命中任何规则（不处理）", Color.GRAY);
                return;
            }
            TransformResult r = MessageTransform.apply(hit.profile, ScriptStage.CLIENT_TO_BURP,
                    request.url(), request.method(), CryptoHttpHandler.headerLines(request.headers()), body);
            byte[] displayBody = r.changed() ? r.body : body;
            String text = MessagePrinter.request(request,
                    bodyText(displayBody, hit.profile.charset), beautify());
            show(text, decorate(hit, r), Color.GRAY);
        }

        @Override
        public HttpRequest getRequest() {
            if (request == null) {
                return null;
            }
            String edited = editedText();
            if (edited == null) {
                return request;
            }
            // 页签里是明文整包；按整包解析（连 Header 改动都生效），发送前由 HTTP 处理器加密
            return MessagePrinter.parseRequest(request, edited);
        }

        @Override
        public Component uiComponent() {
            return super.uiComponent();
        }

        @Override
        public Selection selectedData() {
            return super.selectedData();
        }

        @Override
        public boolean isModified() {
            return editedContents() != null;
        }
    }

    /* ==================== 响应编辑器 ==================== */

    private static final class ResponseEditor extends BaseEditor
            implements ExtensionProvidedHttpResponseEditor {

        private HttpResponse response;
        private HttpRequest request;

        ResponseEditor(UiContext ctx, AppConfig.ToolGroup group) {
            super(ctx, group);
        }

        @Override
        public String caption() {
            return "BurpCryptCat 明文";
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            try {
                if (requestResponse == null || requestResponse.request() == null
                        || requestResponse.response() == null) {
                    return false;
                }
                return TargetResolver.resolve(ctx.config(), group,
                        requestResponse.request().url(), false) != null;
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.response = requestResponse == null ? null : requestResponse.response();
            this.request = requestResponse == null ? null : requestResponse.request();
            if (response == null) {
                show("", "没有响应", Color.GRAY);
                return;
            }
            String url = request == null ? "" : request.url();
            byte[] body = response.body() == null ? new byte[0] : response.body().getBytes();
            TargetResolver.Hit hit = TargetResolver.resolve(ctx.config(), group, url, false);
            if (hit == null) {
                show(MessagePrinter.response(response, bodyText(body, "UTF-8"), beautify()),
                        "未命中任何规则（不处理）", Color.GRAY);
                return;
            }
            TransformResult r = MessageTransform.apply(hit.profile, ScriptStage.SERVER_TO_BURP,
                    url, "" /*method 由请求提供*/, CryptoHttpHandler.headerLines(response.headers()), body);
            byte[] displayBody = r.changed() ? r.body : body;
            String text = MessagePrinter.response(response,
                    bodyText(displayBody, hit.profile.charset), beautify());
            show(text, decorate(hit, r), Color.GRAY);
        }

        @Override
        public HttpResponse getResponse() {
            if (response == null) {
                return null;
            }
            String edited = editedText();
            if (edited == null) {
                return response;
            }
            return MessagePrinter.parseResponse(response, edited);
        }

        @Override
        public Component uiComponent() {
            return super.uiComponent();
        }

        @Override
        public Selection selectedData() {
            return super.selectedData();
        }

        @Override
        public boolean isModified() {
            return editedContents() != null;
        }
    }
}
