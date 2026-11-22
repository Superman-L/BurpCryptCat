package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.config.AppConfig;
import burp.config.ConfigStore;
import burp.http.CryptoHttpHandler;
import burp.http.CryptoProxyHandler;
import burp.http.HandoffCache;
import burp.support.Log;
import burp.support.StatusFile;
import burp.transform.CryptoService;
import burp.transform.PlaintextLog;
import burp.ui.CryptoEditors;
import burp.ui.CryptoMenu;
import burp.ui.MainTab;
import burp.ui.UiContext;

import java.io.PrintWriter;

/**
 * BurpCryptCat · Body 透明加解密 —— 扩展入口。
 *
 * <p>在上游 BurpCrypto 的思路（算法 / 密钥 / IV 三要素）之上，重写了配置方式与处理
 * 逻辑：不再需要 Intruder Payload Processor，而是"选一个算法 + 填 Key/IV + 配一条
 * 生效规则"，插件就在 Proxy / Repeater / Intruder 里自动处理 Body 的加解密，
 * URL、Header、Cookie 一概不动。</p>
 *
 * <p>处理器分工：</p>
 * <ul>
 *   <li>{@link CryptoHttpHandler} —— 全工具的请求发出前加密、响应收到后解密
 *       （Repeater / Intruder / Scanner …），<b>跳过 Proxy</b>。</li>
 *   <li>{@link CryptoProxyHandler} —— Proxy 专用两段式：
 *       收到时解密（历史/编辑器显明文）→ 放行前/回写前再加密（线上仍是密文）。</li>
 * </ul>
 */
public class BurpExtender implements BurpExtension {

    public static final String VERSION = "1.7.3";
    public static final String NAME = "BurpCryptCat";

    private CryptoService service;
    private UiContext uiContext;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME + " v" + VERSION);

        Log.init(outputWriter(api), false);

        // 1) 配置：从 Burp Preferences 读取（首次运行给一份示例）
        ConfigStore store = new ConfigStore(api.persistence());
        AppConfig config = store.load();
        Log.setDebug(config.debug);

        // 2) 服务层
        PlaintextLog log = new PlaintextLog();
        this.service = new CryptoService(config, log);
        this.uiContext = new UiContext(api, service, store);
        store.bind(config, null);

        // 3) HTTP 处理器（Proxy 的请求加密也走这里，见 CryptoHttpHandler 注释）
        HandoffCache handoff = new HandoffCache();
        api.http().registerHttpHandler(new CryptoHttpHandler(service, handoff));

        CryptoProxyHandler proxyHandler = new CryptoProxyHandler(service, handoff);
        api.proxy().registerRequestHandler(proxyHandler);
        api.proxy().registerResponseHandler(proxyHandler);

        // 4) 编辑器里的「BurpCryptCat明文」页签
        api.userInterface().registerHttpRequestEditorProvider(CryptoEditors.requestProvider(uiContext));
        api.userInterface().registerHttpResponseEditorProvider(CryptoEditors.responseProvider(uiContext));

        // 5) 右键菜单：解密后发送到 Repeater / Intruder、查看明文、就地解密
        api.userInterface().registerContextMenuItemsProvider(new CryptoMenu(uiContext));

        // 6) 主界面
        MainTab tab = new MainTab(uiContext);
        try {
            api.userInterface().applyThemeToComponent(tab);
        } catch (Exception ignore) {
            // 主题套用失败不影响功能
        }
        api.userInterface().registerSuiteTab("BurpCryptCat", tab);

        // 7) 首次运行落盘，保证配置真的"持久化"
        store.save(config);

        api.extension().registerUnloadingHandler(() -> {
            burp.script.PythonRunner.shutdown();
            Log.step("BurpCryptCat 已卸载，配置保留在 ~/.BurpCrypto/config");
        });

        banner();
        StatusFile.write(VERSION, config, "扩展已加载", store.directory());
        Log.info("配置文件：" + store.describe());
        Log.info("状态文件：" + StatusFile.file(store.directory()).getAbsolutePath() + "（排错时可直接看这里）");
        if (config.rules.stream().noneMatch(r -> r.enabled) && config.fallbackProfileId.isBlank()) {
            Log.warn("⚠ 当前没有任何启用的规则，插件不会处理任何流量。"
                    + "请到「② 生效规则」勾选一条规则的「启用」。");
        }
    }

    private void banner() {
        Log.step(NAME + " v" + VERSION + " 加载完成");
        Log.info("作者：基于 whwlsfb/BurpCrypto 二次开发（配置与处理逻辑重写）");
        Log.info("用法：① 配置方案里选算法/填 Key/IV → ② 生效规则里按 Host 或 URL 启用 → ③ 正常抓包");
        Log.info("处理范围：只改 Body；Proxy 请求保留明文（Original 密文 / Edited 明文）并由 HttpHandler 加密上线；响应报文不动、明文看页签");
        AppConfig cfg = service.config();
        Log.info("当前状态：" + cfg.statusText());
        Log.info("Proxy 处理=" + cfg.proxyEnabled
                + "  请求回写加密=" + cfg.proxyReencryptRequest
                + "  响应回写加密=" + cfg.proxyReencryptResponse
                + "  （两项回写加密都关掉时：历史显示明文，但两端会收到明文）");
        if (!cfg.masterEnabled) {
            Log.warn("总开关是关闭的，先把「BurpCryptCat」标签页里的总开关打开");
        }
    }

    /** 把 Log 接到 Burp 的 Extender → Output 面板。 */
    @SuppressWarnings("deprecation")
    private static PrintWriter outputWriter(MontoyaApi api) {
        return new PrintWriter(api.logging().output(), true);
    }

    public CryptoService service() {
        return service;
    }
}
