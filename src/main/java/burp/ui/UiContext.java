package burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.config.AppConfig;
import burp.config.ConfigStore;
import burp.support.Log;
import burp.support.StatusFile;
import burp.transform.CryptoService;

import java.util.ArrayList;
import java.util.List;

/**
 * 界面与逻辑之间的共享上下文：一份配置、一个服务、一个持久化器。
 *
 * <p>所有"改配置"的动作最后都收敛到 {@link #commit(String)}：保存到 Burp 配置、
 * 通知各处刷新、打一行日志。这样就不存在"某个页面忘了落盘"的问题。</p>
 */
public final class UiContext {

    public final MontoyaApi api;
    public final CryptoService service;
    public final ConfigStore store;

    private final List<Runnable> listeners = new ArrayList<>();
    private Runnable statusSink = () -> {
    };
    private String lastSaveHint = "";

    public UiContext(MontoyaApi api, CryptoService service, ConfigStore store) {
        this.api = api;
        this.service = service;
        this.store = store;
    }

    public AppConfig config() {
        return service.config();
    }

    /** 配置已改动：落盘 + 广播。 */
    public void commit(String reason) {
        AppConfig cfg = config();
        store.save(cfg);
        lastSaveHint = "已保存 · " + java.time.LocalTime.now().withNano(0)
                + (reason == null || reason.isEmpty() ? "" : " · " + reason);
        Log.setDebug(cfg.debug);
        StatusFile.write(burp.BurpExtender.VERSION, cfg, "配置已保存：" + reason, store.directory());
        refreshStatus();
        for (Runnable r : new ArrayList<>(listeners)) {
            try {
                r.run();
            } catch (RuntimeException e) {
                Log.error("界面刷新失败", e);
            }
        }
    }

    /** 从磁盘重新载入配置（换目录后 / 手工改过文件后使用）。 */
    public void reloadFromStore() {
        AppConfig cfg = store.load();
        service.update(cfg);
        Log.setDebug(cfg.debug);
        refreshStatus();
        for (Runnable r : new ArrayList<>(listeners)) {
            try {
                r.run();
            } catch (RuntimeException e) {
                Log.error("界面刷新失败", e);
            }
        }
    }

    public void onConfigChanged(Runnable r) {
        listeners.add(r);
    }

    public void setStatusSink(Runnable sink) {
        this.statusSink = sink;
    }

    public void refreshStatus() {
        statusSink.run();
    }

    public String lastSaveHint() {
        return lastSaveHint;
    }
}
