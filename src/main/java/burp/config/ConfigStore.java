package burp.config;

import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
import burp.support.Log;

import java.io.File;
import java.io.IOException;

/**
 * 配置持久化：**本地文件**（默认 {@code ~/.BurpCrypto/config}），可在界面里换目录。
 *
 * <p>为什么改成文件：配置里有 Key/IV、有按目标维护的规则，测试人员经常要
 * "这次项目一套配置"、在几台机器/几个同事之间传递。放在本地目录里可以直接备份、
 * 可以 git、可以拷 U 盘，比埋在 Burp 的 Preferences 里好管理得多。</p>
 *
 * <p>Burp Preferences 只留一个"配置目录指针"，这样换目录后下次启动还能找到。</p>
 */
public final class ConfigStore {

    /** Preferences 里只存一个目录指针 */
    private static final String KEY_DIR = "burpcrypto.config.dir";
    /** 旧版（1.2.0 及以前）把整份 INI 存在 Preferences 里，首次升级时迁移过来 */
    private static final String KEY_LEGACY_INI = "burpcrypto.body.config.ini";

    private final Preferences prefs;
    private volatile File dir;

    public ConfigStore(Persistence persistence) {
        this.prefs = persistence.preferences();
        this.dir = resolveDir();
    }

    /* ==================== 路径 ==================== */

    public File directory() {
        return dir;
    }

    public File file() {
        return ConfigFile.fileIn(dir);
    }

    /** 规则文件：~/.BurpCrypto/rules（和 config 分开，方便长久保存 / 单独备份 / 手改） */
    public File rulesFile() {
        return new File(dir, "rules");
    }

    public boolean fileExists() {
        return ConfigFile.exists(file());
    }

    /**
     * 切换配置目录。
     *
     * @param copyCurrent true = 把当前内存里的配置写到新目录（覆盖）；
     *                    false = 不动新目录里的文件，交给调用方 {@link #load()} 读它
     */
    public void setDirectory(File newDir, boolean copyCurrent) {
        if (newDir == null) {
            return;
        }
        File target = newDir.getAbsoluteFile();
        if (target.equals(dir)) {
            return;
        }
        Log.info("配置目录切换：" + dir.getAbsolutePath() + " → " + target.getAbsolutePath()
                + (copyCurrent ? "（用当前配置覆盖）" : "（载入该目录的配置）"));
        this.dir = target;
        try {
            prefs.setString(KEY_DIR, target.getAbsolutePath());
        } catch (Exception e) {
            Log.error("保存配置目录指针失败", e);
        }
        if (copyCurrent) {
            saveNow();
        }
    }

    private File resolveDir() {
        try {
            String configured = prefs.getString(KEY_DIR);
            if (configured != null && !configured.isBlank()) {
                return new File(configured.trim()).getAbsoluteFile();
            }
        } catch (Exception ignore) {
            // Preferences 读失败就用默认目录
        }
        return ConfigFile.defaultDir();
    }

    private AppConfig current;
    private Runnable changeListener = () -> {
    };

    /** 记录"当前这份配置"，供换目录时立即落盘。 */
    public void bind(AppConfig config, Runnable onChange) {
        this.current = config;
        if (onChange != null) {
            this.changeListener = onChange;
        }
    }

    private void saveNow() {
        if (current != null) {
            write(current);
        }
    }

    /* ==================== 读 ==================== */

    public AppConfig load() {
        File f = file();
        try {
            if (ConfigFile.exists(f)) {
                String text = ConfigFile.read(f);
                AppConfig cfg = AppConfig.fromIni(text);
                loadRules(cfg);
                Log.step("已从文件载入配置：" + f.getAbsolutePath()
                        + "（方案 " + cfg.profiles.size() + " 个，规则 " + cfg.rules.size() + " 条）");
                return cfg;
            }
            // 首次运行：尝试从旧版 Preferences 迁移
            AppConfig migrated = tryMigrateFromPreferences();
            if (migrated != null) {
                write(migrated);
                writeRules(migrated);
                Log.step("已把旧版（Preferences）里的配置迁移到：" + f.getAbsolutePath());
                return migrated;
            }
            AppConfig fresh = AppConfig.defaults();
            write(fresh);
            writeRules(fresh);
            Log.step("首次运行，已生成示例配置：" + f.getAbsolutePath());
            return fresh;
        } catch (Exception e) {
            Log.error("读取配置文件失败（回退到默认配置）：" + f.getAbsolutePath(), e);
            return AppConfig.defaults();
        }
    }

    private AppConfig tryMigrateFromPreferences() {
        try {
            String legacy = prefs.getString(KEY_LEGACY_INI);
            if (legacy == null || legacy.isBlank()) {
                return null;
            }
            AppConfig cfg = AppConfig.fromIni(legacy);
            // 迁移成功后删掉旧键，避免以后又"复活"覆盖新文件
            try {
                prefs.deleteString(KEY_LEGACY_INI);
            } catch (Exception ignore) {
                // 删不掉也无妨
            }
            return cfg;
        } catch (Exception e) {
            return null;
        }
    }

    /* ==================== 写 ==================== */

    public void save(AppConfig cfg) {
        this.current = cfg;
        write(cfg);
        writeRules(cfg);
    }

    /** 写 config（不含规则） */
    private void write(AppConfig cfg) {
        File f = file();
        try {
            ConfigFile.write(f, ConfigFile.withHeader(cfg.toIni(false), f));
        } catch (IOException e) {
            Log.error("写入配置文件失败：" + f.getAbsolutePath(), e);
        }
    }

    /** 写规则文件 */
    private void writeRules(AppConfig cfg) {
        File f = rulesFile();
        try {
            ConfigFile.write(f, ConfigFile.withHeader(cfg.rulesToIni(), f));
        } catch (IOException e) {
            Log.error("写入规则文件失败：" + f.getAbsolutePath(), e);
        }
    }

    /** 规则优先读独立文件；没有就沿用 config 里内联的规则并落盘（迁移） */
    private void loadRules(AppConfig cfg) {
        File rf = rulesFile();
        try {
            if (ConfigFile.exists(rf)) {
                java.util.List<burp.config.Rule> rules = AppConfig.parseRules(ConfigFile.read(rf));
                cfg.rules.clear();
                cfg.rules.addAll(rules);
                Log.info("已从规则文件载入 " + rules.size() + " 条规则：" + rf.getAbsolutePath());
                return;
            }
        } catch (IOException e) {
            Log.error("读取规则文件失败（沿用 config 内联规则）：" + rf.getAbsolutePath(), e);
            return;
        }
        if (!cfg.rules.isEmpty()) {
            writeRules(cfg);
            Log.step("已把内联规则迁移到独立文件：" + rf.getAbsolutePath());
        }
    }

    /** 界面展示用。 */
    public String describe() {
        return file().getAbsolutePath() + (file().isFile() ? "" : "（尚未创建）")
                + "   |   规则：" + rulesFile().getAbsolutePath()
                + (rulesFile().isFile() ? "" : "（尚未创建）");
    }
}
