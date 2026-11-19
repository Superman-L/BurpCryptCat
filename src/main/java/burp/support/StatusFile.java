package burp.support;

import burp.config.AppConfig;
import burp.config.Profile;
import burp.config.Rule;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 把"当前生效状态"写到一个小文本文件里，方便排错和给插件提 issue 时附上。
 *
 * <p>只写开关、规则、方案元信息（算法/编码/Key 是否已填、长度），
 * <b>绝不写 Key / IV 的具体内容</b>。</p>
 *
 * <p>路径：/tmp/burpcrypto-status.txt（非 Unix 系统退化为 java.io.tmpdir）。</p>
 */
public final class StatusFile {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private StatusFile() {
    }

    /** 主文件：配置目录下的 status.txt（~/.BurpCrypto/status.txt） */
    public static File file(File configDir) {
        if (configDir != null) {
            return new File(configDir, "status.txt");
        }
        return mirrorFile();
    }

    /** 镜像文件：/tmp/burpcrypto-status.txt，方便随手 tail */
    public static File mirrorFile() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("mac") || os.contains("linux") || os.contains("unix")) {
            return new File("/tmp/burpcrypto-status.txt");
        }
        return new File(System.getProperty("java.io.tmpdir"), "burpcrypto-status.txt");
    }

    public static void write(String version, AppConfig cfg, String note, File configDir) {
        StringBuilder sb = new StringBuilder();
        sb.append("BurpCryptCat ").append(version).append('\n');
        sb.append("配置目录  : ").append(configDir == null ? "（未知）" : configDir.getAbsolutePath()).append('\n');
        sb.append("时间      : ").append(LocalDateTime.now().format(FMT)).append('\n');
        if (note != null && !note.isEmpty()) {
            sb.append("事件      : ").append(note).append('\n');
        }
        sb.append("状态      : ").append(cfg.statusText()).append('\n');
        sb.append("总开关    : ").append(cfg.masterEnabled).append('\n');
        sb.append("生效工具  : ").append(cfg.tools.isEmpty() ? "（全部关闭）" : cfg.tools.toString()).append('\n');
        sb.append("Proxy     : 参与=").append(cfg.proxyEnabled)
                .append("  请求回写加密=").append(cfg.proxyReencryptRequest)
                .append("  响应回写加密=").append(cfg.proxyReencryptResponse).append('\n');
        sb.append("明文美化  : ").append(cfg.beautifyJson).append("\n");
        sb.append("兜底方案  : ").append(cfg.fallbackProfileId.isEmpty() ? "（未设置）" : cfg.fallbackProfileId).append('\n');
        sb.append('\n').append("[配置方案 ").append(cfg.profiles.size()).append(" 个]\n");
        for (Profile p : cfg.profiles) {
            String err = p.validate();
            sb.append("  - ").append(p.name)
                    .append("  id=").append(p.id)
                    .append("  ").append(p.cipher)
                    .append("  编码=").append(p.bodyEncoding)
                    .append("  范围=").append(p.bodyScope)
                    .append("  启用=").append(p.enabled)
                    .append("  Key长度=").append(p.key == null ? 0 : p.key.length())
                    .append("  IV长度=").append(p.iv == null ? 0 : p.iv.length())
                    .append("  自检=").append(err == null ? "通过" : ("失败(" + err + ")"))
                    .append('\n');
        }
        sb.append('\n').append("[生效规则 ").append(cfg.rules.size()).append(" 条，按顺序匹配]\n");
        int i = 1;
        for (Rule r : cfg.rules) {
            Profile p = cfg.profile(r.profileId);
            sb.append("  ").append(i++).append(". ")
                    .append(r.enabled ? "[启用] " : "[停用] ")
                    .append(r.matchType).append(' ').append(r.pattern)
                    .append("  →  ").append(p == null ? "（方案缺失）" : p.name)
                    .append(r.onRequest ? "  请求" : "").append(r.onResponse ? "  响应" : "")
                    .append('\n');
        }
        writeTo(file(configDir), sb.toString());
        // 再写一份镜像到临时目录，方便排错时直接看
        if (configDir != null) {
            writeTo(mirrorFile(), sb.toString());
        }
    }

    private static void writeTo(File f, String text) {
        try {
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) {
                //noinspection ResultOfMethodCallIgnored
                parent.mkdirs();
            }
            Files.writeString(f.toPath(), text, StandardCharsets.UTF_8);
            try {
                Files.setPosixFilePermissions(f.toPath(),
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            } catch (Exception ignore) {
                // 非 POSIX 文件系统忽略
            }
        } catch (IOException e) {
            Log.warn("写入状态文件失败（不影响使用）：" + e);
        }
    }
}
