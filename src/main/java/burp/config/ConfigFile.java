package burp.config;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * 配置文件读写（纯文件 IO，不依赖 Burp API，方便单测）。
 *
 * <p>默认位置：{@code ~/.BurpCrypto/config}（Windows 为 {@code C:\Users\<你>\.BurpCrypto\config}）。
 * 写入是"先写临时文件再原子替换 + 留一份 config.bak"，避免 Burp 崩了把配置写坏。</p>
 */
public final class ConfigFile {

    /** 配置文件名（无扩展名，按需求就叫 config） */
    public static final String FILE_NAME = "config";
    /** 目录名 */
    public static final String DIR_NAME = ".BurpCrypto";

    private ConfigFile() {
    }

    /** 默认配置目录：~/.BurpCrypto */
    public static File defaultDir() {
        return new File(System.getProperty("user.home", "."), DIR_NAME);
    }

    public static File fileIn(File dir) {
        return new File(dir, FILE_NAME);
    }

    public static File backupOf(File file) {
        return new File(file.getParentFile(), FILE_NAME + ".bak");
    }

    public static boolean exists(File file) {
        return file != null && file.isFile();
    }

    public static String read(File file) throws IOException {
        return Files.readString(file.toPath(), StandardCharsets.UTF_8);
    }

    /**
     * 原子写入：临时文件 → 替换；替换前把旧文件留一份 {@code config.bak}。
     */
    public static void write(File file, String content) throws IOException {
        File dir = file.getParentFile();
        if (dir != null && !dir.isDirectory()) {
            Files.createDirectories(dir.toPath());
            restrict(dir.toPath());
        }
        if (file.isFile()) {
            try {
                Files.copy(file.toPath(), backupOf(file).toPath(), StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException ignore) {
                // 备份失败不影响主流程
            }
        }
        Path tmp = new File(dir, FILE_NAME + ".tmp").toPath();
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        try {
            Files.move(tmp, file.toPath(), StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
        restrict(file.toPath());
    }

    /** 尽量把权限收紧到 700 / 600（配置里有密钥）。Windows 上失败了就忽略。 */
    private static void restrict(Path path) {
        try {
            if (Files.isDirectory(path)) {
                Files.setPosixFilePermissions(path, java.nio.file.attribute.PosixFilePermissions
                        .fromString("rwx------"));
            } else {
                Files.setPosixFilePermissions(path, java.nio.file.attribute.PosixFilePermissions
                        .fromString("rw-------"));
            }
        } catch (Exception ignore) {
            // 非 POSIX 文件系统（Windows）忽略
        }
    }

    /** 把配置文本加上文件头注释（时间与路径），便于人工查看。 */
    public static String withHeader(String ini, File file) {
        return "# 本文件由 BurpCryptCat 自动维护，可直接编辑（扩展保存时会被覆盖）\n"
                + "# 位置：" + file.getAbsolutePath() + "\n"
                + "# 时间：" + java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + "\n"
                + ini;
    }
}
