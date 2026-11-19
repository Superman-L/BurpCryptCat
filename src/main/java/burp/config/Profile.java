package burp.config;

import burp.crypto.Codec;
import burp.crypto.CryptoEngine;
import burp.crypto.CryptoException;
import burp.crypto.KeyMaterial;

import java.util.Objects;
import java.util.UUID;

/**
 * 一条加解密配置（界面上叫"配置方案"）：算法 + Key + IV + 密文编码 + Body 处理范围。
 *
 * <p>字段刻意做得扁平、全部可读写，方便直接映射到 INI 文本与 Swing 表单。
 * {@link #toEngine()} 负责把文本配置编译成可用的加解密引擎，编译结果带缓存，
 * 配置一改（{@link #touch()}）缓存立刻失效。</p>
 */
public final class Profile {

    /** 密文在 Body 里的表示方式 */
    public enum BodyEncoding {
        BASE64("Base64"),
        HEX("HEX"),
        RAW("原始二进制");

        private final String label;

        BodyEncoding(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }

        @Override
        public String toString() {
            return label;
        }

        public static BodyEncoding of(String n) {
            if (n == null) {
                return BASE64;
            }
            for (BodyEncoding e : values()) {
                if (e.name().equalsIgnoreCase(n.trim())) {
                    return e;
                }
            }
            return BASE64;
        }
    }

    /**
     * 加解密方式：内置算法 / JS 脚本 / 外部命令。
     *
     * <p>脚本方式对应"四个阶段接口"（客户端→Burp、Burp→服务端、服务端→Burp、Burp→客户端），
     * 由脚本自己决定每步怎么处理，插件只在对应阶段调用同名函数。</p>
     */
    public enum Engine {
        BUILTIN("内置算法"),
        SCRIPT_JS("脚本（JavaScript）"),
        SCRIPT_CMD("外部命令（stdin/stdout）");

        private final String label;

        Engine(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }

        @Override
        public String toString() {
            return label;
        }

        public static Engine of(String n) {
            if (n == null) {
                return BUILTIN;
            }
            for (Engine e : values()) {
                if (e.name().equalsIgnoreCase(n.trim())) {
                    return e;
                }
            }
            return BUILTIN;
        }
    }

    /** 处理 Body 的哪一部分 */
    public enum BodyScope {
        WHOLE("整个 Body"),
        JSON_FIELD("JSON 字段");

        private final String label;

        BodyScope(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }

        @Override
        public String toString() {
            return label;
        }

        public static BodyScope of(String n) {
            if (n == null) {
                return WHOLE;
            }
            for (BodyScope e : values()) {
                if (e.name().equalsIgnoreCase(n.trim())) {
                    return e;
                }
            }
            return WHOLE;
        }
    }

    public String id = UUID.randomUUID().toString().substring(0, 8);
    public String name = "新配置";
    public boolean enabled = true;

    /** 算法描述，例如 AES/CBC/PKCS5Padding */
    public String cipher = "AES/CBC/PKCS5Padding";
    public String key = "";
    public KeyMaterial.Format keyFormat = KeyMaterial.Format.AUTO;
    public String iv = "";
    public KeyMaterial.Format ivFormat = KeyMaterial.Format.AUTO;
    public CryptoEngine.IvMode ivMode = CryptoEngine.IvMode.AUTO;

    /** 加解密方式 */
    public Engine engine = Engine.BUILTIN;
    /** 脚本模式：JS 脚本文件名（相对 ~/.BurpCrypto/scripts）或外部命令行 */
    public String scriptPath = "";
    /** 外部命令超时（毫秒） */
    public int scriptTimeoutMs = 5000;

    public BodyEncoding bodyEncoding = BodyEncoding.BASE64;
    public BodyScope bodyScope = BodyScope.WHOLE;
    public String jsonField = "data";
    public String charset = "UTF-8";

    public boolean onRequest = true;
    public boolean onResponse = true;

    public String comment = "";

    /** 缓存版本号：任何改动都会 +1，使已编译引擎失效 */
    private transient long version = 1;
    private transient CryptoEngine cached;
    private transient CryptoException cachedError;
    private transient long cachedVersion = -1;

    public Profile() {
    }

    public Profile(String id, String name) {
        this.id = id;
        this.name = name;
    }

    /** 标记为"已修改"，丢弃编译缓存。 */
    public void touch() {
        version++;
    }

    public long version() {
        return version;
    }

    /**
     * 把文本配置编译成引擎。失败时抛 {@link CryptoException}，消息可直接展示给用户。
     * 编译结果会缓存，直到 {@link #touch()} 被调用。
     */
    public CryptoEngine toEngine() throws CryptoException {
        if (isScript()) {
            throw new CryptoException("当前方案使用"
                    + engine.label() + "，不走内置算法引擎");
        }
        if (cachedVersion == version) {
            if (cachedError != null) {
                throw cachedError;
            }
            return cached;
        }
        try {
            cached = CryptoEngine.create(cipher, key, keyFormat, iv, ivFormat, ivMode, charset);
            cachedError = null;
            cachedVersion = version;
            return cached;
        } catch (CryptoException e) {
            cached = null;
            cachedError = e;
            cachedVersion = version;
            throw e;
        }
    }

    /** 是否脚本方式 */
    public boolean isScript() {
        return engine != null && engine != Engine.BUILTIN;
    }

    /** 试算一次，返回 null 表示配置可用，否则返回错误描述。 */
    public String validate() {
        if (isScript()) {
            return validateScript();
        }
        try {
            CryptoEngine engine = toEngine();
            byte[] probe = "BurpCryptCat".getBytes(Codec.charset(charset));
            byte[] ct = engine.encrypt(probe);
            byte[] back = engine.decrypt(ct);
            if (!new String(back, Codec.charset(charset)).equals("BurpCryptCat")) {
                return "自检失败：加解密结果不一致";
            }
            return null;
        } catch (CryptoException e) {
            return e.getMessage();
        } catch (RuntimeException e) {
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    private String validateScript() {
        if (scriptPath == null || scriptPath.isBlank()) {
            return engine == Engine.SCRIPT_JS ? "脚本路径为空" : "外部命令为空";
        }
        if (engine == Engine.SCRIPT_CMD) {
            return null;               // 命令不预跑，避免副作用
        }
        java.io.File f = burp.script.ScriptRuntime.resolve(this);
        if (f == null || !f.isFile()) {
            return "脚本文件不存在：" + (f == null ? scriptPath : f.getAbsolutePath());
        }
        java.util.List<String> hooks = burp.script.JsScriptRunner.hooksOf(f);
        if (hooks.isEmpty()) {
            return "脚本编译失败，或没有实现任何钩子（clientToBurp / burpToServer / serverToBurp / burpToClient）";
        }
        return null;
    }

    public Profile copy() {
        Profile p = new Profile();
        p.id = UUID.randomUUID().toString().substring(0, 8);
        p.name = name + " 副本";
        p.enabled = enabled;
        p.cipher = cipher;
        p.key = key;
        p.keyFormat = keyFormat;
        p.iv = iv;
        p.ivFormat = ivFormat;
        p.ivMode = ivMode;
        p.engine = engine;
        p.scriptPath = scriptPath;
        p.scriptTimeoutMs = scriptTimeoutMs;
        p.bodyEncoding = bodyEncoding;
        p.bodyScope = bodyScope;
        p.jsonField = jsonField;
        p.charset = charset;
        p.onRequest = onRequest;
        p.onResponse = onResponse;
        p.comment = comment;
        return p;
    }

    /** 生成一行摘要，用于主界面状态标签。 */
    public String summary() {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append("  ·  ").append(isScript() ? engine.label() : cipher);
        if (bodyEncoding != BodyEncoding.BASE64) {
            sb.append("  ·  ").append(bodyEncoding.label());
        }
        if (bodyScope == BodyScope.JSON_FIELD) {
            sb.append("  ·  字段 ").append(jsonField);
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Profile p && Objects.equals(id, p.id);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id);
    }
}
