package xiabridge;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponsePersisted;
import burp.IHttpService;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * BurpCryptCat ←→ xia SQL 的桥接层（自包含，只依赖 JDK 与 Burp 旧版 API）。
 *
 * <p>作用：让 xia SQL 在"拿到请求"时看到**明文**（这样它才能在参数上注入），
 * 在"发出请求"时按 BurpCryptCat 的配置**加密**，从而测试加密接口。</p>
 *
 * <p>配置直接读 BurpCryptCat 的配置文件，保证两边永远一致：</p>
 * <pre>
 *   ~/.BurpCrypto/config          （可用 -Dburpcrypto.config=/path 覆盖）
 * </pre>
 *
 * <p>设计原则：**任何一步失败都原样返回**，绝不把 xia SQL 自己的流程搞坏。
 * SM4 不在本桥接层实现（用 BurpCrypto 的明文页签测 SM4 目标即可）。</p>
 */
public final class CatBridge {

    private static final String ENV_CONFIG = "burpcrypto.config";
    private static long lastLoad;
    private static File cachedFile;
    private static Config cached;
    private static boolean announced;

    private CatBridge() {
    }

    /* ==================================================================
     *  对外入口（被 xia SQL 的 BurpExtender 调用）
     * ================================================================== */

    /**
     * 求出"这个请求解密后可用的完整报文"：Header 原样、Body 换成明文。
     *
     * <p>返回 null 表示"不需要/解不开"，调用方应继续用原报文。
     * 注意返回的是**整条请求**（请求行 + 头 + 空行 + 明文 Body），
     * 可以直接交给 helpers.analyzeRequest(...) 解析参数。</p>
     */
    public static byte[] decryptRequest(IHttpRequestResponse rr, IExtensionHelpers helpers,
                                        IBurpExtenderCallbacks callbacks) {
        try {
            if (rr == null || rr.getRequest() == null) {
                return null;
            }
            Holder.helpers = helpers;
            String url = fullUrl(rr);
            Profile p = resolveProfile(url);
            if (p == null) {
                return null;
            }
            byte[] body = bodyOf(rr.getRequest(), helpers);
            if (body.length == 0 || !p.looksCipher(body)) {
                return null;
            }
            byte[] plain = p.decrypt(body);
            if (plain == null || plain.length == 0 || !p.isText(plain)) {
                return null;
            }
            announce(callbacks, p);
            byte[] rebuilt = helpers.buildHttpMessage(
                    helpers.analyzeRequest(rr.getRequest()).getHeaders(), plain);
            return rebuilt;
        } catch (Throwable e) {
            report(callbacks, "入口解密失败", e);
            return null;
        }
    }

    /**
     * 生成"请求体已换成明文"的快照（Burp 原生的临时文件对象，UI 里能直接看到明文）。
     *
     * <p>先让 Burp 自己造快照，再 setRequest 换成明文副本 —— 这样类型一定是 Burp 自家的，
     * 不依赖它对自定义 IHttpRequestResponse 实现的兼容性。原报文一个字都不动。</p>
     */
    public static IHttpRequestResponsePersisted snapshot(IBurpExtenderCallbacks callbacks,
                                                         IHttpRequestResponse original,
                                                         byte[] plainReq) {
        IHttpRequestResponsePersisted snap = callbacks.saveBuffersToTempFiles(original);
        if (plainReq != null) {
            try {
                snap.setRequest(plainReq);       // plainReq 是完整报文（头 + 明文 Body）
            } catch (Throwable ignore) {
                // 换快照失败不影响扫描逻辑
            }
        }
        return snap;
    }

    /** 发出前把明文 Body 加密（已是密文则不动），然后交给 Burp 发送。 */
    public static IHttpRequestResponse send(IBurpExtenderCallbacks callbacks, IHttpService service,
                                            IHttpRequestResponse base, byte[] request) {
        try {
            byte[] outgoing = request;
            if (request != null) {
                Holder.helpers = callbacks.getHelpers();
                Profile p = resolveProfile(fullUrl(base));
                if (p != null) {
                    byte[] body = bodyOf(request, callbacks.getHelpers());
                    byte[] enc = encryptWithMode(fullUrl(base), body);
                    if (enc != null && enc.length > 0) {
                        outgoing = callbacks.getHelpers().buildHttpMessage(
                                callbacks.getHelpers().analyzeRequest(request).getHeaders(), enc);
                    }
                }
            }
            return callbacks.makeHttpRequest(service, outgoing);
        } catch (Throwable ignore) {
            return callbacks.makeHttpRequest(service, request);
        }
    }

    /**
     * 纯函数版：按 URL 命中的方案解密一段 Body；不命中/解不开返回 null。
     *
     * <p>给测试和"二次开发自己的插件"用，不涉及 Burp 对象。</p>
     */
    public static byte[] decryptBody(String url, byte[] body) {
        try {
            if (body == null || body.length == 0) {
                return null;
            }
            Profile p = resolveProfile(url);
            if (p == null || !p.looksCipher(body)) {
                return null;
            }
            byte[] plain = p.decrypt(body);
            return plain != null && p.isText(plain) ? plain : null;
        } catch (Throwable e) {
            return null;
        }
    }

    /** 纯函数版：按 URL 命中的方案加密一段明文 Body；不命中/已是密文返回 null（自动模式）。 */
    public static byte[] encryptBody(String url, byte[] body) {
        return encryptWithMode(url, body);
    }

    /** 按"发包加密"模式加密：AUTO=明文才加密 / FORCE=总是加密 / OFF=不加密。 */
    public static byte[] encryptWithMode(String url, byte[] body) {
        try {
            if (body == null || body.length == 0) {
                return null;
            }
            String mode = encryptMode();
            if (ENC_OFF.equalsIgnoreCase(mode)) {
                return null;
            }
            Profile p = resolveProfile(url);
            if (p == null) {
                return null;
            }
            if (!ENC_FORCE.equalsIgnoreCase(mode) && p.looksCipher(body)) {
                return null;                 // 自动模式：已经是密文就不动
            }
            return p.encrypt(body);
        } catch (Throwable e) {
            return null;
        }
    }

    /* ==================================================================
     *  报文工具
     * ================================================================== */

    private static String urlOf(IHttpRequestResponse rr) {
        try {
            if (rr.getHttpService() == null || rr.getRequest() == null) {
                return "";
            }
            String proto = rr.getHttpService().getProtocol();
            return proto + "://" + rr.getHttpService().getHost() + ":" + rr.getHttpService().getPort();
        } catch (Throwable ignore) {
            return "";
        }
    }

    private static String fullUrl(IHttpRequestResponse rr) {
        try {
            IExtensionHelpers h = Holder.helpers;
            if (h != null) {
                return h.analyzeRequest(rr).getUrl().toString();
            }
        } catch (Throwable ignore) {
            // 退回 host 级别
        }
        return urlOf(rr);
    }

    private static byte[] bodyOf(byte[] request, IExtensionHelpers helpers) {
        try {
            int off = helpers.analyzeRequest(request).getBodyOffset();
            if (off < 0 || off > request.length) {
                return new byte[0];
            }
            byte[] out = new byte[request.length - off];
            System.arraycopy(request, off, out, 0, out.length);
            return out;
        } catch (Throwable ignore) {
            int idx = indexOf(request, new byte[]{'\r', '\n', '\r', '\n'});
            if (idx < 0) {
                return new byte[0];
            }
            byte[] out = new byte[request.length - idx - 4];
            System.arraycopy(request, idx + 4, out, 0, out.length);
            return out;
        }
    }

    private static int indexOf(byte[] data, byte[] pat) {
        outer:
        for (int i = 0; i + pat.length <= data.length; i++) {
            for (int j = 0; j < pat.length; j++) {
                if (data[i + j] != pat[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** 供 urlOf 之外的地方拿到 helpers（xia SQL 里随处可得，这里只是为了少改签名）。 */
    private static final class Holder {
        static IExtensionHelpers helpers;
    }

    /* ==================================================================
     *  配置与匹配
     * ================================================================== */

    /* ==================== 方案选择（界面上的"加密方案"下拉框） ==================== */

    /** 下拉框第一个选项：跟随规则自动匹配 */
    public static final String SEL_AUTO = "AUTO";
    /** 下拉框第二个选项：不处理（纯明文，不加密） */
    public static final String SEL_OFF = "OFF";

    private static final String SEL_FILE = "xia_bridge.ini";

    /** 界面上可选的方案列表：{id, 显示名}。 */
    public static List<String[]> profilesForUi() {
        List<String[]> out = new ArrayList<>();
        out.add(new String[]{SEL_AUTO, "跟随规则（按 URL 自动匹配）"});
        out.add(new String[]{SEL_OFF, "不处理（保持明文，不加密）"});
        Config cfg = config();
        if (cfg != null) {
            for (Profile p : cfg.profiles) {
                out.add(new String[]{p.id,
                        p.name + "  [" + p.cipher + "]" + (p.enabled ? "" : "  (已停用)")});
            }
        }
        return out;
    }

    /** 发包加密模式：自动（明文加密、密文跳过） */
    public static final String ENC_AUTO = "AUTO";
    /** 发包加密模式：总是加密（不做密文判定，用于 payload 恰好被判成密文的极少数情况） */
    public static final String ENC_FORCE = "FORCE";
    /** 发包加密模式：不加密（只解密模板，发包保持明文） */
    public static final String ENC_OFF = "OFF";

    /** 当前选中的方案 id（AUTO / OFF / 具体方案 id）。 */
    public static String selectedProfileId() {
        String v = sel().get("profile");
        return v == null || v.isBlank() ? SEL_AUTO : v;
    }

    /** 当前发包加密模式。 */
    public static String encryptMode() {
        String v = sel().get("encrypt");
        return v == null || v.isBlank() ? ENC_AUTO : v.trim().toUpperCase();
    }

    /** 界面切换方案时调用。 */
    public static void selectProfileId(String id) {
        Map<String, String> kv = sel();
        kv.put("profile", id == null || id.isBlank() ? SEL_AUTO : id.trim());
        saveSel(kv);
    }

    /** 界面切换"发包加密"时调用。 */
    public static void selectEncryptMode(String mode) {
        Map<String, String> kv = sel();
        kv.put("encrypt", mode == null || mode.isBlank() ? ENC_AUTO : mode.trim().toUpperCase());
        saveSel(kv);
    }

    private static Map<String, String> sel() {
        Map<String, String> kv = new LinkedHashMap<>();
        try {
            File f = selFile();
            if (f.isFile()) {
                for (String line : Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) {
                        continue;
                    }
                    int eq = t.indexOf('=');
                    if (eq > 0) {
                        kv.put(t.substring(0, eq).trim().toLowerCase(), t.substring(eq + 1).trim());
                    }
                }
            }
        } catch (Throwable ignore) {
            // 读失败就用默认值
        }
        return kv;
    }

    private static void saveSel(Map<String, String> kv) {
        try {
            File f = selFile();
            File dir = f.getParentFile();
            if (dir != null && !dir.isDirectory()) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
            }
            StringBuilder sb = new StringBuilder();
            sb.append("# xia SQL × BurpCrypto 的本地选择\n");
            sb.append("# profile: AUTO=跟随规则, OFF=不处理, 或具体方案 id\n");
            sb.append("# encrypt: AUTO=自动加密, FORCE=总是加密, OFF=不加密\n");
            sb.append("profile=").append(kv.getOrDefault("profile", SEL_AUTO)).append('\n');
            sb.append("encrypt=").append(kv.getOrDefault("encrypt", ENC_AUTO)).append('\n');
            Files.write(f.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
            try {
                Files.setPosixFilePermissions(f.toPath(),
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            } catch (Throwable ignore) {
                // Windows 忽略
            }
        } catch (Throwable ignore) {
            // 写失败退化为默认
        }
    }

    /** 界面提示用：当前读取的配置文件路径。 */
    public static String configPathForUi() {
        return configFile().getAbsolutePath();
    }

    private static File selFile() {
        return new File(configFile().getParentFile(), SEL_FILE);
    }

    /** 解析出这次要用的方案：强制选择优先，其次按规则匹配；脚本方案一律跳过。 */
    private static Profile resolveProfile(String url) {
        Config cfg = config();
        if (cfg == null || !cfg.master) {
            return null;
        }
        String sel = selectedProfileId();
        if (SEL_OFF.equalsIgnoreCase(sel)) {
            return null;
        }
        Profile p;
        if (!SEL_AUTO.equalsIgnoreCase(sel)) {
            p = cfg.profile(sel);
            if (p == null || !p.enabled) {
                // 选中的方案被删了/停用了 → 退回按规则匹配，避免"突然什么都不做"
                p = match(cfg, url);
            }
        } else {
            p = match(cfg, url);
        }
        if (p != null && !"BUILTIN".equalsIgnoreCase(p.engine)) {
            // 脚本/外部命令方案：桥接层不实现脚本引擎，交回 BurpCryptCat 本体处理
            hintScript();
            return null;
        }
        return p;
    }

    private static void hintScript() {
        if (SCRIPT_HINTED.compareAndSet(false, true)) {
            System.err.println("[BurpCryptCat-Bridge] 命中的方案是脚本/外部命令模式，"
                    + "桥接层只支持内置算法；该方案下请在 BurpCryptCat 的「明文」页签里操作，"
                    + "或改用内置算法方案给 xia SQL 用。");
        }
    }

    private static final java.util.concurrent.atomic.AtomicBoolean SCRIPT_HINTED =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private static Profile match(String url) {
        Config cfg = config();
        if (cfg == null || !cfg.master) {
            return null;
        }
        return match(cfg, url);
    }

    private static Profile match(Config cfg, String url) {
        String host = hostOf(url);
        for (Rule r : cfg.rules) {
            if (!r.enabled || !r.onRequest) {
                continue;
            }
            Profile p = cfg.profile(r.profileId);
            if (p == null || !p.enabled || !p.onRequest) {
                continue;
            }
            if (r.matches(host, url)) {
                return p;
            }
        }
        Profile fb = cfg.profile(cfg.fallback);
        if (fb != null && fb.enabled && fb.onRequest) {
            return fb;
        }
        return null;
    }

    private static String hostOf(String url) {
        if (url == null) {
            return "";
        }
        int s = url.indexOf("://");
        s = s < 0 ? 0 : s + 3;
        int e = url.length();
        for (int i = s; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c == '/' || c == '?' || c == '#') {
                e = i;
                break;
            }
        }
        String auth = url.substring(s, Math.min(e, url.length()));
        int colon = auth.indexOf(':');
        return colon < 0 ? auth : auth.substring(0, colon);
    }

    /** 读配置（按文件 mtime 缓存，改完配置无需重启）。 */
    private static synchronized Config config() {
        File f = configFile();
        try {
            long mtime = f.isFile() ? f.lastModified() : -1;
            if (cached != null && f.equals(cachedFile) && mtime == lastLoad) {
                return cached;
            }
            if (!f.isFile()) {
                return null;
            }
            cached = Config.parse(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
            cachedFile = f;
            lastLoad = mtime;
            return cached;
        } catch (Throwable e) {
            return cached;
        }
    }

    private static File configFile() {
        String override = System.getProperty(ENV_CONFIG, System.getenv("BURPCRYPTO_CONFIG"));
        if (override != null && !override.isBlank()) {
            return new File(override);
        }
        return new File(new File(System.getProperty("user.home", "."), ".BurpCrypto"), "config");
    }

    private static final java.util.concurrent.atomic.AtomicInteger ERRORS =
            new java.util.concurrent.atomic.AtomicInteger();

    private static void report(IBurpExtenderCallbacks callbacks, String what, Throwable t) {
        if (callbacks == null) {
            return;
        }
        int n = ERRORS.incrementAndGet();
        if (n > 5) {
            return;                        // 只报前 5 次，避免刷屏
        }
        try {
            callbacks.printError("[CatBridge] " + what + "：" + t);
            if (n == 5) {
                callbacks.printError("[CatBridge] 同类错误后续不再打印");
            }
        } catch (Throwable ignore) {
            // 忽略
        }
    }

    private static void announce(IBurpExtenderCallbacks callbacks, Profile p) {
        if (announced || callbacks == null) {
            return;
        }
        announced = true;
        try {
            callbacks.printOutput("[CatBridge] 已接入 BurpCryptCat 配置："
                    + configFile().getAbsolutePath() + "，当前命中方案「" + p.name + "」(" + p.cipher + ")");
            callbacks.printOutput("[CatBridge] 规则：请求体在 xia SQL 内显示为明文，发包时自动加密");
        } catch (Throwable ignore) {
            // 忽略
        }
    }

    /* ==================================================================
     *  数据模型
     * ================================================================== */

    private static final class Config {
        boolean master = true;
        String fallback = "";
        final List<Profile> profiles = new ArrayList<>();
        final List<Rule> rules = new ArrayList<>();

        Profile profile(String id) {
            if (id == null || id.isEmpty()) {
                return null;
            }
            for (Profile p : profiles) {
                if (id.equals(p.id)) {
                    return p;
                }
            }
            return null;
        }

        static Config parse(String text) {
            Config c = new Config();
            String section = "";
            Map<String, String> kv = new LinkedHashMap<>();
            for (String raw : text.split("\\R")) {
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) {
                    continue;
                }
                if (line.startsWith("[") && line.endsWith("]")) {
                    flush(c, section, kv);
                    section = line.substring(1, line.length() - 1).trim().toLowerCase();
                    kv.clear();
                    continue;
                }
                int eq = line.indexOf('=');
                if (eq > 0) {
                    kv.put(line.substring(0, eq).trim().toLowerCase(), line.substring(eq + 1));
                }
            }
            flush(c, section, kv);
            return c;
        }

        private static void flush(Config c, String section, Map<String, String> kv) {
            if (kv.isEmpty()) {
                return;
            }
            switch (section) {
                case "global" -> {
                    c.master = bool(kv.get("master"), true);
                    c.fallback = kv.getOrDefault("fallback", "");
                }
                case "profile" -> c.profiles.add(Profile.of(kv));
                case "rule" -> c.rules.add(Rule.of(kv));
                default -> {
                }
            }
        }
    }

    private static final class Rule {
        boolean enabled = true;
        String matchType = "HOST";
        String pattern = "*";
        String profileId = "";
        boolean onRequest = true;
        boolean onResponse = true;

        static Rule of(Map<String, String> kv) {
            Rule r = new Rule();
            r.enabled = bool(kv.get("enabled"), true);
            r.matchType = kv.getOrDefault("matchtype", "HOST").trim().toUpperCase();
            r.pattern = kv.getOrDefault("pattern", "*");
            r.profileId = kv.getOrDefault("profile", "");
            r.onRequest = bool(kv.get("onrequest"), true);
            r.onResponse = bool(kv.get("onresponse"), true);
            return r;
        }

        boolean matches(String host, String url) {
            String p = pattern == null ? "" : pattern.trim();
            if (p.isEmpty()) {
                return false;
            }
            if (p.equals("*")) {
                return true;
            }
            try {
                switch (matchType) {
                    case "URL_REGEX":
                        return Pattern.compile(p, Pattern.CASE_INSENSITIVE).matcher(url).find();
                    case "URL_GLOB":
                        return Pattern.compile(globToRegex(p), Pattern.CASE_INSENSITIVE).matcher(url).matches();
                    default:
                        String h = host.toLowerCase();
                        String lp = p.toLowerCase();
                        if (lp.startsWith("*.")) {
                            return h.endsWith(lp.substring(1)) || h.equals(lp.substring(2));
                        }
                        return h.equals(lp) || h.endsWith("." + lp);
                }
            } catch (Throwable e) {
                return false;
            }
        }

        private static String globToRegex(String p) {
            StringBuilder sb = new StringBuilder("^");
            for (char ch : p.toCharArray()) {
                if (ch == '*') {
                    sb.append(".*");
                } else if (ch == '?') {
                    sb.append('.');
                } else {
                    sb.append(Pattern.quote(String.valueOf(ch)));
                }
            }
            return sb.append('$').toString();
        }
    }

    /* ==================================================================
     *  单个配置方案（加解密）
     * ================================================================== */

    private static final class Profile {
        String id = "";
        String name = "";
        boolean enabled = true;
        String engine = "BUILTIN";
        String cipher = "AES/CBC/PKCS5Padding";
        String key = "";
        String keyFormat = "AUTO";
        String iv = "";
        String ivFormat = "AUTO";
        String ivMode = "AUTO";
        String bodyEncoding = "BASE64";
        String bodyScope = "WHOLE";
        String jsonField = "data";
        String charset = "UTF-8";
        boolean onRequest = true;
        boolean onResponse = true;

        // 解析后的缓存
        private String family, mode, padding;
        private int blockSize, ivLen;
        private boolean aead;

        static Profile of(Map<String, String> kv) {
            Profile p = new Profile();
            p.id = kv.getOrDefault("id", "");
            p.name = kv.getOrDefault("name", "");
            p.enabled = bool(kv.get("enabled"), true);
            p.engine = kv.getOrDefault("engine", "BUILTIN").trim().toUpperCase();
            p.cipher = kv.getOrDefault("cipher", p.cipher);
            p.key = kv.getOrDefault("key", "");
            p.keyFormat = kv.getOrDefault("keyformat", "AUTO").toUpperCase();
            p.iv = kv.getOrDefault("iv", "");
            p.ivFormat = kv.getOrDefault("ivformat", "AUTO").toUpperCase();
            p.ivMode = kv.getOrDefault("ivmode", "AUTO").toUpperCase();
            p.bodyEncoding = kv.getOrDefault("bodyencoding", "BASE64").toUpperCase();
            p.bodyScope = kv.getOrDefault("bodyscope", "WHOLE").toUpperCase();
            p.jsonField = kv.getOrDefault("jsonfield", "data");
            p.charset = kv.getOrDefault("charset", "UTF-8");
            p.onRequest = bool(kv.get("onrequest"), true);
            p.onResponse = bool(kv.get("onresponse"), true);
            p.init();
            return p;
        }

        private void init() {
            String[] parts = cipher.split("/");
            family = parts[0].trim().toUpperCase();
            if (family.equals("3DES") || family.equals("TRIPLEDES")) {
                family = "DESEDE";
            }
            mode = parts.length > 1 ? parts[1].trim().toUpperCase() : "ECB";
            padding = parts.length > 2 ? parts[2].trim().toUpperCase() : "PKCS5PADDING";
            if (padding.equals("PKCS7PADDING")) {
                padding = "PKCS5PADDING";
            }
            switch (family) {
                case "AES" -> {
                    blockSize = 16;
                }
                case "DES", "DESEDE" -> {
                    blockSize = 8;
                }
                case "SM4" -> {
                    blockSize = 16;
                }
                default -> blockSize = 0;
            }
            boolean streamLike = blockSize == 0 || mode.equals("CTR") || mode.equals("CFB")
                    || mode.equals("OFB") || mode.equals("GCM");
            if (streamLike) {
                padding = "NOPADDING";
            }
            aead = mode.equals("GCM");
            ivLen = mode.equals("ECB") || blockSize == 0
                    ? ("CHACHA20".equals(family) ? 12 : 0)
                    : (mode.equals("GCM") ? 12 : blockSize);
        }

        Charset cs() {
            try {
                return Charset.forName(charset);
            } catch (Throwable e) {
                return StandardCharsets.UTF_8;
            }
        }

        /* ---------- 判定 ---------- */

        boolean looksCipher(byte[] body) {
            try {
                if (bodyScope.equals("JSON_FIELD")) {
                    String text = new String(body, cs());
                    String v = jsonGet(text, jsonField);
                    return v != null && !v.isEmpty() && canDecrypt(decRaw(v.getBytes(cs())));
                }
                return canDecrypt(decRaw(body));
            } catch (Throwable e) {
                return false;
            }
        }

        private boolean canDecrypt(byte[] ct) {
            try {
                byte[] plain = crypto(ct, Cipher.DECRYPT_MODE);
                return plain != null && isText(plain);
            } catch (Throwable e) {
                return false;
            }
        }

        /* ---------- 解密 / 加密 ---------- */

        byte[] decrypt(byte[] body) {
            try {
                if (bodyScope.equals("JSON_FIELD")) {
                    String text = new String(body, cs());
                    String v = jsonGet(text, jsonField);
                    if (v == null) {
                        return null;
                    }
                    byte[] plain = crypto(decRaw(v.getBytes(cs())), Cipher.DECRYPT_MODE);
                    if (plain == null) {
                        return null;
                    }
                    String s = jsonSet(text, jsonField, new String(plain, cs()));
                    return s == null ? null : s.getBytes(cs());
                }
                byte[] plain = crypto(decRaw(body), Cipher.DECRYPT_MODE);
                if (plain == null) {
                    return null;
                }
                return plain;
            } catch (Throwable e) {
                return null;
            }
        }

        byte[] encrypt(byte[] body) {
            try {
                if (bodyScope.equals("JSON_FIELD")) {
                    String text = new String(body, cs());
                    String v = jsonGet(text, jsonField);
                    if (v == null) {
                        return null;
                    }
                    byte[] ct = crypto(v.getBytes(cs()), Cipher.ENCRYPT_MODE);
                    if (ct == null) {
                        return null;
                    }
                    String s = jsonSet(text, jsonField,
                            new String(encRaw(ct), StandardCharsets.ISO_8859_1));
                    return s == null ? null : s.getBytes(cs());
                }
                byte[] ct = crypto(body, Cipher.ENCRYPT_MODE);
                if (ct == null) {
                    return null;
                }
                return encRaw(ct);
            } catch (Throwable e) {
                return null;
            }
        }

        /* ---------- 编码层 ---------- */

        private byte[] decRaw(byte[] body) {
            String s = new String(body, cs()).trim();
            switch (bodyEncoding) {
                case "HEX":
                    return hex(s);
                case "RAW":
                    return body;
                default:
                    return b64(s);
            }
        }

        private byte[] encRaw(byte[] ct) {
            switch (bodyEncoding) {
                case "HEX":
                    return toHex(ct).getBytes(StandardCharsets.UTF_8);
                case "RAW":
                    return ct;
                default:
                    return Base64.getEncoder().encodeToString(ct).getBytes(StandardCharsets.UTF_8);
            }
        }

        /* ---------- 真正的加解密 ---------- */

        private byte[] crypto(byte[] data, int op) throws Exception {
            if (data == null || data.length == 0) {
                return null;
            }
            if ("SM4".equals(family)) {
                return null;                     // 桥接层不支持 SM4，交给 BurpCryptCat 本体
            }
            byte[] k = resolveKey();
            if (k == null) {
                return null;
            }
            boolean enc = op == Cipher.ENCRYPT_MODE;
            String jceMode = ivMode;

            if ("PREPENDED".equals(jceMode) || ("AUTO".equals(jceMode) && (iv == null || iv.isBlank()))) {
                if (enc) {
                    byte[] randomIv = new byte[blockSize];
                    new java.security.SecureRandom().nextBytes(randomIv);
                    byte[] ct = doJce(data, k, randomIv, op);
                    if (ct == null) {
                        return null;
                    }
                    byte[] out = new byte[randomIv.length + ct.length];
                    System.arraycopy(randomIv, 0, out, 0, randomIv.length);
                    System.arraycopy(ct, 0, out, randomIv.length, ct.length);
                    return out;
                }
                if (data.length <= blockSize) {
                    return null;
                }
                byte[] head = java.util.Arrays.copyOf(data, blockSize);
                byte[] rest = java.util.Arrays.copyOfRange(data, blockSize, data.length);
                return doJce(rest, k, head, op);
            }

            byte[] ivb = resolveIv();
            if ("AUTO".equals(jceMode) && ivb != null) {
                // 先按固定 IV 解；解不出可读文本再按 IV||CT 解
                byte[] first = doJce(data, k, ivb, op);
                if (!enc && (first == null || !isText(first)) && data.length > blockSize) {
                    byte[] head = java.util.Arrays.copyOf(data, blockSize);
                    byte[] rest = java.util.Arrays.copyOfRange(data, blockSize, data.length);
                    byte[] second = doJce(rest, k, head, op);
                    if (second != null && isText(second)) {
                        return second;
                    }
                }
                return first;
            }
            return doJce(data, k, ivb, op);
        }

        private byte[] doJce(byte[] data, byte[] key, byte[] ivb, int op) {
            try {
                String transformation = transformation();
                Cipher c = Cipher.getInstance(transformation);
                SecretKeySpec ks = new SecretKeySpec(key,
                        "DESEDE".equals(family) ? "DESede" : family);
                boolean needIv = ivLen > 0 && !mode.equals("ECB");
                if (aead) {
                    c.init(op, ks, new javax.crypto.spec.GCMParameterSpec(128, ivb));
                } else if (needIv && ivb != null) {
                    c.init(op, ks, new IvParameterSpec(ivb));
                } else {
                    c.init(op, ks);
                }
                return c.doFinal(data);
            } catch (Throwable e) {
                return null;
            }
        }

        private String transformation() {
            String p = padding;
            if (p.equals("ZEROPADDING")) {
                p = "NOPADDING";
            }
            if ("RC4".equals(family)) {
                return "ARCFOUR";
            }
            if ("CHACHA20".equals(family)) {
                return "ChaCha20";
            }
            return ("DESEDE".equals(family) ? "DESede" : family) + "/" + mode + "/" + p;
        }

        /* ---------- Key / IV ---------- */

        private byte[] resolveKey() {
            int[] allowed = switch (family) {
                case "AES" -> new int[]{16, 24, 32};
                case "DES" -> new int[]{8};
                case "DESEDE" -> new int[]{24};
                case "CHACHA20" -> new int[]{32};
                default -> new int[0];
            };
            return resolve(key, keyFormat, allowed);
        }

        private byte[] resolveIv() {
            if (ivLen <= 0) {
                return null;
            }
            int[] allowed = aead ? new int[]{12, 16} : new int[]{ivLen};
            byte[] out = resolve(iv, ivFormat, allowed);
            return out;
        }

        /** 与 BurpCryptCat 一致：AUTO 时按"算法允许的长度"挑候选解码方式。 */
        private static byte[] resolve(String text, String format, int[] allowed) {
            if (text == null || text.isBlank()) {
                return null;
            }
            String raw = text.trim();
            List<byte[]> cands = new ArrayList<>(3);
            byte[] h = hex(raw);
            if (h != null) {
                cands.add(h);
            }
            byte[] b = b64(raw);
            if (b != null) {
                cands.add(b);
            }
            cands.add(raw.getBytes(StandardCharsets.UTF_8));
            if ("HEX".equals(format)) {
                return h;
            }
            if ("BASE64".equals(format)) {
                return b;
            }
            if ("UTF8".equals(format)) {
                return cands.get(cands.size() - 1);
            }
            if (allowed.length > 0) {
                for (byte[] c : cands) {
                    for (int len : allowed) {
                        if (c.length == len) {
                            return c;
                        }
                    }
                }
            }
            return cands.get(cands.size() - 1);
        }

        /* ---------- 文本工具 ---------- */

        boolean isText(byte[] data) {
            try {
                String s = cs().newDecoder().decode(java.nio.ByteBuffer.wrap(data)).toString().strip();
                if (s.isEmpty()) {
                    return false;
                }
                for (int i = 0; i < s.length(); i++) {
                    char ch = s.charAt(i);
                    if (ch == '\t' || ch == '\r' || ch == '\n') {
                        continue;
                    }
                    if (ch < 0x20 || ch == 0x7f) {
                        return false;
                    }
                }
                return true;
            } catch (Throwable e) {
                return false;
            }
        }
    }

    /* ==================================================================
     *  小工具
     * ================================================================== */

    private static boolean bool(String v, boolean def) {
        if (v == null || v.isBlank()) {
            return def;
        }
        String s = v.trim();
        return s.equalsIgnoreCase("true") || s.equals("1") || s.equalsIgnoreCase("yes");
    }

    private static byte[] b64(String s) {
        try {
            String t = s.replaceAll("\\s", "");
            while (t.endsWith("=")) {
                t = t.substring(0, t.length() - 1);
            }
            if (t.isEmpty() || t.length() % 4 == 1) {
                return null;
            }
            StringBuilder sb = new StringBuilder(t);
            while (sb.length() % 4 != 0) {
                sb.append('=');
            }
            for (int i = 0; i < t.length(); i++) {
                char c = t.charAt(i);
                boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                        || (c >= '0' && c <= '9') || c == '+' || c == '/';
                if (!ok) {
                    return null;
                }
            }
            return Base64.getDecoder().decode(sb.toString());
        } catch (Throwable e) {
            return null;
        }
    }

    private static byte[] hex(String s) {
        try {
            String t = s.replaceAll("[\\s:-]", "");
            if (t.isEmpty() || t.length() % 2 != 0) {
                return null;
            }
            byte[] out = new byte[t.length() / 2];
            for (int i = 0; i < out.length; i++) {
                int hi = Character.digit(t.charAt(i * 2), 16);
                int lo = Character.digit(t.charAt(i * 2 + 1), 16);
                if (hi < 0 || lo < 0) {
                    return null;
                }
                out[i] = (byte) ((hi << 4) | lo);
            }
            return out;
        } catch (Throwable e) {
            return null;
        }
    }

    private static String toHex(byte[] d) {
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte b : d) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /* ---------- JSON 字段（与 BurpCrypto 的 JSON_FIELD 模式对齐） ---------- */

    private static int[] jsonFind(String json, String field) {
        if (json == null || field == null || field.isEmpty()) {
            return null;
        }
        String quoted = "\"" + field + "\"";
        int from = 0;
        while (true) {
            int idx = json.indexOf(quoted, from);
            if (idx < 0) {
                return null;
            }
            int i = idx + quoted.length();
            while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
                i++;
            }
            if (i >= json.length() || json.charAt(i) != ':') {
                from = idx + quoted.length();
                continue;
            }
            i++;
            while (i < json.length() && Character.isWhitespace(json.charAt(i))) {
                i++;
            }
            if (i >= json.length() || json.charAt(i) != '"') {
                from = idx + quoted.length();
                continue;
            }
            int start = i + 1;
            int j = start;
            while (j < json.length()) {
                char c = json.charAt(j);
                if (c == '\\') {
                    j += 2;
                    continue;
                }
                if (c == '"') {
                    return new int[]{start, j};
                }
                j++;
            }
            return null;
        }
    }

    private static String jsonGet(String json, String field) {
        int[] r = jsonFind(json, field);
        return r == null ? null : json.substring(r[0], r[1]);
    }

    private static String jsonSet(String json, String field, String value) {
        int[] r = jsonFind(json, field);
        return r == null ? null : json.substring(0, r[0]) + value + json.substring(r[1]);
    }
}
