package burp.tests;

import burp.config.AppConfig;
import burp.config.ConfigFile;
import burp.config.Profile;
import burp.config.Rule;
import burp.crypto.CipherSpec;
import burp.crypto.Codec;
import burp.crypto.CryptoEngine;
import burp.crypto.CryptoException;
import burp.crypto.KeyMaterial;
import burp.crypto.Sm4;
import burp.transform.BodyTransformer;
import burp.transform.CryptoService;
import burp.transform.JsonField;
import burp.transform.PlainTextFormatter;
import burp.transform.MessageTransform;
import burp.transform.PlaintextLog;
import burp.transform.TargetResolver;
import burp.transform.TransformResult;

import java.nio.charset.StandardCharsets;

/**
 * 纯 JVM 单元测试（不依赖 Burp），覆盖：算法向量、Key/IV 解析、编码、规则匹配、
 * 配置序列化、Body 转换的幂等性与容错。
 *
 * <p>运行方式见 build.sh / tools/run-tests.sh，退出码非 0 表示有失败。</p>
 */
public final class BurpCryptoTests {

    private static int passed;
    private static int failed;

    public static void main(String[] args) {
        sm4Vector();
        aesCbcVector();
        sm4CbcVector();
        keyParsing();
        ivValidation();
        ivPrependMode();
        ivAutoModeRealWorld();
        zeroPadding();
        noPaddingAlignment();
        iniRoundTrip();
        configFilePersistence();
        ruleMatching();
        resolverPriority();
        allToolsSwitch();
        scriptEngine();
        transformIdempotence();
        transformJsonField();
        transformHexEncoding();
        wrongKeyDoesNotCorrupt();
        serviceLogging();
        jsonFieldEditor();
        cipherSpecParsing();
        plainTextFormatting();

        System.out.println();
        System.out.println("=====================================");
        System.out.printf("通过 %d 项，失败 %d 项%n", passed, failed);
        System.out.println("=====================================");
        if (failed > 0) {
            System.exit(1);
        }
    }

    /* ==================== 算法向量 ==================== */

    private static void sm4Vector() {
        try {
            byte[] key = Codec.fromHex("0123456789abcdeffedcba9876543210");
            byte[] plain = Codec.fromHex("0123456789abcdeffedcba9876543210");
            int[] rk = Sm4.expandKey(key);
            byte[] ct = new byte[16];
            Sm4.encryptBlock(rk, plain, 0, ct, 0);
            eq("SM4 单分组向量（GB/T 32907）", "681edf34d206965e86b3e94f536e4246", Codec.toHex(ct));
            byte[] back = new byte[16];
            Sm4.decryptBlock(rk, ct, 0, back, 0);
            eq("SM4 解密还原", Codec.toHex(plain), Codec.toHex(back));
        } catch (Exception e) {
            fail("SM4 向量", e);
        }
    }

    private static void aesCbcVector() {
        try {
            CryptoEngine e = engine("AES/CBC/PKCS5Padding", "0123456789abcdef", "1234567890123456");
            byte[] ct = e.encrypt("{\"a\":1}".getBytes(StandardCharsets.UTF_8));
            // openssl: printf '{"a":1}' | openssl enc -aes-128-cbc -K 3031... -iv 3132...
            eq("AES/CBC/PKCS5Padding 与 openssl 一致", "fa05130928cf856b2ead7f9d7a50cf30", Codec.toHex(ct));
            eq("AES 解密还原", "{\"a\":1}", new String(e.decrypt(ct), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("AES 向量", e);
        }
    }

    private static void sm4CbcVector() {
        try {
            CryptoEngine e = CryptoEngine.create("SM4/CBC/PKCS5Padding",
                    "0123456789abcdeffedcba9876543210", KeyMaterial.Format.HEX,
                    "000102030405060708090a0b0c0d0e0f", KeyMaterial.Format.HEX,
                    CryptoEngine.IvMode.FIXED, "UTF-8");
            byte[] ct = e.encrypt("{\"a\":1,\"b\":\"test-1234\"}".getBytes(StandardCharsets.UTF_8));
            // openssl: printf '{"a":1,"b":"test-1234"}' | openssl enc -sm4-cbc -K 0123... -iv 0001...
            eq("SM4/CBC 与 openssl 一致",
                    "OWh3XuZAwdfNuj/Ly6rDj/ovm7XAPI5YiYPcJ1ricNM=", Codec.toBase64(ct));
        } catch (Exception e) {
            fail("SM4-CBC 向量", e);
        }
    }

    /* ==================== Key / IV 解析 ==================== */

    private static void keyParsing() {
        try {
            CipherSpec aes = CipherSpec.of("AES/CBC/PKCS5Padding");
            // "1234567890123456" 既是 16 位口令、也"像" 8 字节 hex：AUTO 必须按长度选中 16 字节
            byte[] k = KeyMaterial.key("1234567890123456", KeyMaterial.Format.AUTO, aes);
            eq("AUTO 优先按算法长度识别 16 位口令", 16, k.length);
            eq("AUTO 口令内容正确", "1234567890123456", new String(k, StandardCharsets.UTF_8));

            byte[] hex = KeyMaterial.key("30313233343536373839616263646566",
                    KeyMaterial.Format.AUTO, aes);
            eq("AUTO 识别 32 位 hex 为 16 字节", 16, hex.length);

            byte[] forced = KeyMaterial.key("30313233343536373839616263646566",
                    KeyMaterial.Format.HEX, aes);
            eq("显式 HEX 解析 16 字节", 16, forced.length);
            eq("显式 HEX 内容", "0123456789abcdef", new String(forced, StandardCharsets.UTF_8));

            try {
                KeyMaterial.key("1234", KeyMaterial.Format.UTF8, aes);
                fail("短密钥应当报错", null);
            } catch (CryptoException ex) {
                ok("短密钥报错信息可读：" + ex.getMessage());
            }
        } catch (Exception e) {
            fail("Key 解析", e);
        }
    }

    private static void ivValidation() {
        try {
            CipherSpec aes = CipherSpec.of("AES/CBC/PKCS5Padding");
            try {
                KeyMaterial.iv("", KeyMaterial.Format.AUTO, aes);
                fail("CBC 缺 IV 应当报错", null);
            } catch (CryptoException ex) {
                ok("CBC 缺 IV 报错：" + ex.getMessage());
            }
            byte[] iv = KeyMaterial.iv("00112233445566778899aabbccddeeff",
                    KeyMaterial.Format.AUTO, aes);
            eq("HEX IV 解析 16 字节", 16, iv.length);

            CipherSpec ecb = CipherSpec.of("AES/ECB/PKCS5Padding");
            eq("ECB 不需要 IV", null, KeyMaterial.iv("whatever", KeyMaterial.Format.AUTO, ecb));
        } catch (Exception e) {
            fail("IV 校验", e);
        }
    }

    private static void ivPrependMode() {
        try {
            CryptoEngine e = CryptoEngine.create("AES/CBC/PKCS5Padding", "0123456789abcdef",
                    KeyMaterial.Format.UTF8, "", KeyMaterial.Format.AUTO,
                    CryptoEngine.IvMode.PREPENDED, "UTF-8");
            String text = "每包随机 IV 的场景";
            byte[] ct1 = e.encrypt(text.getBytes(StandardCharsets.UTF_8));
            byte[] ct2 = e.encrypt(text.getBytes(StandardCharsets.UTF_8));
            eq("前置 IV 模式：两次密文不同（IV 随机）", true, !Codec.toHex(ct1).equals(Codec.toHex(ct2)));
            eq("前置 IV 模式：能解回原文", text, new String(e.decrypt(ct1), StandardCharsets.UTF_8));
            eq("前置 IV 模式：另一份也能解", text, new String(e.decrypt(ct2), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("前置 IV 模式", e);
        }
    }

    /**
     * 真实样本回归（广东移动小程序 / 微信 api 加密风格）：
     * 报文体 = base64( IV(16B 随机) || AES-128-CBC/PKCS7(明文, key, IV) )，
     * 配置里若填了固定 IV，只有第一个分组会乱 —— 这里用真实密文钉死这个行为。
     */
    private static void ivAutoModeRealWorld() {
        try {
            ivAutoModeRealWorld0();
        } catch (Exception e) {
            fail("真实样本（IV 前置）", e);
        }
    }

    private static void ivAutoModeRealWorld0() throws Exception {
        String ct = "mFVkMTwQoDQQ5w355H/7DpUMXf4FFwWVfk+A2k1161ExZpgzaEJHxwNgBTT3+wOn2A/chTqBm0OjXHsAYRAA"
                + "x7i23jyMs1/yMp7yJgb4LZ1Cx7QpFTlizjkWWZF01w/Rv+jPLR7J2gkvVk8MDA0bTIwdgEqRVR1n2LZOYvXkbGr"
                + "DqinuxQbZItUiXB4/eaMu3Xu49PORXD8FCBbCcKtXM1Wwcs5nSbqcGmPGPtVsv/Y=";
        String keyB64 = "ysIEuRgXG/SMp4HqZL1BEw=";

        // ① 固定 IV（用户当时的配置）：只解出"前面一段乱码 + 后面正常 JSON"
        Profile fixed = new Profile("t", "固定 IV");
        fixed.cipher = "AES/CBC/PKCS5Padding";
        fixed.key = keyB64;
        fixed.keyFormat = KeyMaterial.Format.BASE64;
        fixed.iv = "63cef27c4a68b8f4";
        fixed.ivFormat = KeyMaterial.Format.UTF8;
        fixed.ivMode = CryptoEngine.IvMode.FIXED;
        TransformResult bad = BodyTransformer.decrypt(fixed, ct.getBytes(StandardCharsets.UTF_8));
        eq("固定 IV：判定为解不出可读文本（不乱改报文）", TransformResult.Kind.SKIPPED, bad.kind);
        String lenient = new String(fixed.toEngine().decrypt(Codec.fromBase64(ct)),
                StandardCharsets.UTF_8);
        eq("固定 IV：首 16 字节确实是乱码（复现用户现象）", true,
                !lenient.startsWith("{") && lenient.contains("\"custintonetwork\""));

        // ② AUTO（默认）：自动识别出"密文前置了 IV"
        Profile auto = new Profile("t", "自动");
        auto.cipher = fixed.cipher;
        auto.key = keyB64;
        auto.keyFormat = KeyMaterial.Format.BASE64;
        auto.iv = "63cef27c4a68b8f4";
        auto.ivFormat = KeyMaterial.Format.UTF8;
        auto.ivMode = CryptoEngine.IvMode.AUTO;
        TransformResult good = BodyTransformer.decrypt(auto, ct.getBytes(StandardCharsets.UTF_8));
        eq("自动 IV：成功解密", true, good.changed());
        String json = new String(good.body, StandardCharsets.UTF_8);
        eq("自动 IV：明文是完整 JSON", true, json.startsWith("{\"result\""));
        eq("自动 IV：内容正确", true, json.contains("\"age\":\"21\""));
        eq("自动 IV：没有残留乱码", true, json.contains("custintonetwork"));

        // ③ 显式的 IV||CT 模式同样可用
        Profile pre = new Profile("t", "前置 IV");
        pre.cipher = fixed.cipher;
        pre.key = keyB64;
        pre.keyFormat = KeyMaterial.Format.BASE64;
        pre.iv = "";
        pre.ivMode = CryptoEngine.IvMode.PREPENDED;
        TransformResult pre1 = BodyTransformer.decrypt(pre, ct.getBytes(StandardCharsets.UTF_8));
        eq("IV||CT 模式：同样能解出 JSON", true,
                new String(pre1.body, StandardCharsets.UTF_8).startsWith("{\"result\""));

        // ④ AUTO 加密一侧：有固定 IV 就用固定 IV（可被同样配置解回）
        TransformResult enc = BodyTransformer.encrypt(auto, "{\"a\":1}".getBytes(StandardCharsets.UTF_8));
        eq("自动 IV：加密后可自行解回", "{\"a\":1}",
                new String(auto.toEngine().decrypt(Codec.fromBase64(
                        new String(enc.body, StandardCharsets.UTF_8))), StandardCharsets.UTF_8));
    }

    private static void zeroPadding() {
        try {
            CryptoEngine e = engine("AES/CBC/ZeroPadding", "0123456789abcdef", "1234567890123456");
            byte[] ct = e.encrypt("hello".getBytes(StandardCharsets.UTF_8));
            eq("ZeroPadding 分组对齐", 0, ct.length % 16);
            eq("ZeroPadding 还原", "hello", new String(e.decrypt(ct), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("ZeroPadding", e);
        }
    }

    private static void noPaddingAlignment() {
        try {
            CryptoEngine e = engine("AES/CBC/NoPadding", "0123456789abcdef", "1234567890123456");
            try {
                e.encrypt("abc".getBytes(StandardCharsets.UTF_8));
                fail("NoPadding 未对齐应报错", null);
            } catch (CryptoException ex) {
                ok("NoPadding 对齐报错：" + ex.getMessage());
            }
            byte[] ct = e.encrypt("0123456789abcdef".getBytes(StandardCharsets.UTF_8));
            eq("NoPadding 对齐时可加解密", "0123456789abcdef",
                    new String(e.decrypt(ct), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("NoPadding", e);
        }
    }

    /* ==================== 配置 ==================== */

    private static void iniRoundTrip() {
        AppConfig cfg = AppConfig.defaults();
        Profile p = new Profile("p1", "测试 方案");
        p.cipher = "SM4/CBC/PKCS5Padding";
        p.key = "0123456789abcdeffedcba9876543210";
        p.keyFormat = KeyMaterial.Format.HEX;
        p.iv = "000102030405060708090a0b0c0d0e0f";
        p.ivFormat = KeyMaterial.Format.HEX;
        p.bodyEncoding = Profile.BodyEncoding.HEX;
        p.bodyScope = Profile.BodyScope.JSON_FIELD;
        p.jsonField = "payload";
        p.comment = "多行\n注释=带等号";
        cfg.profiles.add(p);
        cfg.rules.add(new Rule("p1", Rule.MatchType.URL_REGEX, "https://api\\.example\\.com/.*"));
        cfg.fallbackProfileId = "p1";
        cfg.logLimit = 321;
        cfg.proxyEnabled = true;
        cfg.proxyReencryptRequest = false;
        cfg.proxyReencryptResponse = true;
        cfg.tools.remove(AppConfig.ToolGroup.INTRUDER);

        AppConfig back = AppConfig.fromIni(cfg.toIni());
        eq("INI：方案数量", cfg.profiles.size(), back.profiles.size());
        Profile bp = back.profile("p1");
        eq("INI：算法", p.cipher, bp.cipher);
        eq("INI：Key", p.key, bp.key);
        eq("INI：Key 格式", p.keyFormat, bp.keyFormat);
        eq("INI：IV 模式", p.ivMode, bp.ivMode);
        eq("INI：编码", p.bodyEncoding, bp.bodyEncoding);
        eq("INI：范围", p.bodyScope, bp.bodyScope);
        eq("INI：字段名", p.jsonField, bp.jsonField);
        eq("INI：多行注释转义", p.comment, bp.comment);
        eq("INI：规则数", cfg.rules.size(), back.rules.size());
        eq("INI：规则正则", cfg.rules.get(1).pattern, back.rules.get(1).pattern);
        eq("INI：兜底方案", "p1", back.fallbackProfileId);
        eq("INI：日志条数", 321, back.logLimit);
        eq("INI：Proxy 参与开关", true, back.proxyEnabled);
        eq("INI：请求回写加密开关", false, back.proxyReencryptRequest);
        eq("INI：响应回写加密开关", true, back.proxyReencryptResponse);
        eq("INI：工具集合", false, back.toolEnabled(AppConfig.ToolGroup.INTRUDER));
        eq("INI：空配置回退默认", 1, AppConfig.fromIni("").profiles.size());
    }

    private static void configFilePersistence() {
        try {
            java.nio.file.Path tmp = java.nio.file.Files.createTempDirectory("burpcrypto-cfg");
            java.io.File dir = tmp.resolve(".BurpCrypto").toFile();
            java.io.File file = ConfigFile.fileIn(dir);
            eq("配置文件名为 config", "config", file.getName());
            eq("默认目录以 .BurpCrypto 结尾", true,
                    ConfigFile.defaultDir().getPath().endsWith(".BurpCrypto"));

            AppConfig cfg = AppConfig.defaults();
            String text = ConfigFile.withHeader(cfg.toIni(), file);
            ConfigFile.write(file, text);
            eq("写入后文件存在", true, ConfigFile.exists(file));
            eq("没有残留 .tmp", false, new java.io.File(dir, "config.tmp").exists());
            eq("文件头含路径", true, ConfigFile.read(file).contains(file.getAbsolutePath()));

            AppConfig back = AppConfig.fromIni(ConfigFile.read(file));
            eq("带文件头也能解析：方案数", cfg.profiles.size(), back.profiles.size());
            eq("带文件头也能解析：规则数", cfg.rules.size(), back.rules.size());

            // 二次写入：旧内容进 config.bak
            AppConfig changed = AppConfig.fromIni(text);
            changed.logLimit = 4321;
            ConfigFile.write(file, ConfigFile.withHeader(changed.toIni(), file));
            eq("生成备份 config.bak", true, ConfigFile.backupOf(file).isFile());
            eq("备份里是旧内容", 1000,
                    AppConfig.fromIni(ConfigFile.read(ConfigFile.backupOf(file))).logLimit);

            // 目录自动创建 + 覆盖写
            java.io.File deep = tmp.resolve("a/b/c").toFile();
            java.io.File deepFile = ConfigFile.fileIn(deep);
            ConfigFile.write(deepFile, AppConfig.defaults().toIni());
            eq("多级目录自动创建", true, ConfigFile.exists(deepFile));
            ConfigFile.write(deepFile, AppConfig.defaults().toIni());
            eq("覆盖写成功", true, ConfigFile.exists(deepFile));
        } catch (Exception e) {
            fail("配置文件读写", e);
        }
    }

    private static void ruleMatching() {
        Rule host = new Rule("p", Rule.MatchType.HOST, "*.example.com");
        eq("Host 通配：a.example.com", true, host.matches("a.example.com", "https://a.example.com/x"));
        eq("Host 通配：example.com 本身", true, host.matches("example.com", "https://example.com/"));
        eq("Host 通配：不误伤", false, host.matches("badexample.com", "https://badexample.com/"));

        Rule glob = new Rule("p", Rule.MatchType.URL_GLOB, "https://api.example.com/gw/*");
        eq("URL 通配命中", true, glob.matches("api.example.com", "https://api.example.com/gw/login"));
        eq("URL 通配不命中", false, glob.matches("api.example.com", "https://api.example.com/other"));

        Rule regex = new Rule("p", Rule.MatchType.URL_REGEX, "https://[^/]+/api/v\\d+/");
        eq("URL 正则命中", true, regex.matches("x", "https://x/api/v2/user"));
        eq("URL 正则不命中", false, regex.matches("x", "https://x/api/user"));

        Rule all = new Rule("p", Rule.MatchType.HOST, "*");
        eq("星号匹配全部", true, all.matches("anything", "https://anything/"));

        eq("hostOf 去端口", "a.com", TargetResolver.hostOf("https://a.com:8443/x?y=1"));
        eq("hostOf 无端口", "a.com", TargetResolver.hostOf("https://a.com/x"));
    }

    private static void resolverPriority() {
        AppConfig cfg = AppConfig.defaults();
        cfg.masterEnabled = true;
        Profile p1 = cfg.profiles.get(0);
        Profile p2 = p1.copy();
        p2.id = "p2";
        p2.name = "第二套";
        cfg.profiles.add(p2);

        cfg.rules.clear();
        cfg.rules.add(new Rule(p2.id, Rule.MatchType.HOST, "special.com"));
        cfg.rules.add(new Rule(p1.id, Rule.MatchType.HOST, "*"));
        cfg.fallbackProfileId = "";

        TargetResolver.Hit hit = TargetResolver.resolve(cfg, AppConfig.ToolGroup.PROXY,
                "https://special.com/api", true);
        eq("规则优先：命中第一条", p2.id, hit.profile.id);
        eq("规则命中来源", "规则 special.com", hit.source());

        hit = TargetResolver.resolve(cfg, AppConfig.ToolGroup.PROXY, "https://other.com/api", true);
        eq("规则兜底：命中通配规则", p1.id, hit.profile.id);

        cfg.masterEnabled = false;
        eq("总开关关闭则不解析", null,
                TargetResolver.resolve(cfg, AppConfig.ToolGroup.PROXY, "https://other.com/", true));
        cfg.masterEnabled = true;

        cfg.tools.remove(AppConfig.ToolGroup.REPEATER);
        eq("工具未勾选则不解析", null,
                TargetResolver.resolve(cfg, AppConfig.ToolGroup.REPEATER, "https://other.com/", true));
        cfg.tools.add(AppConfig.ToolGroup.REPEATER);

        cfg.rules.clear();
        cfg.fallbackProfileId = p2.id;
        hit = TargetResolver.resolve(cfg, AppConfig.ToolGroup.INTRUDER, "https://x.com/", false);
        eq("无规则时走兜底方案", p2.id, hit.profile.id);
        eq("兜底来源标注", true, hit.fallback);

        cfg.fallbackProfileId = "";
        eq("无规则无兜底则不处理", null,
                TargetResolver.resolve(cfg, AppConfig.ToolGroup.INTRUDER, "https://x.com/", false));
    }

    private static void allToolsSwitch() {
        AppConfig cfg = AppConfig.defaults();
        eq("默认只对 3 个工具生效", 3, cfg.tools.size());
        eq("默认不含其它插件", false, cfg.toolEnabled(AppConfig.ToolGroup.OTHER));
        eq("默认 allTools=false", false, cfg.allToolsEnabled());

        cfg.setAllTools(true);
        eq("顶层开：覆盖 4 组工具", 4, cfg.tools.size());
        eq("顶层开：其它插件生效", true, cfg.toolEnabled(AppConfig.ToolGroup.OTHER));
        eq("顶层开：allTools=true", true, cfg.allToolsEnabled());

        AppConfig back = AppConfig.fromIni(cfg.toIni());
        eq("INI 往返：全部工具保留", true, back.allToolsEnabled());
        eq("INI 往返：其它插件保留", true, back.toolEnabled(AppConfig.ToolGroup.OTHER));

        // 手写 tools=ALL 的简写也要认（空配置会回退默认，所以带上一个方案段）
        String ini = cfg.toIni().replaceFirst("tools=[^\n]*", "tools=ALL");
        AppConfig all = AppConfig.fromIni(ini);
        eq("INI 语法 tools=ALL", true, all.allToolsEnabled());

        cfg.setAllTools(false);
        eq("顶层关：回到 3 个工具", 3, cfg.tools.size());
        eq("顶层关：其它插件关闭", false, cfg.toolEnabled(AppConfig.ToolGroup.OTHER));

        // 顶层开关与规则解析联动：开→命中、关→不命中
        AppConfig cfg2 = AppConfig.defaults();
        cfg2.rules.clear();
        cfg2.rules.add(new Rule(cfg2.profiles.get(0).id, Rule.MatchType.HOST, "*"));
        cfg2.tools.clear();
        eq("未勾其它插件：EXTENSIONS 请求不处理", null,
                TargetResolver.resolve(cfg2, AppConfig.ToolGroup.OTHER, "https://x.com/", true));
        cfg2.setAllTools(true);
        eq("勾上顶层：EXTENSIONS 请求处理", true,
                TargetResolver.resolve(cfg2, AppConfig.ToolGroup.OTHER, "https://x.com/", true) != null);
    }

    /**
     * 四个脚本接口：JS 脚本 + 外部命令，覆盖"解密→注入→加密"和"脚本未实现/报错时保持原样"。
     */
    private static void scriptEngine() {
        try {
            java.nio.file.Path tmp = java.nio.file.Files.createTempDirectory("burpcrypto-script");
            // ---------- ① JS：四个钩子 ----------
            java.io.File js = tmp.resolve("demo.js").toFile();
            java.nio.file.Files.writeString(js.toPath(), """
                    function clientToBurp(ctx) { return crypto.aesCbcDecrypt(KEY, IV, ctx.body); }
                    function burpToServer(ctx) { return crypto.aesCbcEncrypt(KEY, IV, ctx.body); }
                    function serverToBurp(ctx) { return crypto.aesCbcDecrypt(KEY, IV, ctx.body); }
                    function burpToClient(ctx) { return crypto.aesCbcEncrypt(KEY, IV, ctx.body); }
                    var KEY = "0123456789abcdef";
                    var IV  = "1234567890123456";
                    """);

            Profile p = new Profile("js", "JS 脚本方案");
            p.engine = Profile.Engine.SCRIPT_JS;
            p.scriptPath = js.getAbsolutePath();
            p.charset = "UTF-8";

            eq("脚本：自检通过", null, p.validate());
            eq("脚本：识别出 4 个钩子", 4, burp.script.JsScriptRunner.hooksOf(js).size());

            byte[] plain = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);
            var enc = MessageTransform.apply(p, burp.script.ScriptStage.BURP_TO_SERVER,
                    "http://x/", "POST", java.util.List.of(), plain);
            eq("脚本·②Burp→服务端：已加密", true, enc.changed());
            eq("脚本·②：像 Base64", true,
                    new String(enc.body, StandardCharsets.UTF_8).matches("^[A-Za-z0-9+/=]+$"));

            var dec = MessageTransform.apply(p, burp.script.ScriptStage.CLIENT_TO_BURP,
                    "http://x/", "POST", java.util.List.of(), enc.body);
            eq("脚本·①客户端→Burp：已解密", true, dec.changed());
            eq("脚本·①：内容正确", "{\"a\":1}", new String(dec.body, StandardCharsets.UTF_8));

            // ctx.header / ctx.log 可用
            java.io.File js2 = tmp.resolve("hdr.js").toFile();
            java.nio.file.Files.writeString(js2.toPath(), """
                    function serverToBurp(ctx) {
                        var iv = ctx.header("x-iv");
                        ctx.log("iv=" + iv);
                        return ctx.body + "|" + iv + "|" + ctx.stageCode;
                    }
                    """);
            Profile p2 = new Profile("js2", "带 Header 的脚本");
            p2.engine = Profile.Engine.SCRIPT_JS;
            p2.scriptPath = js2.getAbsolutePath();
            var r2 = MessageTransform.apply(p2, burp.script.ScriptStage.SERVER_TO_BURP,
                    "http://x/", "POST", java.util.List.of("X-Iv: ABCD"), "hello".getBytes(StandardCharsets.UTF_8));
            eq("脚本：能读 Header 与阶段号", "hello|ABCD|3",
                    new String(r2.body, StandardCharsets.UTF_8));

            // 未实现该阶段 → 不改动
            var r3 = MessageTransform.apply(p2, burp.script.ScriptStage.BURP_TO_SERVER,
                    "http://x/", "POST", java.util.List.of(), "hi".getBytes(StandardCharsets.UTF_8));
            eq("脚本：未实现的阶段不改动", false, r3.changed());

            // 脚本报错 → FAILED 且不改动
            java.io.File bad = tmp.resolve("bad.js").toFile();
            java.nio.file.Files.writeString(bad.toPath(),
                    "function clientToBurp(ctx) { throw new Error('boom'); }\n");
            Profile p3 = new Profile("bad", "坏脚本");
            p3.engine = Profile.Engine.SCRIPT_JS;
            p3.scriptPath = bad.getAbsolutePath();
            var r4 = MessageTransform.apply(p3, burp.script.ScriptStage.CLIENT_TO_BURP,
                    "http://x/", "POST", java.util.List.of(), "x".getBytes(StandardCharsets.UTF_8));
            eq("脚本：抛异常 → FAILED", burp.transform.TransformResult.Kind.FAILED, r4.kind);
            eq("脚本：抛异常 → 不改动", false, r4.changed());

            // ---------- ② 外部命令 ----------
            Profile cmd = new Profile("cmd", "外部命令");
            cmd.engine = Profile.Engine.SCRIPT_CMD;
            cmd.scriptPath = "sed 's/$/|cmd/'";
            cmd.scriptTimeoutMs = 5000;
            eq("外部命令：自检通过（不预跑）", null, cmd.validate());
            var rc = MessageTransform.apply(cmd, burp.script.ScriptStage.BURP_TO_SERVER,
                    "http://x/", "POST", java.util.List.of(), "hello".getBytes(StandardCharsets.UTF_8));
            eq("外部命令：stdout 生效", "hello|cmd",
                    new String(rc.body, StandardCharsets.UTF_8));

            Profile cmdBad = new Profile("cmdbad", "失败命令");
            cmdBad.engine = Profile.Engine.SCRIPT_CMD;
            cmdBad.scriptPath = "exit 3";
            var rc2 = MessageTransform.apply(cmdBad, burp.script.ScriptStage.BURP_TO_SERVER,
                    "http://x/", "POST", java.util.List.of(), "hi".getBytes(StandardCharsets.UTF_8));
            eq("外部命令：非 0 退出 → FAILED", burp.transform.TransformResult.Kind.FAILED, rc2.kind);
            eq("外部命令：失败时不改动", false, rc2.changed());

            // ---------- ③ 配置往返 ----------
            AppConfig cfg = AppConfig.defaults();
            Profile sp = new Profile("sp", "脚本方案");
            sp.engine = Profile.Engine.SCRIPT_JS;
            sp.scriptPath = "demo.js";
            sp.scriptTimeoutMs = 1234;
            cfg.profiles.add(sp);
            AppConfig back = AppConfig.fromIni(cfg.toIni());
            eq("配置：脚本方式往返", Profile.Engine.SCRIPT_JS, back.profile("sp").engine);
            eq("配置：脚本路径往返", "demo.js", back.profile("sp").scriptPath);
            eq("配置：脚本超时往返", 1234, back.profile("sp").scriptTimeoutMs);

            // 内置算法方案仍然工作（回归）
            Profile builtin = aesProfile();
            eq("内置方案：不受影响", true,
                    MessageTransform.apply(builtin, burp.script.ScriptStage.CLIENT_TO_BURP,
                            "http://x/", "POST", java.util.List.of(),
                            BodyTransformer.encrypt(builtin, "{\"k\":1}".getBytes(StandardCharsets.UTF_8)).body)
                            .changed());
        } catch (Exception e) {
            fail("脚本方式", e);
        }
    }

    /* ==================== Body 转换 ==================== */

    private static void transformIdempotence() {
        Profile p = aesProfile();
        byte[] plain = "{\"user\":\"admin\"}".getBytes(StandardCharsets.UTF_8);

        TransformResult enc = BodyTransformer.encrypt(p, plain);
        eq("加密：发生改动", true, enc.changed());
        eq("加密：明文被记录", "{\"user\":\"admin\"}", enc.plaintext);

        TransformResult again = BodyTransformer.encrypt(p, enc.body);
        eq("再次加密：识别为已是密文，不改动", false, again.changed());
        eq("再次加密：状态为跳过", TransformResult.Kind.SKIPPED, again.kind);

        TransformResult dec = BodyTransformer.decrypt(p, enc.body);
        eq("解密：发生改动", true, dec.changed());
        eq("解密：内容正确", "{\"user\":\"admin\"}", new String(dec.body, StandardCharsets.UTF_8));

        TransformResult decPlain = BodyTransformer.decrypt(p, plain);
        eq("对明文解密：不改动", false, decPlain.changed());

        eq("looksEncrypted 密文", true, BodyTransformer.looksEncrypted(p, enc.body));
        eq("looksEncrypted 明文", false, BodyTransformer.looksEncrypted(p, plain));

        TransformResult empty = BodyTransformer.encrypt(p, new byte[0]);
        eq("空 Body 不改动", false, empty.changed());
    }

    private static void transformJsonField() {
        Profile p = aesProfile();
        p.bodyScope = Profile.BodyScope.JSON_FIELD;
        p.jsonField = "data";
        String json = "{\"code\":0,\"data\":\"hello world\",\"msg\":\"ok\"}";

        TransformResult enc = BodyTransformer.encrypt(p, json.getBytes(StandardCharsets.UTF_8));
        eq("JSON 字段加密：改动", true, enc.changed());
        String cipherJson = new String(enc.body, StandardCharsets.UTF_8);
        eq("JSON 字段加密：其它字段保持", true,
                cipherJson.startsWith("{\"code\":0,\"data\":\"") && cipherJson.endsWith("\",\"msg\":\"ok\"}"));

        TransformResult dec = BodyTransformer.decrypt(p, cipherJson.getBytes(StandardCharsets.UTF_8));
        eq("JSON 字段解密：还原", json, new String(dec.body, StandardCharsets.UTF_8));

        TransformResult miss = BodyTransformer.encrypt(p, "{\"other\":1}".getBytes(StandardCharsets.UTF_8));
        eq("字段不存在：不改动", false, miss.changed());

        TransformResult decMiss = BodyTransformer.decrypt(p,
                "{\"data\":\"not-cipher\"}".getBytes(StandardCharsets.UTF_8));
        eq("字段不是密文：不改动", false, decMiss.changed());
    }

    private static void transformHexEncoding() {
        Profile p = aesProfile();
        p.bodyEncoding = Profile.BodyEncoding.HEX;
        byte[] plain = "hello".getBytes(StandardCharsets.UTF_8);
        TransformResult enc = BodyTransformer.encrypt(p, plain);
        eq("HEX 编码：是 hex 文本", true,
                new String(enc.body, StandardCharsets.UTF_8).matches("[0-9a-f]+"));
        TransformResult dec = BodyTransformer.decrypt(p, enc.body);
        eq("HEX 编码：解密还原", "hello", new String(dec.body, StandardCharsets.UTF_8));
    }

    private static void wrongKeyDoesNotCorrupt() {
        Profile wrong = aesProfile();
        wrong.key = "ffffffffffffffff";
        wrong.touch();
        byte[] plain = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);
        Profile good = aesProfile();
        byte[] cipher = BodyTransformer.encrypt(good, plain).body;

        TransformResult dec = BodyTransformer.decrypt(wrong, cipher);
        eq("错误密钥：不修改 Body", false, dec.changed());
        eq("错误密钥：状态为跳过", TransformResult.Kind.SKIPPED, dec.kind);

        Profile broken = aesProfile();
        broken.key = "short";
        broken.touch();
        TransformResult res = BodyTransformer.encrypt(broken, plain);
        eq("配置非法：不改动且报告失败", TransformResult.Kind.FAILED, res.kind);
        eq("配置非法：不改动", false, res.changed());
    }

    private static void serviceLogging() {
        AppConfig cfg = AppConfig.defaults();
        cfg.rules.clear();
        cfg.rules.add(new Rule(cfg.profiles.get(0).id, Rule.MatchType.HOST, "*"));
        PlaintextLog log = new PlaintextLog();
        CryptoService service = new CryptoService(cfg, log);

        byte[] plain = "{\"x\":1}".getBytes(StandardCharsets.UTF_8);
        TransformResult enc = service.process(AppConfig.ToolGroup.PROXY,
                CryptoService.Phase.REQUEST_ENCRYPT, "POST", "https://api.example.com/login", plain);
        eq("服务层：加密成功", true, enc.changed());
        eq("服务层：写入一条明文流水", 1, log.size());

        TransformResult dec = service.process(AppConfig.ToolGroup.PROXY,
                CryptoService.Phase.RESPONSE_DECRYPT, "POST", "https://api.example.com/login",
                enc.body);
        eq("服务层：解密成功", true, dec.changed());
        eq("服务层：再写入一条", 2, log.size());
        eq("服务层：流水明文", "{\"x\":1}", log.snapshot().get(0).plaintext);
    }

    private static void jsonFieldEditor() {
        String json = "{\"a\":1,\"data\":\"x\\\"y\",\"b\":{\"data\":\"nested\"}}";
        eq("JSON 取值（带转义）", "x\"y", JsonField.get(json, "data"));
        String replaced = JsonField.set(json, "data", "NEW");
        eq("JSON 替换只改第一个匹配", "{\"a\":1,\"data\":\"NEW\",\"b\":{\"data\":\"nested\"}}", replaced);
        eq("JSON 字段不存在", null, JsonField.get(json, "missing"));
        eq("JSON 替换转义", "{\"data\":\"a\\\"b\"}", JsonField.set("{\"data\":\"x\"}", "data", "a\"b"));
    }

    private static void cipherSpecParsing() {
        try {
            CipherSpec aes = CipherSpec.of("AES/CBC/PKCS5Padding");
            eq("AES 分组 16", 16, aes.blockSize);
            eq("AES IV 16", 16, aes.ivLength);
            eq("AES 密钥长度集合", 3, aes.keyLengths.length);

            CipherSpec pkcs7 = CipherSpec.of("AES/CBC/PKCS7Padding");
            eq("PKCS7 归一为 PKCS5", CipherSpec.PKCS5, pkcs7.padding);

            CipherSpec gcm = CipherSpec.of("AES/GCM/NoPadding");
            eq("GCM 是 AEAD", true, gcm.aead);
            eq("GCM IV 12", 12, gcm.ivLength);

            CipherSpec ctr = CipherSpec.of("AES/CTR/PKCS5Padding");
            eq("流式模式强制 NoPadding", CipherSpec.NO_PADDING, ctr.padding);

            CipherSpec sm4 = CipherSpec.of("SM4/CBC/PKCS5Padding");
            eq("SM4 分组 16", 16, sm4.blockSize);
            eq("SM4 密钥 16", 16, sm4.keyLengths[0]);

            CipherSpec rc4 = CipherSpec.of("RC4");
            eq("RC4 流式", 0, rc4.blockSize);
            eq("RC4 不需要 IV", 0, rc4.ivLength);

            CipherSpec des = CipherSpec.of("DES/CBC/PKCS5Padding");
            eq("DES 分组 8", 8, des.blockSize);

            CipherSpec ede = CipherSpec.of("3DES/CBC/PKCS5Padding");
            eq("3DES 识别", "DESede", ede.family);

            try {
                CipherSpec.of("AES/CBC/PKCS5Padding/extra");
                fail("多余段应报错", null);
            } catch (CryptoException ex) {
                ok("算法格式校验：" + ex.getMessage());
            }
        } catch (Exception e) {
            fail("算法解析", e);
        }
    }

    /* ==================== 完整报文与美化 ==================== */

    private static void plainTextFormatting() {
        String json = "{\"code\":0,\"data\":{\"list\":[1,2,3],\"ok\":true},\"msg\":\"ok\"}";
        String pretty = PlainTextFormatter.beautifyJson(json);
        eq("JSON 美化：含换行", true, pretty.contains("\n"));
        eq("JSON 美化：缩进正确", true, pretty.contains("\n  \"code\": 0,"));
        eq("JSON 美化：内容不变", PlainTextFormatter.squeeze(json),
                PlainTextFormatter.squeeze(pretty));
        eq("JSON 美化：幂等", pretty, PlainTextFormatter.beautifyJson(pretty));

        String withEscape = "{\"a\":\"he said \\\"hi\\\", ok\",\"b\":[{\"c\":1}]}";
        eq("JSON 美化：字符串里的引号/逗号不误伤",
                PlainTextFormatter.squeeze(withEscape),
                PlainTextFormatter.squeeze(PlainTextFormatter.beautifyJson(withEscape)));

        eq("JSON 美化：空对象不换行", "{}", PlainTextFormatter.beautifyJson("{}"));
        eq("JSON 美化：空数组不换行", "[]", PlainTextFormatter.beautifyJson("[]"));
        eq("JSON 美化：非 JSON 原样返回", "a=1&b=2",
                PlainTextFormatter.beautifyJson("a=1&b=2"));
        eq("JSON 美化：畸形输入原样返回", "{\"a\":1",
                PlainTextFormatter.beautifyJson("{\"a\":1"));

        String raw = "POST /api/login HTTP/1.1\r\nHost: a.com\r\nContent-Length: 999\r\n\r\n{\"a\":1}";
        eq("报文取 Body：CRLF", "{\"a\":1}", PlainTextFormatter.bodyOf(raw));
        eq("报文取 Body：LF", "body", PlainTextFormatter.bodyOf("POST / HTTP/1.1\n\nbody"));
        eq("报文取 Body：没有 Body", "", PlainTextFormatter.bodyOf("GET / HTTP/1.1\r\n"));
        eq("报文取 Body：空输入", "", PlainTextFormatter.bodyOf(null));
    }

    /* ==================== 工具方法 ==================== */

    private static Profile aesProfile() {
        Profile p = new Profile("t", "测试 AES");
        p.cipher = "AES/CBC/PKCS5Padding";
        p.key = "0123456789abcdef";
        p.keyFormat = KeyMaterial.Format.UTF8;
        p.iv = "1234567890123456";
        p.ivFormat = KeyMaterial.Format.UTF8;
        p.ivMode = CryptoEngine.IvMode.FIXED;
        p.bodyEncoding = Profile.BodyEncoding.BASE64;
        return p;
    }

    private static CryptoEngine engine(String cipher, String key, String iv) throws CryptoException {
        return CryptoEngine.create(cipher, key, KeyMaterial.Format.UTF8, iv,
                KeyMaterial.Format.UTF8, CryptoEngine.IvMode.FIXED, "UTF-8");
    }

    private static void eq(String name, Object expected, Object actual) {
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        if (ok) {
            ok(name);
        } else {
            fail(name + " 期望=" + expected + " 实际=" + actual, null);
        }
    }

    private static void ok(String name) {
        passed++;
        System.out.println("  ✓ " + name);
    }

    private static void fail(String name, Throwable t) {
        failed++;
        System.out.println("  ✗ " + name + (t == null ? "" : "  [" + t + "]"));
        if (t != null && System.getenv("VERBOSE") != null) {
            t.printStackTrace();
        }
    }
}
