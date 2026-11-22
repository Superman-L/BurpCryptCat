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
        customRuleExpression();
        resolverPriority();
        allToolsSwitch();
        scriptEngine();
        pythonScriptEngine();
        scriptUtilsBuiltins();
        pythonCryptoHelpers();
        jsCryptoHelpers();
        rulesFileAndGlobalSettings();
        handoffByMessageId();
        handoffOriginalBody();
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

    /** 自定义表达式规则：host/path/query/url + 运算符 + 逻辑组合 + 语法校验 */
    private static void customRuleExpression() {
        try {
            burp.config.RuleExpression e = burp.config.RuleExpression.compile(
                    "host == \"api.example.com\" && path == \"/api/login\"");
            eq("自定义：host+path 全等命中", true,
                    e.test("api.example.com", "https://api.example.com/api/login"));
            eq("自定义：host 不同不命中", false, e.test("x.com", "https://x.com/api/login"));
            eq("自定义：path 不同不命中", false, e.test("api.example.com", "https://api.example.com/api/other"));

            eq("自定义：startsWith", true, burp.config.RuleExpression
                    .compile("path startsWith \"/gw/\"")
                    .test("a.com", "https://a.com/gw/foo?x=1"));
            eq("自定义：like 通配", true, burp.config.RuleExpression
                    .compile("host like \"*.example.com\"")
                    .test("api.example.com", "https://api.example.com/x"));
            eq("自定义：like 不命中", false, burp.config.RuleExpression
                    .compile("host like \"*.example.com\"")
                    .test("example.com.evil.cn", "https://example.com.evil.cn/x"));
            eq("自定义：正则 find", true, burp.config.RuleExpression
                    .compile("url ~= \"/login\"")
                    .test("a.com", "https://a.com/v1/login?x=1"));
            eq("自定义：query 取参", true, burp.config.RuleExpression
                    .compile("query contains \"from=mini\"")
                    .test("a.com", "https://a.com/p?from=mini&id=1"));
            eq("自定义：无 query 为空串", true, burp.config.RuleExpression
                    .compile("query == \"\"")
                    .test("a.com", "https://a.com/p"));
            eq("自定义：!= 与括号", true, burp.config.RuleExpression
                    .compile("host == \"a.com\" && !(path contains \"/public/\")")
                    .test("a.com", "https://a.com/app/index"));
            eq("自定义：&& 优先于 ||", true, burp.config.RuleExpression
                    .compile("host == \"a.com\" || host == \"b.com\" && path == \"/x\"")
                    .test("a.com", "https://a.com/y"));
            eq("自定义：大小写不敏感（host 值需一致）", false, burp.config.RuleExpression
                    .compile("host == \"A.com\"")
                    .test("a.com", "https://a.com/x"));
            eq("自定义：正则忽略大小写", true, burp.config.RuleExpression
                    .compile("url ~= \"/API/\"")
                    .test("a.com", "https://a.com/api/x"));
            eq("自定义：endsWith", true, burp.config.RuleExpression
                    .compile("path endsWith \".do\"")
                    .test("a.com", "https://a.com/sys/login.do"));

            // 语法错误
            expectInvalid("自定义：未知变量", "foo == \"x\"");
            expectInvalid("自定义：缺右括号", "(host == \"a\"");
            expectInvalid("自定义：字符串未闭合", "host == \"a");
            expectInvalid("自定义：缺操作数", "host ==");
            expectInvalid("自定义：正则写错", "url ~= \"[\"");

            // Rule 集成 + 配置往返
            AppConfig cfg = AppConfig.defaults();
            Rule rule = new Rule("sample", Rule.MatchType.CUSTOM,
                    "host == \"api.example.com\" && path == \"/api/login\"");
            eq("自定义规则：validate 通过", null, rule.validate(cfg));
            eq("自定义规则：命中", true,
                    rule.matches("api.example.com", "https://api.example.com/api/login"));
            eq("自定义规则：不命中", false,
                    rule.matches("api.example.com", "https://api.example.com/other"));
            eq("自定义规则：描述带类型", true, rule.describe().contains("自定义表达式"));

            Rule bad = new Rule("sample", Rule.MatchType.CUSTOM, "host == ");
            eq("自定义规则：非法表达式 validate 报错", true,
                    bad.validate(cfg) != null && bad.validate(cfg).contains("自定义表达式错误"));
            eq("自定义规则：非法表达式不命中", false, bad.matches("a.com", "https://a.com/x"));

            AppConfig back = AppConfig.fromIni(cfgWithRule(cfg, rule).toIni());
            eq("自定义规则：配置往返保留类型", Rule.MatchType.CUSTOM, back.rules.get(0).matchType);
            eq("自定义规则：配置往返保留表达式",
                    "host == \"api.example.com\" && path == \"/api/login\"",
                    back.rules.get(0).pattern);
        } catch (Exception e) {
            fail("自定义表达式规则", e);
        }
    }

    private static AppConfig cfgWithRule(AppConfig base, Rule rule) {
        AppConfig c = AppConfig.fromIni(base.toIni());
        c.rules.clear();
        c.rules.add(rule);
        return c;
    }

    private static void expectInvalid(String name, String expr) {
        try {
            burp.config.RuleExpression.compile(expr);
            fail(name + "（应当报错却通过了）", new IllegalStateException(expr));
        } catch (IllegalArgumentException expected) {
            ok(name);
        }
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

    /**
     * Python 脚本方式：四个 snake_case 接口、环境自带解释器、常驻进程协议、语法错误/未实现钩子的兜底。
     */
    private static void pythonScriptEngine() {
        String py = burp.script.PythonSupport.resolveInterpreter("");
        if (py == null) {
            ok("Python 方式：环境没有 python3/python，跳过（不影响其它测试）");
            return;
        }
        try {
            java.nio.file.Path tmp = java.nio.file.Files.createTempDirectory("burpcryptcat-py");
            java.io.File script = tmp.resolve("demo.py").toFile();
            java.nio.file.Files.writeString(script.toPath(), """
                    # 测试脚本：故意在模块级 print，验证不会污染协议
                    print("noise on stdout, should go to stderr")

                    def burp_to_server(ctx):
                        return ctx.body.upper() + "|py|" + str(ctx.stage_code)

                    def client_to_burp(ctx):
                        ctx.log("iv=" + str(ctx.header("x-iv")))
                        return "HDR=" + str(ctx.header("x-iv")) + ";" + ctx.body
                    """);

            Profile p = new Profile("py", "Python 方案");
            p.engine = Profile.Engine.SCRIPT_PY;
            p.scriptPath = script.getAbsolutePath();
            p.pythonCommand = "";                     // 留空 = 自动探测环境里的 python
            p.charset = "UTF-8";

            eq("Python：自检通过（解释器+语法+钩子）", null, p.validate());
            eq("Python：识别出 2 个钩子", 2,
                    burp.script.PythonSupport.hooksOf(script).size());

            var enc = MessageTransform.apply(p, burp.script.ScriptStage.BURP_TO_SERVER,
                    "http://x/", "POST", java.util.List.of(), "hello".getBytes(StandardCharsets.UTF_8));
            eq("Python：②Burp→服务端 生效", true, enc.changed());
            eq("Python：内容与 stageCode 正确", "HELLO|py|2",
                    new String(enc.body, StandardCharsets.UTF_8));

            var dec = MessageTransform.apply(p, burp.script.ScriptStage.CLIENT_TO_BURP,
                    "http://x/", "POST", java.util.List.of("X-Iv: ABCD"),
                    "hi".getBytes(StandardCharsets.UTF_8));
            eq("Python：①客户端→Burp 能读 Header", "HDR=ABCD;hi",
                    new String(dec.body, StandardCharsets.UTF_8));

            var miss = MessageTransform.apply(p, burp.script.ScriptStage.SERVER_TO_BURP,
                    "http://x/", "POST", java.util.List.of(), "x".getBytes(StandardCharsets.UTF_8));
            eq("Python：未实现的阶段不改动", false, miss.changed());

            // 语法错误 → 自检能报出来
            java.io.File bad = tmp.resolve("bad.py").toFile();
            java.nio.file.Files.writeString(bad.toPath(), "def burp_to_server(ctx)\n    return 1\n");
            Profile p2 = new Profile("py2", "语法错误");
            p2.engine = Profile.Engine.SCRIPT_PY;
            p2.scriptPath = bad.getAbsolutePath();
            String err = p2.validate();
            eq("Python：语法错误能被自检发现", true, err != null && err.contains("语法检查失败"));

            // 运行时抛异常 → FAILED 且不改动
            java.io.File thrower = tmp.resolve("throws.py").toFile();
            java.nio.file.Files.writeString(thrower.toPath(),
                    "def burp_to_server(ctx):\n    raise ValueError('boom')\n");
            Profile p3 = new Profile("py3", "抛异常");
            p3.engine = Profile.Engine.SCRIPT_PY;
            p3.scriptPath = thrower.getAbsolutePath();
            var r = MessageTransform.apply(p3, burp.script.ScriptStage.BURP_TO_SERVER,
                    "http://x/", "POST", java.util.List.of(), "x".getBytes(StandardCharsets.UTF_8));
            eq("Python：异常 → FAILED", burp.transform.TransformResult.Kind.FAILED, r.kind);
            eq("Python：异常 → 不改动", false, r.changed());

            // 手填解释器路径也应可用
            Profile p4 = new Profile("py4", "指定解释器");
            p4.engine = Profile.Engine.SCRIPT_PY;
            p4.scriptPath = script.getAbsolutePath();
            p4.pythonCommand = py;
            eq("Python：手动指定解释器可用", null, p4.validate());

            // 配置往返（解释器自 1.7.0 起是全局设置，见 rulesFileAndGlobalSettings）
            AppConfig cfg = AppConfig.defaults();
            cfg.profiles.add(p4);
            AppConfig back = AppConfig.fromIni(cfg.toIni());
            eq("配置：Python 引擎往返", Profile.Engine.SCRIPT_PY, back.profile("py4").engine);
        } catch (Exception e) {
            fail("Python 方式", e);
        } finally {
            burp.script.PythonRunner.shutdown();
        }
    }

    /** 脚本内置工具（JS 侧 crypto.*）：编码/摘要/HMAC/AES/SM4/DES */
    private static void scriptUtilsBuiltins() {
        try {
            burp.script.ScriptUtils u = new burp.script.ScriptUtils();
            eq("工具：Base64 往返", "hello", u.b64Decode(u.b64Encode("hello")));
            eq("工具：Base64 URL-safe", "a+b/c=", u.b64UrlDecode(u.b64UrlEncode("a+b/c=")));
            eq("工具：hex 往返", "hi", u.hexDecode(u.hexEncode("hi")));
            eq("工具：hexUpper", "4849", u.hexUpper("HI"));
            eq("工具：md5", "900150983cd24fb0d6963f7d28e17f72", u.md5("abc"));
            eq("工具：sha1", "a9993e364706816aba3e25717850c26c9cd0d89d", u.sha1("abc"));
            eq("工具：sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    u.sha256("abc"));
            eq("工具：sha512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                    + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", u.sha512("abc"));
            eq("工具：hmacMd5", "ed7e724d3a91554aaa2043041d9c5305", u.hmacMd5("k", "m"));
            eq("工具：hmacSha256", "b60090e3052297aeb5a080889ce2fc4bca957e756faeb4df7d31800ca1e771ec",
                    u.hmacSha256("k", "m"));
            eq("工具：urlEncode/Decode", "a b/中", u.urlDecode(u.urlEncode("a b/中")));

            String key = "0123456789abcdef";
            String iv = "1234567890123456";
            String plain = "{\"a\":1}";
            eq("工具：AES-CBC 与 openssl 一致", "+gUTCSjPhWsurX+delDPMA==", u.aesCbcEncrypt(key, iv, plain));
            eq("工具：AES-CBC 解密", plain, u.aesCbcDecrypt(key, iv, u.aesCbcEncrypt(key, iv, plain)));
            eq("工具：AES-ECB 与 openssl 一致", "4Bu2yOikMUYfFkhodEsv7w==", u.aesEcbEncrypt(key, plain));
            eq("工具：AES-ECB 解密", plain, u.aesEcbDecrypt(key, u.aesEcbEncrypt(key, plain)));
            eq("工具：AES-CBC 随机 IV 前置往返", plain, u.aesCbcDecryptPrependIv(key, u.aesCbcEncryptPrependIv(key, plain)));
            eq("工具：SM4-CBC 往返", plain, u.sm4CbcDecrypt(key, iv, u.sm4CbcEncrypt(key, iv, plain)));
            eq("工具：SM4-CBC 已知向量", "QuwNt7vnPfUWzKGlEBqd6A==", u.sm4CbcEncrypt(key, iv, plain));
            eq("工具：SM4-CBC 随机 IV 前置往返", plain,
                    u.sm4CbcDecryptPrependIv(key, u.sm4CbcEncryptPrependIv(key, plain)));
            String desKey = "12345678";
            String des3Key = "123456789012345678901234";
            eq("工具：DES-CBC 往返", plain, u.desCbcDecrypt(desKey, desKey, u.desCbcEncrypt(desKey, desKey, plain)));
            eq("工具：3DES-CBC 往返", plain, u.des3CbcDecrypt(des3Key, desKey, u.des3CbcEncrypt(des3Key, desKey, plain)));
            eq("工具：randomHex 长度", 32, u.randomHex(16).length());
            eq("工具：uuid 长度", 36, u.uuid().length());
            eq("工具：key 支持 Base64", plain,
                    u.aesCbcDecrypt("MDEyMzQ1Njc4OWFiY2RlZg==", iv, u.aesCbcEncrypt("MDEyMzQ1Njc4OWFiY2RlZg==", iv, plain)));
        } catch (Exception e) {
            fail("脚本内置工具", e);
        }
    }

    /** Python 侧内置工具（crypto.*）：md5/base64/AES/SM4 都能直接用，无需第三方库 */
    private static void pythonCryptoHelpers() {
        String py = burp.script.PythonSupport.resolveInterpreter("");
        if (py == null) {
            ok("Python 内置工具：环境没有 python3/python，跳过（不影响其它测试）");
            return;
        }
        try {
            java.nio.file.Path tmp = java.nio.file.Files.createTempDirectory("burpcryptcat-py-crypto");
            java.io.File script = tmp.resolve("crypto_demo.py").toFile();
            java.nio.file.Files.writeString(script.toPath(), """
                    def client_to_burp(ctx):
                        ct = crypto.aes_cbc_encrypt("0123456789abcdef", "1234567890123456", ctx.body)
                        sm = crypto.sm4_cbc_encrypt("0123456789abcdef", "1234567890123456", ctx.body)
                        plain = crypto.aes_cbc_decrypt("0123456789abcdef", "1234567890123456", ct)
                        sm_rt = crypto.sm4_cbc_decrypt_prepend_iv(
                            "0123456789abcdef", crypto.sm4_cbc_encrypt_prepend_iv("0123456789abcdef", ctx.body))
                        return "|".join([crypto.md5(ctx.body), crypto.b64e(ctx.body), plain, sm,
                                         crypto.b64d(crypto.b64e(ctx.body)), sm_rt, crypto.sha256(ctx.body)[:8]])
                    """);
            Profile p = new Profile("pyc", "Python 内置工具");
            p.engine = Profile.Engine.SCRIPT_PY;
            p.scriptPath = script.getAbsolutePath();
            p.charset = "UTF-8";
            eq("Python 内置工具：自检通过", null, p.validate());
            var r = MessageTransform.apply(p, burp.script.ScriptStage.CLIENT_TO_BURP,
                    "http://x/", "POST", java.util.List.of(), "abc".getBytes(StandardCharsets.UTF_8));
            eq("Python 内置工具：md5/Base64/AES/SM4 结果正确",
                    "900150983cd24fb0d6963f7d28e17f72|YWJj|abc|2Q1BqpZgMG9E2XraERIrRA==|abc|abc|ba7816bf",
                    new String(r.body, StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Python 内置工具", e);
        } finally {
            burp.script.PythonRunner.shutdown();
        }
    }

    /** JS 侧内置工具走 Rhino 也要能用（防止只是 Java 方法对、脚本里调用不了） */
    private static void jsCryptoHelpers() {
        try {
            java.nio.file.Path tmp = java.nio.file.Files.createTempDirectory("burpcryptcat-js-crypto");
            java.io.File script = tmp.resolve("crypto.js").toFile();
            java.nio.file.Files.writeString(script.toPath(), """
                    function clientToBurp(ctx) {
                        var key = "0123456789abcdef";
                        var iv = "1234567890123456";
                        var aes = crypto.aesCbcEncrypt(key, iv, ctx.body);
                        var sm4 = crypto.sm4CbcEncrypt(key, iv, ctx.body);
                        return [
                            crypto.md5(ctx.body),
                            crypto.b64Encode(ctx.body),
                            crypto.hexUpper("HI"),
                            crypto.hmacSha256("k", "m").substring(0, 8),
                            crypto.urlDecode(crypto.urlEncode("a b")),
                            aes,
                            crypto.aesCbcDecrypt(key, iv, aes),
                            sm4
                        ].join("|");
                    }
                    """);
            Profile p = new Profile("jsx", "JS 内置工具");
            p.engine = Profile.Engine.SCRIPT_JS;
            p.scriptPath = script.getAbsolutePath();
            p.charset = "UTF-8";
            eq("JS 内置工具：自检通过", null, p.validate());
            var r = MessageTransform.apply(p, burp.script.ScriptStage.CLIENT_TO_BURP,
                    "http://x/", "POST", java.util.List.of(), "abc".getBytes(StandardCharsets.UTF_8));
            eq("JS 内置工具：Rhino 里全部可用",
                    "900150983cd24fb0d6963f7d28e17f72|YWJj|4849|b60090e3|a b|18HO59pooyrETHsl3v+72w==|abc|2Q1BqpZgMG9E2XraERIrRA==",
                    new String(r.body, StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("JS 内置工具", e);
        }
    }

    /** 规则单独文件 + 全局 Python 解释器（含旧配置迁移） */
    private static void rulesFileAndGlobalSettings() {
        AppConfig cfg = AppConfig.defaults();
        cfg.rules.clear();
        cfg.rules.add(new Rule("p1", Rule.MatchType.HOST, "a.example.com"));
        Rule r2 = new Rule("p2", Rule.MatchType.URL_GLOB, "https://b.example.com/*");
        r2.onResponse = false;
        cfg.rules.add(r2);

        // 规则文件读写往返
        String rulesIni = cfg.rulesToIni();
        java.util.List<Rule> back = AppConfig.parseRules(rulesIni);
        eq("规则文件：条数", 2, back.size());
        eq("规则文件：匹配方式", Rule.MatchType.URL_GLOB, back.get(1).matchType);
        eq("规则文件：匹配串", "https://b.example.com/*", back.get(1).pattern);
        eq("规则文件：方案引用", "p2", back.get(1).profileId);
        eq("规则文件：方向开关", false, back.get(1).onResponse);
        eq("规则文件：没有规则时是空列表（不回退默认）", 0, AppConfig.parseRules("").size());

        // config 里不再写规则，规则由独立文件承载
        String configIni = cfg.toIni(false);
        eq("config（不带规则）里没有 [rule]", false, configIni.contains("[rule]"));
        eq("config（带规则）里仍有 [rule]", true, cfg.toIni(true).contains("[rule]"));

        // 全局 Python 解释器
        cfg.pythonCommand = "/opt/venv/bin/python3";
        AppConfig withPy = AppConfig.fromIni(cfg.toIni());
        eq("全局 Python 解释器往返", "/opt/venv/bin/python3", withPy.pythonCommand);

        // 旧配置（解释器写在方案里）自动迁移到全局
        String legacy = """
                [global]
                master=true
                [profile]
                id=old
                name=旧方案
                engine=SCRIPT_PY
                script=old.py
                python=/usr/bin/python3
                [rule]
                id=r1
                enabled=true
                matchtype=HOST
                pattern=*
                profile=old
                """;
        AppConfig migrated = AppConfig.fromIni(legacy);
        eq("旧配置迁移：解释器提到全局", "/usr/bin/python3", migrated.pythonCommand);
    }

    /** HandoffCache：改过明文的报文，靠 messageId 仍能认出"这是我解出来的" */
    private static void handoffByMessageId() {
        burp.http.HandoffCache c = new burp.http.HandoffCache();
        c.markMessage(true, 4242);
        eq("记账：同一报文（请求）被记住", true, c.isMarkedMessage(true, 4242));
        eq("记账：不同方向互不影响", false, c.isMarkedMessage(false, 4242));
        eq("记账：未记过的报文", false, c.isMarkedMessage(true, 4243));
        c.markMessage(false, 4242);
        eq("记账：响应侧单独记", true, c.isMarkedMessage(false, 4242));
        c.clear();
        eq("记账：clear 之后清空", false, c.isMarkedMessage(true, 4242));
    }

    /** HandoffCache：收到时的原件比对——用户没改过就绝不能再加密一次 */
    private static void handoffOriginalBody() {
        burp.http.HandoffCache c = new burp.http.HandoffCache();
        byte[] cipher = "9WwXZi1YYQYquOSySOg0L0PvoC25jpfGhgq9".getBytes(StandardCharsets.UTF_8);
        byte[] plain = "{\"username\":\"admin\"}".getBytes(StandardCharsets.UTF_8);
        c.markOriginal(true, 77, cipher);
        eq("原件：同一个 Body 命中", true, c.isOriginal(true, 77, cipher));
        eq("原件：改过的 Body 不命中", false, c.isOriginal(true, 77, plain));
        eq("原件：不同方向不串", false, c.isOriginal(false, 77, cipher));
        eq("原件：没记过的报文", false, c.isOriginal(true, 78, cipher));
        eq("原件：空 Body 不命中", false, c.isOriginal(true, 77, new byte[0]));
        eq("原件：messageId 非法不命中", false, c.isOriginal(true, 0, cipher));
        c.clear();
        eq("原件：clear 之后清空", false, c.isOriginal(true, 77, cipher));
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
