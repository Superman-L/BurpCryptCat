package burp.script;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Python 脚本支持：驱动源码、模板、解释器探测。
 *
 * <p>Python 不在 Burp 的 JRE 里，所以用"常驻子进程 + JSON 行协议"的方式对接：
 * 插件启动 {@code <python> _burpcryptcat_driver.py <你的脚本.py>}，之后每个报文发一行 JSON，
 * 驱动调用你脚本里的同名函数并把结果回一行 JSON。这样既不用装 Jython，也避免每个报文
 * 都启动一次解释器（启动一次 ~60ms，爆破时受不了）。</p>
 */
public final class PythonSupport {

    /** 驱动脚本文件名（生成在脚本目录里，勿手动修改） */
    public static final String DRIVER_NAME = "_burpcryptcat_driver.py";
    /** 内置脚本工具模块的文件名（同目录，驱动会自动 import） */
    public static final String CRYPTO_NAME = "_burpcryptcat_crypto.py";

    private PythonSupport() {
    }

    /* ==================== 解释器 ==================== */

    /** 候选解释器（按顺序探测） */
    private static final String[] CANDIDATES_POSIX = {"python3", "/usr/bin/python3", "python"};
    private static final String[] CANDIDATES_WIN = {"python", "py -3", "python3"};

    /** 解释器解析缓存（探测本身要启动进程，约 20~30ms，绝不能每个报文都跑） */
    private static final java.util.Map<String, Cached> INTERPRETERS =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** 缓存有效期：5 分钟（装了 Python / 换了 venv 后最多等这么久，或点界面「检测」立即刷新） */
    private static final long CACHE_TTL = 5 * 60 * 1000L;

    private static final class Cached {
        final String value;          // null = 不可用
        final long at;
        final String version;

        Cached(String value, String version) {
            this.value = value;
            this.version = version;
            this.at = System.currentTimeMillis();
        }

        boolean expired() {
            return System.currentTimeMillis() - at > CACHE_TTL;
        }
    }

    /**
     * 解析实际要用的解释器：方案里填了就用它（可带参数），否则按环境自动选。
     *
     * <p>结果带 5 分钟缓存 —— 探测要起一次进程，Per-message 调用绝不能每次都探测。</p>
     *
     * @return 可用命令；都不可用返回 null
     */
    public static String resolveInterpreter(String configured) {
        String key = configured == null ? "" : configured.trim();
        Cached c = INTERPRETERS.get(key);
        if (c != null && !c.expired()) {
            return c.value;
        }
        Cached fresh = probeInterpreter(key);
        INTERPRETERS.put(key, fresh);
        return fresh.value;
    }

    private static Cached probeInterpreter(String configured) {
        if (!configured.isBlank()) {
            String cmd = expandHome(configured);
            String v = version(cmd);
            return new Cached(v == null ? null : cmd, v);
        }
        boolean win = System.getProperty("os.name", "").toLowerCase().contains("win");
        for (String cand : win ? CANDIDATES_WIN : CANDIDATES_POSIX) {
            String v = version(cand);
            if (v != null) {
                return new Cached(cand, v);
            }
        }
        return new Cached(null, null);
    }

    /** 清掉解释器缓存（界面点「检测」时调用，让改动立即生效）。 */
    public static void invalidateInterpreterCache() {
        INTERPRETERS.clear();
    }

    /** 探测某个命令是否可用，返回版本字符串（如 "Python 3.9.8"），不可用返回 null。 */
    public static String version(String command) {
        if (command == null || command.isBlank()) {
            return null;
        }
        try {
            List<String> cmd = shell(command.trim(), "-V");
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (!p.waitFor(3, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return null;
            }
            return p.exitValue() == 0 ? out : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** 语法检查结果缓存：path|mtime|size|interpreter → 错误信息（用哨兵表示"通过"） */
    private static final java.util.Map<String, String> SYNTAX_CACHE =
            new java.util.concurrent.ConcurrentHashMap<>();
    private static final String SYNTAX_OK = "\u0000OK";

    /** 语法检查（python -m py_compile），返回 null 表示没问题 */
    public static String syntaxError(String interpreter, File script) {
        if (interpreter == null || script == null || !script.isFile()) {
            return "脚本文件不存在";
        }
        String key = script.getAbsolutePath() + "|" + script.lastModified() + "|"
                + script.length() + "|" + interpreter;
        String cached = SYNTAX_CACHE.get(key);
        if (cached != null) {
            return SYNTAX_OK.equals(cached) ? null : cached;
        }
        String err = syntaxError0(interpreter, script);
        SYNTAX_CACHE.put(key, err == null ? SYNTAX_OK : err);
        return err;
    }

    private static String syntaxError0(String interpreter, File script) {
        try {
            List<String> cmd = shell(interpreter, "-m", "py_compile", script.getAbsolutePath());
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (!p.waitFor(8, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return "语法检查超时";
            }
            return p.exitValue() == 0 ? null : (out.isEmpty() ? "语法检查失败" : out);
        } catch (Exception e) {
            return "语法检查失败：" + e;
        }
    }

    /** 从源码里扫出实现了哪些钩子（给界面显示用，不启动进程）。 */
    public static List<String> hooksOf(File script) {
        List<String> out = new ArrayList<>();
        if (script == null || !script.isFile()) {
            return out;
        }
        try {
            String src = Files.readString(script.toPath(), StandardCharsets.UTF_8);
            for (ScriptStage st : ScriptStage.values()) {
                // client_to_burp / burp_to_server / server_to_burp / burp_to_client
                String snake = camelToSnake(st.hook());
                Pattern p = Pattern.compile("(?m)^\\s*def\\s+" + Pattern.quote(snake) + "\\s*\\(\\s*ctx");
                if (p.matcher(src).find()) {
                    out.add(snake);
                }
            }
        } catch (IOException ignore) {
            // 读不了就当没有
        }
        return out;
    }

    static String camelToSnake(String camel) {
        StringBuilder sb = new StringBuilder();
        for (char c : camel.toCharArray()) {
            if (Character.isUpperCase(c)) {
                sb.append('_').append(Character.toLowerCase(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /* ==================== 驱动 ==================== */

    /** 驱动脚本放在临时目录（一定可写），内容变了才写。 */
    public static File driverDir() {
        return new File(System.getProperty("java.io.tmpdir", "."), "burpcryptcat");
    }

    /** 把驱动脚本 + 内置工具模块写出来，返回驱动文件。 */
    public static File ensureDriver() throws IOException {
        File dir = driverDir();
        if (!dir.isDirectory()) {
            //noinspection ResultOfMethodCallIgnored
            dir.mkdirs();
        }
        writeIfChanged(new File(dir, CRYPTO_NAME), cryptoModule());
        return writeIfChanged(new File(dir, DRIVER_NAME), driver());
    }

    private static File writeIfChanged(File f, String content) throws IOException {
        byte[] want = content.getBytes(StandardCharsets.UTF_8);
        if (f.isFile() && f.length() == want.length) {
            byte[] have = Files.readAllBytes(f.toPath());
            if (java.util.Arrays.equals(have, want)) {
                return f;
            }
        }
        Files.write(f.toPath(), want);
        return f;
    }

    public static String driver() {
        return DRIVER;
    }

    /* ==================== 内置脚本工具 ==================== */

    /**
     * 内置脚本工具模块的源码（写到脚本目录旁边的 _burpcryptcat_crypto.py，
     * 用户脚本里直接 {@code crypto.xxx()} / {@code import crypto} 就能用）。
     */
    private static final String CRYPTO = """
            # -*- coding: utf-8 -*-
            # BurpCryptCat 内置脚本工具：纯标准库实现，无需额外安装（AES/SM4 为内置实现）
            import base64
            import hashlib
            import hmac
            import urllib.parse


            def _to_bytes(v, charset="utf-8"):
                if isinstance(v, (bytes, bytearray)):
                    return bytes(v)
                return str(v).encode(charset, "replace")


            def _to_text(v, charset="utf-8"):
                if isinstance(v, (bytes, bytearray)):
                    return bytes(v).decode(charset, "replace")
                return str(v)


            def _key_bytes(v, sizes):
                if isinstance(v, (bytes, bytearray)):
                    return bytes(v)
                text = str(v)
                try:
                    b = base64.b64decode(text, validate=True)
                    if len(b) in sizes:
                        return b
                except Exception:
                    pass
                b = text.encode("utf-8")
                if len(b) in sizes:
                    return b
                raise ValueError("key/iv 长度不对：%d 字节（期望 %s），请用 Base64 或原文" % (len(b), "/".join(map(str, sizes))))


            # ---------------- 编码 ----------------
            def b64e(data):
                return base64.b64encode(_to_bytes(data)).decode("ascii")


            def b64d(text):
                return _to_text(base64.b64decode(_to_bytes(text)))


            def b64d_raw(text):
                return base64.b64decode(_to_bytes(text))


            def b64u_e(data):
                return base64.urlsafe_b64encode(_to_bytes(data)).decode("ascii")


            def b64u_d(text):
                return _to_text(base64.urlsafe_b64decode(_to_bytes(text)))


            def hexe(data):
                return _to_bytes(data).hex()


            def hexd(text):
                return bytes.fromhex(_to_text(text).replace(" ", "").replace(":", ""))


            def hexd_raw(text):
                return bytes.fromhex(_to_text(text).replace(" ", "").replace(":", ""))


            def urle(data):
                return urllib.parse.quote(_to_text(data), safe="")


            def urld(text):
                return urllib.parse.unquote(_to_text(text))


            # ---------------- 摘要 / HMAC ----------------
            def _digest(name, data):
                return hashlib.new(name, _to_bytes(data)).hexdigest()


            def md5(data):
                return _digest("md5", data)


            def sha1(data):
                return _digest("sha1", data)


            def sha256(data):
                return _digest("sha256", data)


            def sha512(data):
                return _digest("sha512", data)


            def hmac_md5(key, msg):
                return hmac.new(_to_bytes(key), _to_bytes(msg), hashlib.md5).hexdigest()


            def hmac_sha1(key, msg):
                return hmac.new(_to_bytes(key), _to_bytes(msg), hashlib.sha1).hexdigest()


            def hmac_sha256(key, msg):
                return hmac.new(_to_bytes(key), _to_bytes(msg), hashlib.sha256).hexdigest()


            # ---------------- 填充 ----------------
            def pkcs7_pad(data, block=16):
                data = _to_bytes(data)
                n = block - len(data) % block
                return data + bytes([n]) * n


            def pkcs7_unpad(data, block=16):
                data = _to_bytes(data)
                if not data:
                    return data
                n = data[-1]
                if n < 1 or n > block or data[-n:] != bytes([n]) * n:
                    return data
                return data[:-n]


            # ---------------- 杂项 ----------------
            def random_bytes(n):
                return __import__("os").urandom(n)


            def random_hex(n):
                return random_bytes(n).hex()


            def now_ms():
                return int(__import__("time").time() * 1000)


            # ---------------- AES（纯 Python，无第三方依赖） ----------------
            def _aes_sbox():
                p = q = 1
                sbox = [0] * 256
                while True:
                    p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
                    q ^= q << 1
                    q ^= q << 2
                    q ^= q << 4
                    q &= 0xFF
                    if q & 0x80:
                        q ^= 0x09
                    x = (q ^ ((q << 1) | (q >> 7)) & 0xFF ^ ((q << 2) | (q >> 6)) & 0xFF
                         ^ ((q << 3) | (q >> 5)) & 0xFF ^ ((q << 4) | (q >> 4)) & 0xFF)
                    sbox[p] = (x ^ 0x63) & 0xFF
                    if p == 1:
                        break
                sbox[0] = 0x63
                return sbox


            _AES_SBOX = _aes_sbox()
            _AES_INV = [0] * 256
            for _i, _v in enumerate(_AES_SBOX):
                _AES_INV[_v] = _i


            def _xtime(a):
                a <<= 1
                return (a ^ 0x1B) & 0xFF if a & 0x100 else a


            def _gmul(a, b):
                r = 0
                while b:
                    if b & 1:
                        r ^= a
                    a = _xtime(a)
                    b >>= 1
                return r


            def _aes_expand(key):
                nk = len(key) // 4
                if len(key) not in (16, 24, 32):
                    raise ValueError("AES 需要 16/24/32 字节密钥")
                nr = nk + 6
                w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
                rcon = 1
                for i in range(nk, 4 * (nr + 1)):
                    t = list(w[i - 1])
                    if i % nk == 0:
                        t = t[1:] + t[:1]
                        t = [_AES_SBOX[b] for b in t]
                        t[0] ^= rcon
                        rcon = _xtime(rcon)
                    elif nk > 6 and i % nk == 4:
                        t = [_AES_SBOX[b] for b in t]
                    w.append([w[i - nk][j] ^ t[j] for j in range(4)])
                return w, nr


            def _aes_encrypt_block(w, nr, block):
                s = [list(block[i::4]) for i in range(4)]

                def ark(rnd):
                    for c in range(4):
                        for r in range(4):
                            s[r][c] ^= w[rnd * 4 + c][r]

                ark(0)
                for rnd in range(1, nr + 1):
                    for r in range(4):
                        for c in range(4):
                            s[r][c] = _AES_SBOX[s[r][c]]
                    for r in range(1, 4):
                        s[r] = s[r][r:] + s[r][:r]
                    if rnd != nr:
                        for c in range(4):
                            a = [s[r][c] for r in range(4)]
                            s[0][c] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
                            s[1][c] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
                            s[2][c] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
                            s[3][c] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
                    ark(rnd)
                return bytes(s[r][c] for c in range(4) for r in range(4))


            def _aes_decrypt_block(w, nr, block):
                s = [list(block[i::4]) for i in range(4)]

                def ark(rnd):
                    for c in range(4):
                        for r in range(4):
                            s[r][c] ^= w[rnd * 4 + c][r]

                ark(nr)
                for rnd in range(nr - 1, -1, -1):
                    for r in range(1, 4):
                        s[r] = s[r][-r:] + s[r][:-r]
                    for r in range(4):
                        for c in range(4):
                            s[r][c] = _AES_INV[s[r][c]]
                    ark(rnd)
                    if rnd != 0:
                        for c in range(4):
                            a = [s[r][c] for r in range(4)]
                            s[0][c] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
                            s[1][c] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
                            s[2][c] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
                            s[3][c] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
                return bytes(s[r][c] for c in range(4) for r in range(4))


            def aes_cbc_encrypt(key, iv, plain):
                k = _key_bytes(key, (16, 24, 32))
                iv = _key_bytes(iv, (16,))
                w, nr = _aes_expand(k)
                data = pkcs7_pad(_to_bytes(plain))
                out, prev = [], iv
                for i in range(0, len(data), 16):
                    blk = bytes(x ^ y for x, y in zip(data[i:i + 16], prev))
                    ct = _aes_encrypt_block(w, nr, blk)
                    out.append(ct)
                    prev = ct
                return base64.b64encode(b"".join(out)).decode("ascii")


            def aes_cbc_decrypt(key, iv, cipher_b64):
                k = _key_bytes(key, (16, 24, 32))
                iv = _key_bytes(iv, (16,))
                data = base64.b64decode(_to_bytes(cipher_b64))
                if len(data) % 16:
                    raise ValueError("密文长度不是 16 的倍数")
                w, nr = _aes_expand(k)
                out, prev = [], iv
                for i in range(0, len(data), 16):
                    blk = data[i:i + 16]
                    pt = _aes_decrypt_block(w, nr, blk)
                    out.append(bytes(x ^ y for x, y in zip(pt, prev)))
                    prev = blk
                return _to_text(pkcs7_unpad(b"".join(out)))


            def aes_cbc_encrypt_prepend_iv(key, plain):
                iv = random_bytes(16)
                return base64.b64encode(iv + base64.b64decode(aes_cbc_encrypt(key, iv, plain))).decode("ascii")


            def aes_cbc_decrypt_prepend_iv(key, cipher_b64):
                raw = base64.b64decode(_to_bytes(cipher_b64))
                if len(raw) <= 16:
                    raise ValueError("密文太短")
                return aes_cbc_decrypt(key, raw[:16], base64.b64encode(raw[16:]).decode("ascii"))


            # ---------------- SM4（纯 Python，GB/T 32907） ----------------
            _SM4_SBOX = [
                0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
                0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
                0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
                0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
                0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
                0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
                0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
                0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
                0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
                0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
                0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
                0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
                0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
                0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
                0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
                0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
            ]
            _SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
            _SM4_CK = [
                0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
                0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
                0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
                0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
            ]


            def _sm4_tau(a):
                return ((_SM4_SBOX[(a >> 24) & 0xFF] << 24) | (_SM4_SBOX[(a >> 16) & 0xFF] << 16)
                        | (_SM4_SBOX[(a >> 8) & 0xFF] << 8) | _SM4_SBOX[a & 0xFF])


            def _sm4_t(a):
                b = _sm4_tau(a)
                return (b ^ ((b << 2) | (b >> 30)) & 0xFFFFFFFF ^ ((b << 10) | (b >> 22)) & 0xFFFFFFFF
                        ^ ((b << 18) | (b >> 14)) & 0xFFFFFFFF ^ ((b << 24) | (b >> 8)) & 0xFFFFFFFF)


            def _sm4_t_prime(a):
                b = _sm4_tau(a)
                return b ^ ((b << 13) | (b >> 19)) & 0xFFFFFFFF ^ ((b << 23) | (b >> 9)) & 0xFFFFFFFF


            def _sm4_round_keys(key):
                k = [int.from_bytes(key[4 * i:4 * i + 4], "big") ^ _SM4_FK[i] for i in range(4)]
                rk = []
                for i in range(32):
                    k.append(k[i] ^ _sm4_t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ _SM4_CK[i]))
                    rk.append(k[i + 4])
                return rk


            def _sm4_encrypt_block(rk, block):
                x = [int.from_bytes(block[4 * i:4 * i + 4], "big") for i in range(4)]
                for i in range(32):
                    x.append(x[i] ^ _sm4_t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]))
                return b"".join(x[35 - i].to_bytes(4, "big") for i in range(4))


            def _sm4_decrypt_block(rk, block):
                x = [int.from_bytes(block[4 * i:4 * i + 4], "big") for i in range(4)]
                for i in range(32):
                    x.append(x[i] ^ _sm4_t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[31 - i]))
                return b"".join(x[35 - i].to_bytes(4, "big") for i in range(4))


            def sm4_cbc_encrypt(key, iv, plain):
                k = _key_bytes(key, (16,))
                iv = _key_bytes(iv, (16,))
                rk = _sm4_round_keys(k)
                data = pkcs7_pad(_to_bytes(plain))
                out, prev = [], iv
                for i in range(0, len(data), 16):
                    blk = bytes(x ^ y for x, y in zip(data[i:i + 16], prev))
                    ct = _sm4_encrypt_block(rk, blk)
                    out.append(ct)
                    prev = ct
                return base64.b64encode(b"".join(out)).decode("ascii")


            def sm4_cbc_decrypt(key, iv, cipher_b64):
                k = _key_bytes(key, (16,))
                iv = _key_bytes(iv, (16,))
                data = base64.b64decode(_to_bytes(cipher_b64))
                if len(data) % 16:
                    raise ValueError("密文长度不是 16 的倍数")
                rk = _sm4_round_keys(k)
                out, prev = [], iv
                for i in range(0, len(data), 16):
                    blk = data[i:i + 16]
                    pt = _sm4_decrypt_block(rk, blk)
                    out.append(bytes(x ^ y for x, y in zip(pt, prev)))
                    prev = blk
                return _to_text(pkcs7_unpad(b"".join(out)))


            def sm4_cbc_encrypt_prepend_iv(key, plain):
                iv = random_bytes(16)
                return base64.b64encode(iv + base64.b64decode(sm4_cbc_encrypt(key, iv, plain))).decode("ascii")


            def sm4_cbc_decrypt_prepend_iv(key, cipher_b64):
                raw = base64.b64decode(_to_bytes(cipher_b64))
                if len(raw) <= 16:
                    raise ValueError("密文太短")
                return sm4_cbc_decrypt(key, raw[:16], base64.b64encode(raw[16:]).decode("ascii"))
            """;

    /** 内置脚本工具模块（AES/SM4/摘要/编码等）源码。 */
    public static String cryptoModule() {
        return CRYPTO;
    }



    /* ==================== 模板 ==================== */

    public static String template() {
        return TEMPLATE;
    }

    private static List<String> shell(String command, String... extra) {
        List<String> cmd = new ArrayList<>();
        if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
            cmd.add("cmd");
            cmd.add("/c");
        } else {
            cmd.add("/bin/sh");
            cmd.add("-c");
        }
        StringBuilder line = new StringBuilder(command);
        for (String e : extra) {
            line.append(' ').append(e.contains(" ") ? "\"" + e + "\"" : e);
        }
        cmd.add(line.toString());
        return cmd;
    }

    private static boolean probe(String command) {
        return version(command) != null;
    }

    private static String expandHome(String path) {
        if (path.startsWith("~/")) {
            return new File(System.getProperty("user.home", "."), path.substring(2)).getAbsolutePath();
        }
        return path;
    }

    /* ==================================================================
     *  驱动脚本：常驻进程，stdin 收一行 JSON，stdout 回一行 JSON
     * ================================================================== */
    private static final String DRIVER = """
            # -*- coding: utf-8 -*-
            # BurpCryptCat 自动生成的 Python 驱动，请勿修改（会被覆盖）。
            # 用法：python3 _burpcryptcat_driver.py <你的脚本.py>
            import sys, os, json, base64, importlib.util, traceback

            HOOKS = ("client_to_burp", "burp_to_server", "server_to_burp", "burp_to_client")

            # 内置工具模块（和驱动同目录，纯标准库实现；用户脚本里 crypto.xxx() 直接用）
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import _burpcryptcat_crypto as crypto
            sys.modules.setdefault("crypto", crypto)

            # 协议走 fd1 的副本；把 sys.stdout 换成 stderr，这样脚本里 print() 不会污染协议
            _proto = os.fdopen(os.dup(1), "w", encoding="utf-8", newline="\\n")
            sys.stdout = sys.stderr


            def _reply(obj):
                try:
                    _proto.write(json.dumps(obj, ensure_ascii=False) + "\\n")
                    _proto.flush()
                except Exception:
                    pass


            def _load(path):
                spec = importlib.util.spec_from_file_location("bcc_user_script", path)
                mod = importlib.util.module_from_spec(spec)
                mod.__dict__.setdefault("crypto", crypto)     # 脚本里可直接 crypto.md5(...)
                spec.loader.exec_module(mod)
                return mod


            class Ctx(object):
                def __init__(self, req):
                    self.stage = req.get("stage")
                    self.stage_code = req.get("stageCode")
                    self.stage_label = req.get("stageLabel")
                    self.hook = req.get("hook")
                    self.url = req.get("url", "")
                    self.method = req.get("method", "")
                    self.is_request = req.get("isRequest", False)
                    self.charset = req.get("charset", "UTF-8") or "UTF-8"
                    self.profile = req.get("profile", "")
                    self.headers = req.get("headers") or []
                    raw = base64.b64decode(req.get("body") or "")
                    self.raw_body = raw
                    try:
                        self.body = raw.decode(self.charset)
                    except Exception:
                        self.body = raw.decode(self.charset, "replace")
                    self._log = []

                def header(self, name, default=None):
                    n = (name or "").lower()
                    for h in self.headers:
                        if ":" in h:
                            k, v = h.split(":", 1)
                            if k.strip().lower() == n:
                                return v.strip()
                    return default

                def log(self, msg):
                    try:
                        self._log.append(str(msg))
                    except Exception:
                        pass


            def _encode(value, charset):
                if value is None:
                    return None
                if isinstance(value, bytes):
                    return base64.b64encode(value).decode("ascii")
                return base64.b64encode(str(value).encode(charset, "replace")).decode("ascii")


            def main():
                if len(sys.argv) < 2:
                    _reply({"ok": False, "error": "缺少脚本路径参数"})
                    return
                path = sys.argv[1]
                try:
                    mod = _load(path)
                except Exception:
                    _reply({"ok": False, "error": "导入脚本失败：" + traceback.format_exc(limit=4)})
                    return
                found = [h for h in HOOKS if callable(getattr(mod, h, None))]
                _reply({"ok": True, "ready": True, "hooks": found})
                for line in sys.stdin:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        req = json.loads(line)
                    except Exception:
                        _reply({"ok": False, "error": "请求不是合法 JSON"})
                        continue
                    hook = req.get("hook")
                    fn = getattr(mod, hook, None) if hook else None
                    if not callable(fn):
                        _reply({"ok": True, "body": None, "skipped": "脚本没有实现 %s()" % hook})
                        continue
                    ctx = Ctx(req)
                    try:
                        res = fn(ctx)
                        out = res.get("body") if isinstance(res, dict) else res
                    except Exception:
                        _reply({"ok": False, "error": traceback.format_exc(limit=5), "log": ctx._log})
                        continue
                    _reply({"ok": True, "body": _encode(out, ctx.charset), "log": ctx._log})


            if __name__ == "__main__":
                main()
            """;

    /* ==================================================================
     *  用户脚本模板
     * ================================================================== */
    private static final String TEMPLATE = """
            # -*- coding: utf-8 -*-
            # BurpCryptCat · Python 脚本模板
            #
            # 四个接口对应 Burp 的四个处理阶段（只实现需要的，没实现的阶段会被跳过）：
            #   client_to_burp(ctx)   ① 客户端 → Burp     Proxy 收到请求（一般：解密）
            #   burp_to_server(ctx)   ② Burp → 服务端     请求放行前（一般：加密）
            #   server_to_burp(ctx)   ③ 服务端 → Burp     收到响应（一般：解密）
            #   burp_to_client(ctx)   ④ Burp → 客户端     响应回写前（一般：加密）
            #
            # ctx 上有：
            #   ctx.body        当前 Body 文本（按方案字符集解码）
            #   ctx.raw_body    原始 Body 字节
            #   ctx.charset / ctx.url / ctx.method / ctx.is_request
            #   ctx.headers     全部 Header（"Name: value" 列表）
            #   ctx.header("x-iv")               取 Header（大小写不敏感）
            #   ctx.stage / ctx.stage_code       当前阶段（1~4）
            #   ctx.log("...")                   打到 Extender → Output
            #
            # 现成的工具（crypto.*，纯标准库 + 内置 AES/SM4，无需 pip install）：
            #   crypto.b64e / b64d / b64d_raw / b64u_e / b64u_d
            #   crypto.hexe / hexd / urle / urld
            #   crypto.md5 / sha1 / sha256 / sha512 / hmac_md5 / hmac_sha1 / hmac_sha256
            #   crypto.aes_cbc_encrypt(key, iv, plain)        → Base64 密文
            #   crypto.aes_cbc_decrypt(key, iv, cipher_b64)   → 明文
            #   crypto.aes_cbc_encrypt_prepend_iv / aes_cbc_decrypt_prepend_iv
            #   crypto.sm4_cbc_encrypt / sm4_cbc_decrypt / sm4_cbc_decrypt_prepend_iv
            #   crypto.pkcs7_pad / pkcs7_unpad / random_hex / random_bytes / now_ms
            #   也可以 import crypto 后使用；key/iv 支持 Base64 或 UTF-8 原文
            #
            # 返回：字符串 = 新 Body；None = 不改动；也可以 return {"body": "..."}
            import base64
            import os

            KEY = base64.b64decode("ysIEuRgXG/SMp4HqZL1BEw==")   # 例：Base64 的 AES Key
            IV = b"63cef27c4a68b8f4"                            # 例：16 字节固定 IV


            def _unpad(data):
                return data[:-data[-1]] if data else data


            def _decrypt(text):
                # 需要 pycryptodome：pip install pycryptodome
                # 也可以用 cryptography / gmssl，随便你
                from Crypto.Cipher import AES
                raw = base64.b64decode(text.strip())
                if len(raw) > 16 and len(raw) % 16 == 0:
                    iv, ct = raw[:16], raw[16:]        # 密文前 16 字节是随机 IV
                else:
                    iv, ct = IV, raw
                return _unpad(AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)).decode("utf-8")


            def _encrypt(text):
                from Crypto.Cipher import AES
                iv = os.urandom(16)
                data = text.encode("utf-8")
                pad = 16 - len(data) % 16
                data += bytes([pad]) * pad
                return base64.b64encode(iv + AES.new(KEY, AES.MODE_CBC, iv).encrypt(data)).decode()


            def client_to_burp(ctx):
                try:
                    return _decrypt(ctx.body)
                except Exception as e:
                    ctx.log("client_to_burp 解密失败：%s" % e)
                    return None          # None = 保持原样


            def burp_to_server(ctx):
                return _encrypt(ctx.body)


            def server_to_burp(ctx):
                try:
                    return _decrypt(ctx.body)
                except Exception as e:
                    ctx.log("server_to_burp 解密失败：%s" % e)
                    return None


            def burp_to_client(ctx):
                return _encrypt(ctx.body)
            """;
}
