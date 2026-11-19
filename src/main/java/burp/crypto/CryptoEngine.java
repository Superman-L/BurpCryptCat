package burp.crypto;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 面向"一条配置"的加解密门面：把算法描述 + Key/IV 文本 + 字符集组合起来，
 * 对外只暴露 {@code encrypt(bytes)} / {@code decrypt(bytes)}。
 *
 * <p>额外支持一种常见的 IV 传递方式：{@link IvMode#PREPENDED} —— 加密时随机生成 IV
 * 并拼在密文最前面（{@code IV || CT}），解密时自动切出前 16 字节作为 IV。
 * 很多"每包随机 IV"的 App 都是这么干的，配固定 IV 会解不出来。</p>
 */
public final class CryptoEngine {

    public enum IvMode {
        /** 用配置里填的固定 IV */
        FIXED("固定 IV"),
        /** 每次加密随机 IV，前置拼在密文前；解密时自动切分 */
        PREPENDED("随机 IV 前置（IV||CT）"),
        /** 解密时先按固定 IV 试，解不出可读文本再按 IV||CT 试；加密时有 IV 用固定、无 IV 则前置 */
        AUTO("自动（固定 IV / IV||CT 自适应）"),
        /** 不需要 IV（ECB / 流式算法） */
        NONE("无 IV");

        private final String label;

        IvMode(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }

        @Override
        public String toString() {
            return label;
        }

        public static IvMode of(String name) {
            if (name == null) {
                return FIXED;
            }
            for (IvMode m : values()) {
                if (m.name().equalsIgnoreCase(name.trim())) {
                    return m;
                }
            }
            return FIXED;
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final CipherSpec spec;
    private final byte[] key;
    private final byte[] iv;
    private final IvMode ivMode;
    private final Charset charset;

    private CryptoEngine(CipherSpec spec, byte[] key, byte[] iv, IvMode ivMode, Charset charset) {
        this.spec = spec;
        this.key = key;
        this.iv = iv;
        this.ivMode = ivMode;
        this.charset = charset;
    }

    /* ==================== 构建 ==================== */

    public static CryptoEngine create(String transformation,
                                      String keyText, KeyMaterial.Format keyFormat,
                                      String ivText, KeyMaterial.Format ivFormat,
                                      IvMode ivMode, String charsetName) throws CryptoException {
        CipherSpec spec = CipherSpec.of(transformation);
        byte[] key = KeyMaterial.key(keyText, keyFormat, spec);
        IvMode mode = ivMode == null ? IvMode.AUTO : ivMode;
        if (spec.ivLength == 0 || spec.mode.equals("ECB")) {
            mode = IvMode.NONE;
        }
        byte[] iv = null;
        if (mode == IvMode.FIXED) {
            iv = KeyMaterial.iv(ivText, ivFormat, spec);
        } else if (mode == IvMode.AUTO) {
            // AUTO：IV 可填可不填。填了优先用固定 IV，没填就只按 IV||CT 处理
            try {
                iv = KeyMaterial.iv(ivText, ivFormat, spec);
            } catch (CryptoException ignore) {
                iv = null;
            }
        } else if (mode == IvMode.PREPENDED) {
            if (spec.blockSize <= 0) {
                throw new CryptoException("流式算法不支持" + IvMode.PREPENDED.label());
            }
        }
        // 立即构造一次引擎，把"密钥长度/IV 长度/填充"等错误在配置阶段就暴露出来。
        // PREPENDED 模式下 IV 是每次加密随机生成的，这里用占位 IV 做参数校验即可。
        byte[] probeIv = iv;
        if (probeIv == null && spec.requiresIv() && spec.blockSize > 0) {
            probeIv = new byte[spec.blockSize];
        }
        new SymmetricEngine(spec, key, probeIv);
        return new CryptoEngine(spec, key, iv, mode, Codec.charset(charsetName));
    }

    /* ==================== 信息 ==================== */

    public CipherSpec spec() {
        return spec;
    }

    public IvMode ivMode() {
        return ivMode;
    }

    public Charset charset() {
        return charset;
    }

    public int blockSize() {
        return spec.blockSize;
    }

    public boolean hasPadding() {
        return spec.hasPadding();
    }

    /* ==================== 加解密 ==================== */

    public byte[] encrypt(byte[] plain) throws CryptoException {
        if (plain == null) {
            throw new CryptoException("明文为空");
        }
        if (ivMode == IvMode.PREPENDED || (ivMode == IvMode.AUTO && iv == null)) {
            byte[] randomIv = new byte[spec.blockSize];
            RANDOM.nextBytes(randomIv);
            SymmetricEngine engine = new SymmetricEngine(spec, key, randomIv);
            byte[] ct = engine.encrypt(plain);
            byte[] out = new byte[randomIv.length + ct.length];
            System.arraycopy(randomIv, 0, out, 0, randomIv.length);
            System.arraycopy(ct, 0, out, randomIv.length, ct.length);
            return out;
        }
        return new SymmetricEngine(spec, key, iv).encrypt(plain);
    }

    public byte[] decrypt(byte[] cipherBytes) throws CryptoException {
        if (cipherBytes == null || cipherBytes.length == 0) {
            throw new CryptoException("密文为空");
        }
        if (ivMode == IvMode.PREPENDED) {
            return decryptPrepended(cipherBytes);
        }
        if (ivMode == IvMode.AUTO) {
            return decryptAuto(cipherBytes);
        }
        return new SymmetricEngine(spec, key, iv).decrypt(cipherBytes);
    }

    /**
     * 自适应解密：先按固定 IV 解，解不出可读文本再按「前 16 字节是随机 IV」解。
     *
     * <p>为什么需要这个：不少小程序/App 的报文是 {@code base64(IV || AES-CBC(明文))}，
     * 真正的 IV 就在报文体最前面。配置里填固定 IV 去解，只有第一个分组会乱、
     * 后面全对——看起来像"前面一段乱码"，非常容易误判成算法或 Key 错了。</p>
     */
    private byte[] decryptAuto(byte[] cipherBytes) throws CryptoException {
        String firstError = null;
        if (iv != null) {
            try {
                byte[] plain = new SymmetricEngine(spec, key, iv).decrypt(cipherBytes);
                if (Codec.isPlainText(plain)) {
                    return plain;
                }
            } catch (CryptoException e) {
                firstError = e.getMessage();
            }
        }
        if (spec.blockSize > 0 && cipherBytes.length > spec.blockSize) {
            try {
                byte[] plain = decryptPrepended(cipherBytes);
                if (Codec.isPlainText(plain)) {
                    return plain;
                }
            } catch (CryptoException e) {
                if (firstError == null) {
                    firstError = e.getMessage();
                }
            }
        }
        throw new CryptoException("解密失败：固定 IV 与『前 " + spec.blockSize
                + " 字节作 IV』两种方式都解不出可读文本"
                + (firstError == null ? "" : "（" + firstError + "）"));
    }

    /** 按「前 blockSize 字节是随机 IV」解密（IV||CT）。 */
    private byte[] decryptPrepended(byte[] cipherBytes) throws CryptoException {
        int bs = spec.blockSize;
        if (cipherBytes.length <= bs) {
            throw new CryptoException("密文只有 " + cipherBytes.length + " 字节，不够切出前置 IV");
        }
        byte[] head = Arrays.copyOf(cipherBytes, bs);
        byte[] body = Arrays.copyOfRange(cipherBytes, bs, cipherBytes.length);
        return new SymmetricEngine(spec, key, head).decrypt(body);
    }

    public String encryptText(String plaintext) throws CryptoException {
        return Codec.decodeLenient(encrypt(plaintext.getBytes(charset)), charset);
    }

    public String decryptText(byte[] cipherBytes) throws CryptoException {
        return Codec.decodeLenient(decrypt(cipherBytes), charset);
    }

    /** 加密后的字节是否"看起来像文本"（用于判断密文编码是否选对了）。 */
    public boolean outputIsText() {
        return true;
    }
}
