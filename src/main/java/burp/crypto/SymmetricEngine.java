package burp.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * 单次加/解密原语：给定算法、密钥、IV 处理一段二进制。
 *
 * <p>负责 JCE 与内置 SM4 的分发、填充对齐、错误信息翻译。无状态（每次调用新建
 * Cipher 实例），因此可以安全地在 Burp 的多个工作线程里共享。</p>
 */
public final class SymmetricEngine {

    private final CipherSpec spec;
    private final byte[] key;
    private final byte[] iv;
    private final BlockModes.Cipher sm4;

    public SymmetricEngine(CipherSpec spec, byte[] key, byte[] iv) throws CryptoException {
        this.spec = spec;
        this.key = key;
        this.iv = iv;
        if (key == null || key.length == 0) {
            throw new CryptoException("密钥为空");
        }
        if (spec.keyLengths.length > 0) {
            boolean ok = false;
            for (int len : spec.keyLengths) {
                if (key.length == len) {
                    ok = true;
                    break;
                }
            }
            if (!ok) {
                throw new CryptoException("密钥长度 " + key.length + " 字节，与 " + spec.family + " 不匹配");
            }
        }
        if (spec.requiresIv() && (iv == null || iv.length == 0)) {
            throw new CryptoException(spec.mode + " 模式需要 IV");
        }
        this.sm4 = "SM4".equals(spec.family) ? new Sm4Cipher(key) : null;
    }

    public CipherSpec spec() {
        return spec;
    }

    /* ==================== 对外 ==================== */

    public byte[] encrypt(byte[] plain) throws CryptoException {
        return doFinal(Cipher.ENCRYPT_MODE, plain);
    }

    public byte[] decrypt(byte[] cipherBytes) throws CryptoException {
        return doFinal(Cipher.DECRYPT_MODE, cipherBytes);
    }

    /* ==================== 实现 ==================== */

    private byte[] doFinal(int mode, byte[] data) throws CryptoException {
        if (data == null) {
            throw new CryptoException("数据为空");
        }
        int block = spec.blockSize;
        boolean encrypt = mode == Cipher.ENCRYPT_MODE;

        // 内置 SM4：JCE 不参与，填充也要自己做
        if (sm4 != null) {
            if (block > 0 && spec.hasPadding() && spec.isBlockMode()) {
                data = encrypt ? Padding.pad(data, block, spec.padding) : data;
            }
            if (spec.isBlockMode() && data.length % block != 0) {
                throw new CryptoException((encrypt ? "明文" : "密文") + "长度 " + data.length
                        + " 不是分组 " + block + " 的整数倍");
            }
            byte[] out = sm4Raw(mode, data);
            if (!encrypt && block > 0 && spec.hasPadding() && spec.isBlockMode()) {
                out = Padding.unpad(out, block, spec.padding);
            }
            return out;
        }

        if (spec.isZeroPadding()) {
            if (block > 0) {
                data = encrypt ? zeroPad(data, block) : data;
                if (data.length % block != 0) {
                    throw new CryptoException("密文长度 " + data.length + " 不是分组 " + block + " 的整数倍");
                }
            }
            byte[] out = raw(mode, data);
            return encrypt ? out : zeroUnpad(out);
        }

        if (spec.isBlockMode() && !spec.hasPadding() && data.length % block != 0) {
            throw new CryptoException((encrypt ? "明文" : "密文") + "长度 " + data.length
                    + " 不是分组 " + block + " 的整数倍（当前为 NoPadding）");
        }

        return raw(mode, data);
    }

    private byte[] raw(int mode, byte[] data) throws CryptoException {
        long expect = spec.isBlockMode() && spec.hasPadding() && mode == Cipher.DECRYPT_MODE
                ? spec.blockSize : 0;
        if (expect > 0 && data.length % expect != 0) {
            throw new CryptoException("密文长度 " + data.length + " 不是分组 " + expect + " 的整数倍");
        }
        if (sm4 != null) {
            return sm4Raw(mode, data);
        }
        try {
            Cipher cipher = Cipher.getInstance(spec.jceTransformation());
            SecretKeySpec keySpec = new SecretKeySpec(key, jceKeyAlgorithm());
            switch (mode) {
                case Cipher.ENCRYPT_MODE -> {
                    initEncrypt(cipher, keySpec);
                    return cipher.doFinal(data);
                }
                case Cipher.DECRYPT_MODE -> {
                    initDecrypt(cipher, keySpec);
                    return cipher.doFinal(data);
                }
                default -> throw new CryptoException("不支持的模式");
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException(translate(e, mode), e);
        }
    }

    private void initEncrypt(Cipher cipher, SecretKeySpec keySpec) throws GeneralSecurityException {
        if (spec.aead) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
        } else if (spec.ivLength > 0) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        }
    }

    private void initDecrypt(Cipher cipher, SecretKeySpec keySpec) throws GeneralSecurityException {
        if (spec.aead) {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
        } else if (spec.ivLength > 0) {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        }
    }

    private String jceKeyAlgorithm() {
        return switch (spec.family) {
            case "ChaCha20" -> "ChaCha20";
            case "RC4" -> "ARCFOUR";
            default -> spec.family;
        };
    }

    private byte[] sm4Raw(int mode, byte[] data) throws CryptoException {
        boolean encrypt = mode == Cipher.ENCRYPT_MODE;
        String m = spec.mode;
        try {
            return switch (m) {
                case "ECB" -> BlockModes.ecb(sm4, data, encrypt);
                case "CBC" -> BlockModes.cbc(sm4, iv, data, encrypt);
                case "CFB" -> BlockModes.cfb(sm4, iv, data, encrypt);
                case "OFB" -> BlockModes.ofb(sm4, iv, data, encrypt);
                case "CTR" -> BlockModes.ctr(sm4, iv, data, encrypt);
                default -> throw new CryptoException("SM4 暂不支持 " + m + " 模式（支持 ECB/CBC/CFB/OFB/CTR）");
            };
        } catch (IllegalArgumentException e) {
            throw new CryptoException(e.getMessage(), e);
        }
    }

    private String translate(GeneralSecurityException e, int mode) {
        String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        String lower = msg.toLowerCase();
        if (lower.contains("padding") || e instanceof javax.crypto.BadPaddingException) {
            return "解密失败：填充错误（密钥/IV/算法/编码不匹配，或数据本来就不是密文）";
        }
        if (lower.contains("invalid key") || lower.contains("keysize")) {
            return "密钥长度不合法：" + msg;
        }
        if (lower.contains("iv") || lower.contains("parameter")) {
            return "IV 不合法：" + msg;
        }
        if (lower.contains("aead") || lower.contains("tag")) {
            return "GCM 校验失败（密钥/IV 不匹配或密文被截断）";
        }
        return (mode == Cipher.ENCRYPT_MODE ? "加密失败：" : "解密失败：") + msg;
    }

    /* ==================== 零填充 ==================== */

    static byte[] zeroPad(byte[] data, int block) {
        int pad = (block - data.length % block) % block;
        if (pad == 0) {
            return data;
        }
        byte[] out = Arrays.copyOf(data, data.length + pad);
        return out;
    }

    static byte[] zeroUnpad(byte[] data) {
        int end = data.length;
        while (end > 0 && data[end - 1] == 0) {
            end--;
        }
        return Arrays.copyOf(data, end);
    }

    /** 内置 SM4 分组原语适配器。 */
    private static final class Sm4Cipher implements BlockModes.Cipher {
        private final int[] rk;

        Sm4Cipher(byte[] key) {
            this.rk = Sm4.expandKey(key);
        }

        @Override
        public int blockSize() {
            return 16;
        }

        @Override
        public void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
            Sm4.encryptBlock(rk, in, inOff, out, outOff);
        }

        @Override
        public void decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
            Sm4.decryptBlock(rk, in, inOff, out, outOff);
        }
    }
}
