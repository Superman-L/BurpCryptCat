package burp.crypto;

import java.util.Arrays;

/**
 * SM4 的工作模式：ECB / CBC / CFB / OFB / CTR。
 *
 * <p>接口只要求一个"分组加密原语"，模式逻辑与具体算法无关。数据必须是分组长度
 * 的整数倍（填充由上层 {@link SymmetricEngine} 负责）。</p>
 */
public final class BlockModes {

    /** 分组加密原语。 */
    public interface Cipher {
        int blockSize();

        void encryptBlock(byte[] in, int inOff, byte[] out, int outOff);

        void decryptBlock(byte[] in, int inOff, byte[] out, int outOff);
    }

    private BlockModes() {
    }

    public static byte[] ecb(Cipher c, byte[] data, boolean encrypt) {
        int bs = c.blockSize();
        checkAligned(data.length, bs);
        byte[] out = new byte[data.length];
        for (int off = 0; off < data.length; off += bs) {
            if (encrypt) {
                c.encryptBlock(data, off, out, off);
            } else {
                c.decryptBlock(data, off, out, off);
            }
        }
        return out;
    }

    public static byte[] cbc(Cipher c, byte[] iv, byte[] data, boolean encrypt) throws CryptoException {
        int bs = c.blockSize();
        checkAligned(data.length, bs);
        if (iv == null || iv.length != bs) {
            throw new CryptoException("CBC 需要 " + bs + " 字节 IV");
        }
        byte[] out = new byte[data.length];
        byte[] chain = Arrays.copyOf(iv, bs);
        for (int off = 0; off < data.length; off += bs) {
            if (encrypt) {
                byte[] block = new byte[bs];
                for (int i = 0; i < bs; i++) {
                    block[i] = (byte) (data[off + i] ^ chain[i]);
                }
                c.encryptBlock(block, 0, out, off);
                System.arraycopy(out, off, chain, 0, bs);
            } else {
                byte[] block = new byte[bs];
                c.decryptBlock(data, off, block, 0);
                for (int i = 0; i < bs; i++) {
                    out[off + i] = (byte) (block[i] ^ chain[i]);
                }
                System.arraycopy(data, off, chain, 0, bs);
            }
        }
        return out;
    }

    public static byte[] cfb(Cipher c, byte[] iv, byte[] data, boolean encrypt) throws CryptoException {
        int bs = c.blockSize();
        if (iv == null || iv.length != bs) {
            throw new CryptoException("CFB 需要 " + bs + " 字节 IV");
        }
        byte[] out = new byte[data.length];
        byte[] chain = Arrays.copyOf(iv, bs);
        byte[] ks = new byte[bs];
        for (int off = 0; off < data.length; off += bs) {
            c.encryptBlock(chain, 0, ks, 0);
            int n = Math.min(bs, data.length - off);
            for (int i = 0; i < n; i++) {
                out[off + i] = (byte) (data[off + i] ^ ks[i]);
            }
            // 反馈：密文（加解密一致）
            System.arraycopy(out, off, chain, 0, n);
        }
        return out;
    }

    public static byte[] ofb(Cipher c, byte[] iv, byte[] data, boolean encrypt) throws CryptoException {
        int bs = c.blockSize();
        if (iv == null || iv.length != bs) {
            throw new CryptoException("OFB 需要 " + bs + " 字节 IV");
        }
        byte[] out = new byte[data.length];
        byte[] chain = Arrays.copyOf(iv, bs);
        byte[] ks = new byte[bs];
        for (int off = 0; off < data.length; off += bs) {
            c.encryptBlock(chain, 0, ks, 0);
            System.arraycopy(ks, 0, chain, 0, bs);
            int n = Math.min(bs, data.length - off);
            for (int i = 0; i < n; i++) {
                out[off + i] = (byte) (data[off + i] ^ ks[i]);
            }
        }
        return out;
    }

    public static byte[] ctr(Cipher c, byte[] iv, byte[] data, boolean encrypt) throws CryptoException {
        int bs = c.blockSize();
        if (iv == null || iv.length != bs) {
            throw new CryptoException("CTR 需要 " + bs + " 字节 IV");
        }
        byte[] out = new byte[data.length];
        byte[] counter = Arrays.copyOf(iv, bs);
        byte[] ks = new byte[bs];
        for (int off = 0; off < data.length; off += bs) {
            c.encryptBlock(counter, 0, ks, 0);
            int n = Math.min(bs, data.length - off);
            for (int i = 0; i < n; i++) {
                out[off + i] = (byte) (data[off + i] ^ ks[i]);
            }
            increment(counter);
        }
        return out;
    }

    /** 128 位大端计数器自增。 */
    private static void increment(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            if (++counter[i] != 0) {
                return;
            }
        }
    }

    private static void checkAligned(int length, int blockSize) {
        if (length % blockSize != 0) {
            throw new IllegalArgumentException(
                    "数据长度 " + length + " 不是分组长度 " + blockSize + " 的整数倍");
        }
    }
}
