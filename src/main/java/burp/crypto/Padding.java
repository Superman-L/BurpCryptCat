package burp.crypto;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 内置实现（SM4）用的填充算法。JCE 支持的算法走 JCE 自带填充，这里只服务于
 * "自己实现分组密码"的那条路径。
 */
public final class Padding {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Padding() {
    }

    public static byte[] pad(byte[] data, int block, String padding) {
        int padLen = block - data.length % block;
        byte[] out = Arrays.copyOf(data, data.length + padLen);
        switch (padding) {
            case CipherSpec.ZERO -> {
                // 已由 Arrays.copyOf 补 0；若本来就对齐，则不加整块（与常见实现一致）
                if (data.length % block == 0) {
                    return data;
                }
            }
            case CipherSpec.ISO10126 -> {
                byte[] rnd = new byte[padLen - 1];
                RANDOM.nextBytes(rnd);
                System.arraycopy(rnd, 0, out, data.length, rnd.length);
                out[out.length - 1] = (byte) padLen;
            }
            case CipherSpec.ANSIX923 -> {
                // 前面的填充位全 0，最后一个字节是填充长度（Arrays.copyOf 已经补 0）
                out[out.length - 1] = (byte) padLen;
            }
            default -> {
                for (int i = data.length; i < out.length; i++) {
                    out[i] = (byte) padLen;
                }
            }
        }
        return out;
    }

    public static byte[] unpad(byte[] data, int block, String padding) throws CryptoException {
        if (data.length == 0 || data.length % block != 0) {
            throw new CryptoException("密文长度 " + data.length + " 不是分组 " + block + " 的整数倍");
        }
        if (CipherSpec.ZERO.equals(padding)) {
            return zeroUnpad(data);
        }
        int padLen = data[data.length - 1] & 0xFF;
        if (padLen == 0 || padLen > block) {
            throw new CryptoException("填充错误：填充长度非法 (" + padLen + ")");
        }
        if (CipherSpec.PKCS5.equals(padding)) {
            for (int i = data.length - padLen; i < data.length; i++) {
                if ((data[i] & 0xFF) != padLen) {
                    throw new CryptoException("填充错误：PKCS 填充字节不一致");
                }
            }
        }
        return Arrays.copyOf(data, data.length - padLen);
    }

    public static byte[] zeroUnpad(byte[] data) {
        int end = data.length;
        while (end > 0 && data[end - 1] == 0) {
            end--;
        }
        return Arrays.copyOf(data, end);
    }
}
