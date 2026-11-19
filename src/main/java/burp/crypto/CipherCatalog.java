package burp.crypto;

import java.util.ArrayList;
import java.util.List;

/**
 * UI 下拉框用的算法清单。顺序即展示顺序，常用的排前面。
 *
 * <p>之所以不穷举所有"算法/模式/填充"组合，是因为用户大多数时候只想要一个
 * 直观的选项；下拉框允许直接编辑，罕见组合手打即可。</p>
 */
public final class CipherCatalog {

    private CipherCatalog() {
    }

    public static final String[] SUGGESTIONS = {
            "AES/CBC/PKCS5Padding",
            "AES/ECB/PKCS5Padding",
            "AES/CBC/NoPadding",
            "AES/CBC/ZeroPadding",
            "AES/CBC/ISO10126Padding",
            "AES/CFB/NoPadding",
            "AES/OFB/NoPadding",
            "AES/CTR/NoPadding",
            "AES/GCM/NoPadding",
            "SM4/CBC/PKCS5Padding",
            "SM4/ECB/PKCS5Padding",
            "SM4/CBC/NoPadding",
            "SM4/CBC/ZeroPadding",
            "SM4/CTR/NoPadding",
            "SM4/CFB/NoPadding",
            "SM4/OFB/NoPadding",
            "DES/CBC/PKCS5Padding",
            "DES/ECB/PKCS5Padding",
            "DES/CBC/ZeroPadding",
            "DESede/CBC/PKCS5Padding",
            "DESede/ECB/PKCS5Padding",
            "DESede/CFB/NoPadding",
            "RC4",
            "ChaCha20",
    };

    /** 常见算法的示例密钥长度提示，用于 UI 校验提示。 */
    public static List<String> hints(String transformation) {
        List<String> out = new ArrayList<>();
        try {
            CipherSpec spec = CipherSpec.of(transformation);
            out.add(spec.describe());
        } catch (CryptoException e) {
            out.add("无法识别：" + e.getMessage());
        }
        return out;
    }
}
