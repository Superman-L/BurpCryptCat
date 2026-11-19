package burp.crypto;

/** 加解密过程中的可预期失败（配置错误、填充错误、密钥长度不对……）。 */
public class CryptoException extends Exception {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
