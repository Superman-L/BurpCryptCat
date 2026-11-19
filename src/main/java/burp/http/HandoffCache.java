package burp.http;

import burp.crypto.Codec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * "这一步的明文是我们刚才解密出来的"这一事实的短期记账本。
 *
 * <p>为什么需要它：Proxy 的响应有两个可插入点 —— 收到响应时（进历史，展示给测试人员）
 * 和回写给客户端时（真正上线）。前者把密文换成明文，后者必须把明文换回密文。
 * 但如果响应本来就是明文（比如同域下的 HTML 页面），后者绝不能去加密它，
 * 否则会把正常流量搞坏。所以只在"这确实是本扩展刚解密出来的内容"时才回写密文。</p>
 *
 * <p>键用 (方向, URL, 明文 SHA-256)，不依赖 Burp 的 messageId，跨阶段也稳。</p>
 */
public final class HandoffCache {

    private static final long TTL_MILLIS = 5 * 60 * 1000L;
    private static final int MAX_ENTRIES = 5000;

    private final Map<String, Long> marks = new ConcurrentHashMap<>();

    /** 记下"这段明文是本扩展产生的"，等待回写阶段加密。 */
    public void mark(boolean request, String url, byte[] plain) {
        if (plain == null || plain.length == 0) {
            return;
        }
        if (marks.size() > MAX_ENTRIES) {
            sweep();
        }
        marks.put(key(request, url, plain), System.currentTimeMillis());
    }

    /** 这段明文是不是我们产生的？命中会刷新时间戳（处理重复回写）。 */
    public boolean contains(boolean request, String url, byte[] plain) {
        if (plain == null || plain.length == 0) {
            return false;
        }
        String k = key(request, url, plain);
        Long ts = marks.get(k);
        if (ts == null) {
            return false;
        }
        if (System.currentTimeMillis() - ts > TTL_MILLIS) {
            marks.remove(k);
            return false;
        }
        marks.put(k, System.currentTimeMillis());
        return true;
    }

    public void clear() {
        marks.clear();
    }

    private void sweep() {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Long>> it = marks.entrySet().iterator();
        while (it.hasNext()) {
            if (now - it.next().getValue() > TTL_MILLIS) {
                it.remove();
            }
        }
    }

    private static String key(boolean request, String url, byte[] plain) {
        return (request ? "Q|" : "S|") + (url == null ? "" : url) + "|" + sha256(plain);
    }

    private static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return Codec.toHex(md.digest(data)).substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(java.util.Arrays.hashCode(data));
        }
    }
}
