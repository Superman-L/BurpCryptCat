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
 * <p>两套记忆：</p>
 * <ul>
 *   <li><b>按内容</b>（方向, URL, 明文 SHA-256）—— 覆盖"原样放行"，跨阶段稳定；</li>
 *   <li><b>按报文</b>（方向, messageId）—— 覆盖"用户在拦截/编辑器里把明文改过了"的情况：
 *       内容变了，但它仍然是同一条被我解密的报文，放行前必须重新加密。</li>
 * </ul>
 */
public final class HandoffCache {

    private static final long TTL_MILLIS = 5 * 60 * 1000L;
    private static final int MAX_ENTRIES = 5000;

    private final Map<String, Long> marks = new ConcurrentHashMap<>();
    private final Map<String, Long> messageMarks = new ConcurrentHashMap<>();
    /** (方向, messageId) → 收到时那份 Body 的摘要，用来判断用户到底改没改 */
    private final Map<String, Original> originals = new ConcurrentHashMap<>();

    private record Original(String sha, long at) {
    }

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

    /** 记下"这条报文（工具内 messageId）被我解密过" */
    public void markMessage(boolean request, int messageId) {
        if (messageId <= 0) {
            return;
        }
        if (messageMarks.size() > MAX_ENTRIES) {
            prune(messageMarks);
        }
        messageMarks.put(msgKey(request, messageId), System.currentTimeMillis());
    }

    /** 这条报文是否被我解密过（用户改过内容也算） */
    public boolean isMarkedMessage(boolean request, int messageId) {
        if (messageId <= 0) {
            return false;
        }
        String key = msgKey(request, messageId);
        Long ts = messageMarks.get(key);
        if (ts == null) {
            return false;
        }
        if (System.currentTimeMillis() - ts > TTL_MILLIS) {
            messageMarks.remove(key);
            return false;
        }
        messageMarks.put(key, System.currentTimeMillis());
        return true;
    }

    public void clear() {
        marks.clear();
        messageMarks.clear();
        originals.clear();
    }

    /**
     * 记下"收到时这份 Body 的原样"（通常是客户端发来的密文）。
     *
     * <p>默认模式下 Proxy 不再把收到的报文替换成明文，所以放行阶段拿到的
     * 可能还是这份原样密文；有了它就能判断"用户到底动没动过"，
     * 没动过就绝不能再加密一次（脚本方式没有幂等保证）。</p>
     */
    public void markOriginal(boolean request, int messageId, byte[] body) {
        if (messageId <= 0 || body == null || body.length == 0) {
            return;
        }
        if (originals.size() > MAX_ENTRIES) {
            pruneOriginals();
        }
        originals.put(msgKey(request, messageId), new Original(sha256(body), System.currentTimeMillis()));
    }

    /** 当前 Body 是否还是收到时那份原件（用户没改过）。 */
    public boolean isOriginal(boolean request, int messageId, byte[] body) {
        if (messageId <= 0 || body == null || body.length == 0) {
            return false;
        }
        String k = msgKey(request, messageId);
        Original o = originals.get(k);
        if (o == null) {
            return false;
        }
        if (System.currentTimeMillis() - o.at() > TTL_MILLIS) {
            originals.remove(k);
            return false;
        }
        return o.sha().equals(sha256(body));
    }

    private void pruneOriginals() {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Original>> it = originals.entrySet().iterator();
        while (it.hasNext()) {
            if (now - it.next().getValue().at() > TTL_MILLIS) {
                it.remove();
            }
        }
    }

    private static String msgKey(boolean request, int messageId) {
        return (request ? "Q#" : "S#") + messageId;
    }

    private static void prune(Map<String, Long> map) {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Long>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (now - it.next().getValue() > TTL_MILLIS) {
                it.remove();
            }
        }
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
