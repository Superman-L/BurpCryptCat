package burp.transform;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 明文查看器的数据源：环形缓冲 + 变更通知。
 *
 * <p>线程安全：Burp 在多个工作线程里调用处理器，Swing 只在 EDT 读，因此这里用
 * synchronized 保护，并通过监听器让界面自己决定怎么切回 EDT。</p>
 */
public final class PlaintextLog {

    public static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    /** 一条记录 */
    public static final class Entry {
        public final long millis;
        public final String time;
        public final String source;
        public final String direction;
        public final String method;
        public final String host;
        public final String url;
        public final TransformResult.Kind kind;
        public final String detail;
        public final String plaintext;

        public Entry(String source, String direction, String method, String host, String url,
                     TransformResult result) {
            this.millis = System.currentTimeMillis();
            this.time = LocalTime.now().format(TIME_FMT);
            this.source = source;
            this.direction = direction;
            this.method = method;
            this.host = host;
            this.url = url;
            this.kind = result.kind;
            this.detail = result.detail;
            this.plaintext = result.plaintext;
        }

        public String plaintextPreview(int max) {
            return plaintext == null ? "" : burp.crypto.Codec.preview(plaintext, max);
        }
    }

    private final Deque<Entry> entries = new ArrayDeque<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private int limit = 1000;

    public synchronized void setLimit(int limit) {
        this.limit = Math.max(50, limit);
        trim();
    }

    public void add(Entry e) {
        synchronized (this) {
            entries.addFirst(e);
            trim();
        }
        for (Runnable r : listeners) {
            r.run();
        }
    }

    private void trim() {
        while (entries.size() > limit) {
            entries.removeLast();
        }
    }

    public synchronized List<Entry> snapshot() {
        return new ArrayList<>(entries);
    }

    public synchronized Entry get(int index) {
        if (index < 0 || index >= entries.size()) {
            return null;
        }
        int i = 0;
        for (Entry e : entries) {
            if (i++ == index) {
                return e;
            }
        }
        return null;
    }

    public synchronized int size() {
        return entries.size();
    }

    public synchronized void clear() {
        entries.clear();
    }

    public void addListener(Runnable r) {
        listeners.add(r);
    }
}
