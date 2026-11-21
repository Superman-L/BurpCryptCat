package burp.support;

import java.io.PrintWriter;

/**
 * 统一日志出口（Burp 的 Extender → Output 面板）。
 *
 * <p>静态字段是有意的：Burp 扩展的生命周期是"加载 / 卸载"，一个静态的
 * PrintWriter 足够，也能让任意深度的工具类随手打日志而不必层层传参。</p>
 */
public final class Log {

    private static volatile PrintWriter out;
    private static volatile boolean debug;

    private Log() {
    }

    public static void init(PrintWriter writer, boolean debugEnabled) {
        out = writer;
        debug = debugEnabled;
    }

    public static void setDebug(boolean enabled) {
        debug = enabled;
    }

    public static boolean isDebug() {
        return debug;
    }

    public static void info(String msg) {
        println("[*] " + msg);
    }

    public static void step(String msg) {
        println("[+] " + msg);
    }

    public static void warn(String msg) {
        println("[!] " + msg);
    }

    public static void debug(String msg) {
        if (debug) {
            println("[d] " + msg);
        }
    }

    public static void error(String msg, Throwable t) {
        println("[x] " + msg + (t == null ? "" : ": " + t));
        if (debug && t != null) {
            PrintWriter w = out;
            if (w != null) {
                t.printStackTrace(w);
            } else {
                t.printStackTrace();
            }
        }
    }

    private static void println(String msg) {
        PrintWriter w = out;
        if (w != null) {
            synchronized (Log.class) {
                w.println(msg);
                w.flush();
            }
        } else {
            System.out.println(msg);
        }
    }
}
