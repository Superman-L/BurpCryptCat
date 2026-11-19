package burp.script;

import org.mozilla.javascript.BaseFunction;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.Script;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.mozilla.javascript.Undefined;
import org.mozilla.javascript.WrapFactory;
import org.mozilla.javascript.NativeJavaObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JavaScript 脚本执行器（Rhino 1.7.15，解释模式，JDK 17/21 都能跑）。
 *
 * <p>脚本里只需要实现四个同名的函数之一或多个：</p>
 * <pre>
 *   function clientToBurp(ctx) { return ctx.body; }   // ① 客户端 → Burp
 *   function burpToServer(ctx) { return ctx.body; }   // ② Burp → 服务端
 *   function serverToBurp(ctx) { return ctx.body; }   // ③ 服务端 → Burp
 *   function burpToClient(ctx) { return ctx.body; }   // ④ Burp → 客户端
 * </pre>
 *
 * <p>返回值：字符串 = 新 Body；null/undefined = 不改动；{body: "…"} 也可以。
 * 脚本出错一律"不改动 + 报告原因"，不影响 Burp 正常转发。</p>
 */
public final class JsScriptRunner {

    /** 编译结果缓存：路径 → (mtime,size) → 已编译脚本 */
    private static final Map<String, Cached> CACHE = new ConcurrentHashMap<>();

    private static final class Cached {
        final Script script;
        final long mtime;
        final long size;
        final List<String> hooks;

        Cached(Script script, long mtime, long size, List<String> hooks) {
            this.script = script;
            this.mtime = mtime;
            this.size = size;
            this.hooks = hooks;
        }
    }

    private JsScriptRunner() {
    }

    /* ==================== 对外 ==================== */

    public static ScriptOutcome run(File file, ScriptCall call) {
        if (file == null || !file.isFile()) {
            return ScriptOutcome.failed("脚本文件不存在：" + (file == null ? "" : file.getPath()));
        }
        try {
            Cached cached = load(file);
            if (cached == null) {
                return ScriptOutcome.failed("脚本编译失败：" + file.getName());
            }
            if (!cached.hooks.contains(call.stage.hook())) {
                return ScriptOutcome.unchanged("脚本未实现 " + call.stage.hook() + "()，跳过");
            }
            return invoke(file, cached, call);
        } catch (Throwable e) {
            return ScriptOutcome.failed("脚本执行异常：" + e);
        }
    }

    /** 该脚本实现了哪些钩子（给界面显示用）。 */
    public static List<String> hooksOf(File file) {
        try {
            Cached c = load(file);
            return c == null ? Collections.emptyList() : c.hooks;
        } catch (Throwable e) {
            return Collections.emptyList();
        }
    }

    /** 清掉缓存（界面点"重新载入脚本"时用）。 */
    public static void invalidate(File file) {
        if (file != null) {
            CACHE.remove(file.getAbsolutePath());
        }
    }

    /* ==================== 实现 ==================== */

    private static Cached load(File file) throws Exception {
        String key = file.getAbsolutePath();
        long mtime = file.lastModified();
        long size = file.length();
        Cached old = CACHE.get(key);
        if (old != null && old.mtime == mtime && old.size == size) {
            return old;
        }
        String source = Files.readString(file.toPath(), StandardCharsets.UTF_8);

        Context cx = Context.enter();
        try {
            cx.setOptimizationLevel(-1);            // 解释执行，避免动态生成字节码在 JDK21 上的兼容问题
            cx.setLanguageVersion(Context.VERSION_ES6);
            Script script = cx.compileString(source, file.getName(), 1, null);
            Scriptable scope = newScope(cx);
            script.exec(cx, scope);
            List<String> hooks = new ArrayList<>();
            for (ScriptStage st : ScriptStage.values()) {
                Object fn = scope.get(st.hook(), scope);
                if (fn instanceof Function) {
                    hooks.add(st.hook());
                }
            }
            Cached cached = new Cached(script, mtime, size, hooks);
            CACHE.put(key, cached);
            return cached;
        } finally {
            Context.exit();
        }
    }

    private static Scriptable newScope(Context cx) {
        Scriptable scope = cx.initStandardObjects();
        // 让 crypto.xxx() 返回的 Java String 直接变成 JS 字符串，脚本里才能 a + b、s.toUpperCase()
        cx.setWrapFactory(new WrapFactory() {
            @Override
            public Object wrap(Context c, Scriptable sc, Object obj, Class<?> staticType) {
                if (obj instanceof String || obj instanceof Number || obj instanceof Boolean) {
                    return obj;
                }
                return super.wrap(c, sc, obj, staticType);
            }
        });
        scope.put("crypto", scope, Context.javaToJS(new ScriptUtils(), scope));
        return scope;
    }

    private static ScriptOutcome invoke(File file, Cached cached, ScriptCall call) {
        Context cx = Context.enter();
        try {
            cx.setOptimizationLevel(-1);
            cx.setLanguageVersion(Context.VERSION_ES6);
            Scriptable scope = newScope(cx);
            cached.script.exec(cx, scope);          // 重新定义函数（编译已缓存，执行很快）

            Function fn = (Function) scope.get(call.stage.hook(), scope);
            Scriptable ctxObj = buildCtx(cx, scope, call);
            Object result = fn.call(cx, scope, scope, new Object[]{ctxObj});
            return toOutcome(cx, result, call);
        } catch (Throwable e) {
            return ScriptOutcome.failed("脚本 " + call.stage.hook() + "() 抛异常：" + e);
        } finally {
            Context.exit();
        }
    }

    private static Scriptable buildCtx(Context cx, Scriptable scope, ScriptCall call) {
        ScriptableObject ctx = (ScriptableObject) cx.newObject(scope);
        ctx.put("stage", ctx, call.stage.name());
        ctx.put("stageCode", ctx, call.stage.code());
        ctx.put("stageLabel", ctx, call.stage.label());
        ctx.put("hook", ctx, call.stage.hook());
        ctx.put("url", ctx, call.url);
        ctx.put("method", ctx, call.method);
        ctx.put("isRequest", ctx, call.isRequest);
        ctx.put("charset", ctx, call.charset.name());
        ctx.put("profile", ctx, call.profileName);
        ctx.put("body", ctx, call.bodyText());
        Object[] hs = call.headers.toArray();
        ctx.put("headers", ctx, cx.newArray(scope, hs));

        // ctx.log(msg)
        ctx.put("log", ctx, new BaseFunction() {
            @Override
            public Object call(Context c, Scriptable s, Scriptable thisObj, Object[] args) {
                burp.support.Log.info("[script] " + (args.length > 0 ? Context.toString(args[0]) : ""));
                return Undefined.instance;
            }
        });
        // ctx.header("x-iv")
        ctx.put("header", ctx, new BaseFunction() {
            @Override
            public Object call(Context c, Scriptable s, Scriptable thisObj, Object[] args) {
                String v = call.header(args.length > 0 ? Context.toString(args[0]) : null);
                return v == null ? Undefined.instance : v;
            }
        });
        return ctx;
    }

    private static ScriptOutcome toOutcome(Context cx, Object result, ScriptCall call) {
        if (result == null || result == Undefined.instance || result instanceof Undefined) {
            return ScriptOutcome.unchanged("脚本返回空，保持原样");
        }
        if (result instanceof CharSequence) {
            return changed(cx, Context.toString(result), call);
        }
        if (result instanceof NativeJavaObject njo) {
            Object unwrapped = njo.unwrap();
            if (unwrapped == null) {
                return ScriptOutcome.unchanged("脚本返回空，保持原样");
            }
            if (unwrapped instanceof CharSequence) {
                return changed(cx, unwrapped.toString(), call);
            }
            result = unwrapped;
        }
        if (result instanceof Scriptable obj) {
            Object body = ScriptableObject.getProperty(obj, "body");
            if (body instanceof CharSequence) {
                return changed(cx, Context.toString(body), call);
            }
            return ScriptOutcome.unchanged("脚本返回对象但没有 body 字段，保持原样");
        }
        return ScriptOutcome.unchanged("脚本返回值类型不支持（" + result.getClass().getSimpleName() + "），保持原样");
    }

    private static ScriptOutcome changed(Context cx, String text, ScriptCall call) {
        if (text == null) {
            return ScriptOutcome.unchanged("脚本返回 null");
        }
        if (text.length() > 16 * 1024 * 1024) {
            return ScriptOutcome.failed("脚本返回内容过大（>16MB），已忽略");
        }
        byte[] out = text.getBytes(call.charset);
        boolean same = java.util.Arrays.equals(out, call.body);
        if (same) {
            return ScriptOutcome.unchanged("脚本输出与原 Body 相同");
        }
        return ScriptOutcome.changed(out, call.stage.hook() + "() 已处理");
    }
}
