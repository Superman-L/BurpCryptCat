package burp.script;

/**
 * 脚本相关的全局设置（Host 级，不属于某个方案）。
 *
 * <p>Python 解释器是全局的：同一台机器上通常只有一个/几个 Python，没必要每个方案填一遍。
 * 由 {@code CryptoService.update()} 与启动时从配置里灌进来。</p>
 */
public final class ScriptSettings {

    private static volatile String pythonCommand = "";

    private ScriptSettings() {
    }

    /** 全局 Python 解释器；空 = 自动探测（python3 → python）。 */
    public static String pythonCommand() {
        return pythonCommand;
    }

    public static void pythonCommand(String cmd) {
        pythonCommand = cmd == null ? "" : cmd.trim();
    }
}
