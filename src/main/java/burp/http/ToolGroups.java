package burp.http;

import burp.config.AppConfig;
import burp.api.montoya.core.ToolType;

/** Burp 的 ToolType → 配置里的工具分组。 */
public final class ToolGroups {

    private ToolGroups() {
    }

    public static AppConfig.ToolGroup of(ToolType type) {
        if (type == null) {
            return AppConfig.ToolGroup.OTHER;
        }
        return switch (type) {
            case PROXY -> AppConfig.ToolGroup.PROXY;
            case REPEATER -> AppConfig.ToolGroup.REPEATER;
            case INTRUDER -> AppConfig.ToolGroup.INTRUDER;
            default -> AppConfig.ToolGroup.OTHER;
        };
    }
}
