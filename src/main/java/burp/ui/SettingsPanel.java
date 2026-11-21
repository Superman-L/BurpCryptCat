package burp.ui;

import burp.config.AppConfig;
import burp.config.Profile;
import burp.support.Log;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.util.EnumMap;
import java.util.Map;

/**
 * 「全局设置」：总开关、生效工具、Proxy 的两个"重新加密"开关、兜底方案、日志。
 *
 * <p>Proxy 那两个开关是本次二次开发里唯一做了取舍的地方，界面上直接把 Burp 的
 * 限制写出来：Proxy 历史存的就是最终上线/回写的那份报文，因此"历史显示明文"
 * 与"线上保持密文"只能二选一。</p>
 */
public final class SettingsPanel extends JPanel {

    private final UiContext ctx;
    private final JCheckBox master = new JCheckBox("启用自动加解密（总开关）");
    private final Map<AppConfig.ToolGroup, JCheckBox> tools = new EnumMap<>(AppConfig.ToolGroup.class);
    private final JCheckBox allTools = new JCheckBox("对所有工具生效（顶层开关：Proxy / Repeater / Intruder / Scanner / 其它插件）");
    private final JLabel configPath = new JLabel();
    private final JCheckBox proxyEnabled = new JCheckBox("Proxy 参与透明加解密");
    private final JCheckBox reencryptRequest = new JCheckBox("请求放行前重新加密（服务端收到密文）");
    private final JCheckBox reencryptResponse = new JCheckBox("响应回写前重新加密（客户端收到密文）");
    private final JLabel proxyHint = new JLabel();
    private final JCheckBox debug = new JCheckBox("输出调试日志（Extender → Output）");
    private final JCheckBox beautify = new JCheckBox("明文页签里美化 JSON（自动缩进，默认开）");
    private final JTextField pythonField = new JTextField();
    private final JLabel pythonHint = Ui.hint(" ");
    private final JSpinner logLimit = new JSpinner(new SpinnerNumberModel(1000, 50, 100000, 100));
    private final JComboBox<String> fallback = new JComboBox<>();

    public SettingsPanel(UiContext ctx) {
        super(new BorderLayout(8, 8));
        this.ctx = ctx;
        setBorder(new EmptyBorder(12, 14, 12, 14));

        JPanel body = new JPanel(new GridLayout(0, 1, 6, 6));

        JPanel masterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        masterRow.add(master);
        body.add(masterRow);

        // 配置文件位置：默认 ~/.BurpCrypto/config，可换目录
        JPanel cfgRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        cfgRow.add(new JLabel("配置文件："));
        configPath.setFont(configPath.getFont().deriveFont(Font.PLAIN, 11f));
        configPath.setForeground(Ui.MUTED);
        cfgRow.add(configPath);
        cfgRow.add(Ui.button("选择目录…", this::onChooseDir));
        cfgRow.add(Ui.button("重新载入", this::onReloadFromFile));
        cfgRow.add(Ui.button("打开目录", this::onOpenDir));
        body.add(cfgRow);

        JPanel allRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        allRow.add(allTools);
        body.add(allRow);

        JPanel toolRows = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        toolRows.add(new JLabel("生效工具（细分）："));
        for (AppConfig.ToolGroup g : AppConfig.ToolGroup.values()) {
            JCheckBox box = new JCheckBox(g.label());
            tools.put(g, box);
            toolRows.add(box);
        }
        body.add(toolRows);

        JPanel proxyRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        proxyRow.add(proxyEnabled);
        proxyRow.add(reencryptRequest);
        proxyRow.add(reencryptResponse);
        body.add(proxyRow);

        proxyHint.setFont(proxyHint.getFont().deriveFont(11f));
        proxyHint.setForeground(Ui.MUTED);
        proxyHint.setBorder(BorderFactory.createEmptyBorder(0, 8, 6, 8));
        body.add(proxyHint);

        // Python 解释器（脚本方式共用）：标签 + 输入框 + 按钮贴在一起，不留大空隙
        JPanel pyRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        pyRow.add(new JLabel("Python 解释器："));
        pythonField.setPreferredSize(new Dimension(340, 26));
        pythonField.setToolTipText("留空 = 自动探测 python3 / python；也可填绝对路径或 venv 里的 python");
        pyRow.add(pythonField);
        pyRow.add(Ui.button("浏览…", this::onPickPython));
        pyRow.add(Ui.button("检测", this::onDetectPython));
        body.add(pyRow);
        body.add(pythonHint);

        JPanel fallbackRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        fallbackRow.add(new JLabel("兜底方案（未命中任何规则时使用）："));
        fallback.setPreferredSize(new Dimension(280, 26));
        fallbackRow.add(fallback);
        body.add(fallbackRow);

        JPanel logRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        logRow.add(new JLabel("明文查看器最多保留条数："));
        logRow.add(logLimit);
        logRow.add(debug);
        body.add(logRow);

        JPanel beautifyRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        beautifyRow.add(beautify);
        body.add(beautifyRow);


        JPanel saveRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        saveRow.add(Ui.button("保存设置", this::onSave));
        saveRow.add(Ui.button("恢复默认配置（示例）", this::onReset));
        body.add(saveRow);

        add(body, BorderLayout.NORTH);
        JLabel footnote = new JLabel("<html>提示：改完点「保存设置」。<br>"
                + "· Repeater / Intruder 不受上面两个 Proxy 开关影响。<br>"
                + "· 勾上「对所有工具生效」后，Scanner、xia SQL 等插件发出的请求也会被自动加密、"
                + "收到的响应自动解密。<br>"
                + "· 但要注意：这些插件拿到的<b>请求本身得是明文</b>它们才插得进 Payload —— "
                + "所以配合它们用时，建议用「历史明文模式」（把两个『重新加密』关掉），"
                + "或从「BurpCryptCat明文」页签 / 右键『解密后发送到 Repeater』出发。</html>");
        footnote.setFont(footnote.getFont().deriveFont(11f));
        footnote.setForeground(Ui.MUTED);
        add(footnote, BorderLayout.SOUTH);

        allTools.addActionListener(e -> {
            boolean on = allTools.isSelected();
            for (JCheckBox box : tools.values()) {
                box.setSelected(on);
            }
            updateHint();
        });
        reencryptRequest.addActionListener(e -> updateHint());
        reencryptResponse.addActionListener(e -> updateHint());
        proxyEnabled.addActionListener(e -> updateHint());

        ctx.onConfigChanged(this::reload);
        reload();
    }

    private void reload() {
        AppConfig cfg = ctx.config();
        master.setSelected(cfg.masterEnabled);
        for (var e : tools.entrySet()) {
            e.getValue().setSelected(cfg.toolEnabled(e.getKey()));
        }
        allTools.setSelected(cfg.allToolsEnabled());
        configPath.setText(ctx.store.describe());
        pythonField.setText(cfg.pythonCommand == null ? "" : cfg.pythonCommand);
        updatePythonHint();
        proxyEnabled.setSelected(cfg.proxyEnabled);
        reencryptRequest.setSelected(cfg.proxyReencryptRequest);
        reencryptResponse.setSelected(cfg.proxyReencryptResponse);
        debug.setSelected(cfg.debug);
        beautify.setSelected(cfg.beautifyJson);
        logLimit.setValue(cfg.logLimit);

        fallback.removeAllItems();
        fallback.addItem("（不使用兜底）");
        for (Profile p : cfg.profiles) {
            fallback.addItem(p.name + "  [" + p.id + "]");
        }
        Profile fb = cfg.profile(cfg.fallbackProfileId);
        int idx = fb == null ? 0 : cfg.profiles.indexOf(fb) + 1;
        fallback.setSelectedIndex(Math.max(0, idx));
        updateHint();
    }

    private void updateHint() {
        if (!proxyEnabled.isSelected()) {
            proxyHint.setText("Proxy 不处理：历史里看到的是原始密文。Repeater / Intruder 仍然自动加解密。");
            proxyHint.setForeground(Ui.MUTED);
            return;
        }
        boolean req = reencryptRequest.isSelected();
        boolean resp = reencryptResponse.isSelected();
        if (req && resp) {
            proxyHint.setText("当前：线上全密文（服务端与客户端都收到密文）。"
                    + "Proxy 请求侧可切 Original request（原始密文）/ Edited request（解密后的明文）；"
                    + "响应保持原样，明文看「BurpCryptCat明文（响应）」页签。");
            proxyHint.setForeground(Ui.MUTED);
            return;
        }
        StringBuilder sb = new StringBuilder("当前：历史显示明文，但");
        if (!req) {
            sb.append("服务端会收到明文请求");
        }
        if (!req && !resp) {
            sb.append("、");
        }
        if (!resp) {
            sb.append("客户端会收到明文响应");
        }
        sb.append("（目标程序可能因此报错，适合用 Burp 自己发包/测接口时使用）。");
        proxyHint.setText(sb.toString());
        proxyHint.setForeground(Ui.WARN);
    }

    /* ==================== 配置文件位置 ==================== */

    private void onChooseDir() {
        javax.swing.JFileChooser chooser = new javax.swing.JFileChooser();
        chooser.setFileSelectionMode(javax.swing.JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("选择配置保存目录（会生成 config 文件）");
        chooser.setSelectedFile(ctx.store.directory());
        if (chooser.showOpenDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File dir = chooser.getSelectedFile();
        java.io.File target = burp.config.ConfigFile.fileIn(dir);
        if (burp.config.ConfigFile.exists(target)) {
            int choice = javax.swing.JOptionPane.showOptionDialog(this,
                    "该目录里已经有配置：\n" + target.getAbsolutePath()
                            + "\n\n要载入它，还是用当前配置覆盖它？",
                    "切换配置目录", javax.swing.JOptionPane.YES_NO_CANCEL_OPTION,
                    javax.swing.JOptionPane.QUESTION_MESSAGE, null,
                    new Object[]{"载入该目录的配置", "用当前配置覆盖", "取消"}, "载入该目录的配置");
            if (choice == 2 || choice == javax.swing.JOptionPane.CLOSED_OPTION) {
                return;
            }
            if (choice == 0) {
                ctx.store.setDirectory(dir, false);
                ctx.reloadFromStore();
                reload();
                Ui.info(this, "已切换", "已载入该目录的配置：\n" + ctx.store.describe()
                        + "\n\n方案 " + ctx.config().profiles.size() + " 个，规则 "
                        + ctx.config().rules.size() + " 条");
                return;
            }
            ctx.store.setDirectory(dir, true);
            ctx.commit("切换配置目录");
            reload();
            Ui.info(this, "已切换", "当前配置已写入：\n" + ctx.store.describe());
            return;
        }
        // 新目录：把当前配置写过去，切过去就能直接继续用
        ctx.store.setDirectory(dir, true);
        ctx.commit("切换配置目录");
        reload();
        Ui.info(this, "已切换", "配置已写入：\n" + ctx.store.describe());
    }

    private void onReloadFromFile() {
        if (!ctx.store.fileExists()) {
            Ui.error(this, "文件不存在", "还没生成配置文件：\n" + ctx.store.describe());
            return;
        }
        if (!Ui.confirm(this, "重新载入", "将丢弃界面上未保存的改动，从文件重新载入：\n"
                + ctx.store.describe())) {
            return;
        }
        ctx.reloadFromStore();
        reload();
        Ui.info(this, "已载入", "方案 " + ctx.config().profiles.size() + " 个，规则 "
                + ctx.config().rules.size() + " 条");
    }

    private void onOpenDir() {
        try {
            java.io.File dir = ctx.store.directory();
            if (!dir.isDirectory()) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
            }
            java.awt.Desktop.getDesktop().open(dir);
        } catch (Exception e) {
            Ui.error(this, "打不开目录", String.valueOf(e) + "\n\n路径：" + ctx.store.directory());
        }
    }

    private void updatePythonHint() {
        String py = burp.script.PythonSupport.resolveInterpreter(pythonField.getText().trim());
        if (py == null) {
            pythonHint.setText("✗ 没找到 Python：留空会自动找 python3 / python；也可以填绝对路径或 venv 里的 python");
            pythonHint.setForeground(Ui.ERR);
            return;
        }
        String ver = burp.script.PythonSupport.version(py);
        pythonHint.setText("✓ 使用：" + py + (ver == null ? "" : "（" + ver + "）")
                + "    ·    只对「脚本（Python）」方案生效；改完点「保存设置」");
        pythonHint.setForeground(Ui.OK);
    }

    private void onPickPython() {
        javax.swing.JFileChooser chooser = new javax.swing.JFileChooser();
        chooser.setDialogTitle("选择 Python 解释器（如 /usr/local/bin/python3 或 venv/bin/python）");
        java.io.File usr = new java.io.File("/usr/local/bin");
        chooser.setCurrentDirectory(usr.isDirectory() ? usr : new java.io.File(
                System.getProperty("user.home", ".")));
        if (chooser.showOpenDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
            return;
        }
        pythonField.setText(chooser.getSelectedFile().getAbsolutePath());
        updatePythonHint();
    }

    private void onDetectPython() {
        burp.script.PythonSupport.invalidateInterpreterCache();
        String configured = pythonField.getText().trim();
        String py = burp.script.PythonSupport.resolveInterpreter(configured);
        if (py == null) {
            Ui.error(this, "没找到 Python", configured.isEmpty()
                    ? "环境里没有 python3 / python。\n请安装 Python，或在上面填绝对路径。"
                    : "这个路径不可用：" + configured);
            return;
        }
        String ver = burp.script.PythonSupport.version(py);
        Ui.info(this, "Python 可用", "解释器：" + py + "\n" + (ver == null ? "" : ver));
        updatePythonHint();
    }

    private void onSave() {
        AppConfig cfg = ctx.config();
        cfg.masterEnabled = master.isSelected();
        cfg.tools.clear();
        for (var e : tools.entrySet()) {
            if (e.getValue().isSelected()) {
                cfg.tools.add(e.getKey());
            }
        }
        if (cfg.tools.isEmpty()) {
            cfg.tools.addAll(AppConfig.DEFAULT_TOOLS);
        }
        cfg.proxyEnabled = proxyEnabled.isSelected();
        cfg.proxyReencryptRequest = reencryptRequest.isSelected();
        cfg.proxyReencryptResponse = reencryptResponse.isSelected();
        cfg.debug = debug.isSelected();
        cfg.beautifyJson = beautify.isSelected();
        cfg.pythonCommand = pythonField.getText().trim();
        burp.script.ScriptSettings.pythonCommand(cfg.pythonCommand);
        cfg.logLimit = (Integer) logLimit.getValue();
        int idx = fallback.getSelectedIndex();
        cfg.fallbackProfileId = idx <= 0 ? "" : cfg.profiles.get(idx - 1).id;
        Log.setDebug(cfg.debug);
        ctx.commit("保存全局设置");
        Ui.info(this, "已保存", "全局设置已保存。\n\n当前状态：" + cfg.statusText());
    }

    private void onReset() {
        if (!Ui.confirm(this, "恢复默认配置", "将丢弃当前全部方案与规则，恢复为出厂示例配置，确定？")) {
            return;
        }
        ctx.config().copyFrom(AppConfig.defaults());
        ctx.commit("恢复默认配置");
        reload();
    }
}
