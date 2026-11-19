package burp.ui;

import burp.config.AppConfig;
import burp.config.Profile;
import burp.crypto.CipherCatalog;
import burp.crypto.Codec;
import burp.crypto.CryptoEngine;
import burp.crypto.CryptoException;
import burp.crypto.KeyMaterial;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.io.File;
import java.nio.file.Files;

/**
 * 「配置方案」页：左选方案、右填参数（算法 / Key / IV / 编码 / 范围），底部带测试台。
 *
 * <p>交互原则：改完点「保存并应用」才落盘；「测试台」用当前表单里的值即时试算，
 * 不解密错东西也能先把配置调对。</p>
 */
public final class ProfilePanel extends JPanel {

    private final UiContext ctx;
    private final DefaultListModel<Profile> model = new DefaultListModel<>();
    private final JList<Profile> list = new JList<>(model);

    private final JTextField nameField = new JTextField();
    private final JCheckBox enabledBox = new JCheckBox("启用");
    private final JComboBox<Profile.Engine> engineBox = new JComboBox<>(Profile.Engine.values());
    private final JTextField scriptField = new JTextField();
    private final JLabel scriptHint = Ui.hint(" ");
    private final JComboBox<String> cipherBox = new JComboBox<>(CipherCatalog.SUGGESTIONS);
    private final JLabel cipherHint = Ui.hint(" ");
    private final JTextField keyField = new JTextField();
    private final JComboBox<KeyMaterial.Format> keyFormatBox = new JComboBox<>(KeyMaterial.Format.values());
    private final JTextField ivField = new JTextField();
    private final JComboBox<KeyMaterial.Format> ivFormatBox = new JComboBox<>(KeyMaterial.Format.values());
    private final JComboBox<CryptoEngine.IvMode> ivModeBox = new JComboBox<>(CryptoEngine.IvMode.values());
    private final JComboBox<Profile.BodyEncoding> encodingBox = new JComboBox<>(Profile.BodyEncoding.values());
    private final JComboBox<Profile.BodyScope> scopeBox = new JComboBox<>(Profile.BodyScope.values());
    private final JTextField jsonField = new JTextField("data");
    private final JComboBox<String> charsetBox =
            new JComboBox<>(new String[]{"UTF-8", "GBK", "GB18030", "ISO-8859-1"});
    private final JCheckBox reqBox = new JCheckBox("请求", true);
    private final JCheckBox respBox = new JCheckBox("响应", true);
    private final JTextField commentField = new JTextField();

    private final JLabel status = Ui.hint(" ");
    private final JTextArea testIn = Ui.textArea(5, 40, true);
    private final JTextArea testOut = Ui.textArea(5, 40, true);

    private boolean loading;
    private Profile current;

    public ProfilePanel(UiContext ctx) {
        super(new BorderLayout());
        this.ctx = ctx;
        testIn.setText("{\"username\":\"admin\",\"password\":\"123456\"}");

        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setCellRenderer(new Renderer());
        list.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onSelect();
            }
        });

        JPanel left = new JPanel(new BorderLayout(6, 6));
        left.setBorder(new EmptyBorder(10, 10, 10, 6));
        JLabel lt = Ui.label("配置方案", true);
        left.add(lt, BorderLayout.NORTH);
        left.add(new JScrollPane(list), BorderLayout.CENTER);

        JPanel leftButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        leftButtons.add(Ui.button("新建", this::onAdd));
        leftButtons.add(Ui.button("复制", this::onCopy));
        leftButtons.add(Ui.button("删除", this::onDelete));
        left.add(leftButtons, BorderLayout.SOUTH);
        left.setPreferredSize(new Dimension(230, 100));

        JPanel right = new JPanel(new BorderLayout(6, 6));
        right.setBorder(new EmptyBorder(10, 6, 10, 10));
        right.add(buildForm(), BorderLayout.NORTH);
        right.add(buildTestBench(), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);
        split.setDividerLocation(240);
        split.setBorder(null);
        add(split, BorderLayout.CENTER);

        cipherBox.setEditable(true);
        cipherBox.addActionListener(e -> {
            updateCipherHint();
            markDirty();
        });
        engineBox.addActionListener(e -> {
            syncFieldStates();
            updateScriptHint();
            markDirty();
        });
        scopeBox.addActionListener(e -> syncFieldStates());
        ivModeBox.addActionListener(e -> syncFieldStates());

        ctx.onConfigChanged(this::reload);
        reload();
    }

    /* ==================== 布局 ==================== */

    private JComponent buildForm() {
        JPanel box = new JPanel(new BorderLayout(4, 4));

        JPanel top = new JPanel(new BorderLayout(6, 0));
        top.add(Ui.label("方案参数", true), BorderLayout.WEST);
        top.add(enabledBox, BorderLayout.EAST);
        box.add(top, BorderLayout.NORTH);

        Ui.Form form = new Ui.Form();
        form.add("名称", nameField);
        form.add("加解密方式", engineBox, "内置算法：填算法/Key/IV；脚本：实现四个阶段接口；外部命令：stdin 进 stdout 出");
        JPanel scriptRow = new JPanel(new BorderLayout(4, 0));
        scriptRow.add(scriptField, BorderLayout.CENTER);
        JPanel scriptButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        scriptButtons.add(Ui.button("浏览…", this::onPickScript));
        scriptButtons.add(Ui.button("生成模板", this::onMakeTemplate));
        scriptButtons.add(Ui.button("打开目录", this::onOpenScriptDir));
        JPanel scriptWrap = new JPanel(new BorderLayout(4, 0));
        scriptWrap.add(scriptRow, BorderLayout.CENTER);
        scriptWrap.add(scriptButtons, BorderLayout.SOUTH);
        form.add("脚本/命令", scriptWrap);
        form.add("", scriptHint);
        form.add("算法", cipherBox);
        form.add("", cipherHint);
        form.add("Key", keyField);
        form.add("Key 格式", keyFormatBox);
        form.add("IV", ivField);
        JPanel ivRow = new JPanel(new BorderLayout(4, 0));
        ivRow.add(ivFormatBox, BorderLayout.WEST);
        ivRow.add(ivModeBox, BorderLayout.CENTER);
        form.add("IV 格式/模式", ivRow);
        form.add("密文编码", encodingBox);
        JPanel scopeRow = new JPanel(new BorderLayout(4, 0));
        scopeRow.add(scopeBox, BorderLayout.WEST);
        scopeRow.add(jsonField, BorderLayout.CENTER);
        form.add("处理范围", scopeRow, "整个 Body：Body 本身就是密文；JSON 字段：只加解密该字段的值");
        form.add("字符集", charsetBox);
        JPanel dirRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        dirRow.add(reqBox);
        dirRow.add(respBox);
        form.add("处理方向", dirRow);
        form.add("备注", commentField);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        buttons.add(Ui.button("保存并应用", this::onSave));
        buttons.add(Ui.button("自检", this::onSelfTest));
        buttons.add(Ui.button("重新载入", () -> loadProfile(current)));
        buttons.add(Ui.button("导出配置", this::onExport));
        buttons.add(Ui.button("导入配置", this::onImport));
        buttons.add(status);

        box.add(form.build(), BorderLayout.CENTER);
        box.add(buttons, BorderLayout.SOUTH);
        return box;
    }

    private JComponent buildTestBench() {
        JPanel p = new JPanel(new BorderLayout(6, 6));
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("测试台（用当前表单参数即时试算，不写配置）"),
                new EmptyBorder(4, 6, 6, 6)));

        JPanel in = new JPanel(new BorderLayout(4, 4));
        in.add(Ui.hint("输入（明文 / 密文）"), BorderLayout.NORTH);
        in.add(Ui.scroll(testIn), BorderLayout.CENTER);

        JPanel out = new JPanel(new BorderLayout(4, 4));
        out.add(Ui.hint("输出"), BorderLayout.NORTH);
        out.add(Ui.scroll(testOut), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        buttons.add(Ui.button("→ 加密", this::onTestEncrypt));
        buttons.add(Ui.button("→ 解密", this::onTestDecrypt));
        buttons.add(Ui.button("清空输出", () -> testOut.setText("")));

        JPanel center = new JPanel(new BorderLayout(6, 6));
        center.add(in, BorderLayout.CENTER);
        center.add(out, BorderLayout.SOUTH);
        p.add(center, BorderLayout.CENTER);
        p.add(buttons, BorderLayout.SOUTH);
        return p;
    }

    /* ==================== 列表 ==================== */

    private void reload() {
        AppConfig cfg = ctx.config();
        String keep = current == null ? null : current.id;
        model.clear();
        for (Profile p : cfg.profiles) {
            model.addElement(p);
        }
        if (model.isEmpty()) {
            current = null;
            setFormEnabled(false);
            status.setText("还没有配置方案，点「新建」开始");
            return;
        }
        int idx = 0;
        if (keep != null) {
            for (int i = 0; i < model.size(); i++) {
                if (model.get(i).id.equals(keep)) {
                    idx = i;
                    break;
                }
            }
        }
        list.setSelectedIndex(idx);
        loadProfile(model.get(idx));
    }

    private void onSelect() {
        if (loading) {
            return;
        }
        Profile p = list.getSelectedValue();
        if (p != null) {
            loadProfile(p);
        }
    }

    private void loadProfile(Profile p) {
        if (p == null) {
            return;
        }
        loading = true;
        current = p;
        nameField.setText(p.name);
        enabledBox.setSelected(p.enabled);
        engineBox.setSelectedItem(p.engine);
        scriptField.setText(p.scriptPath);
        cipherBox.setSelectedItem(p.cipher);
        if (!p.cipher.equals(cipherBox.getEditor().getItem())) {
            cipherBox.getEditor().setItem(p.cipher);
        }
        keyField.setText(p.key);
        keyFormatBox.setSelectedItem(p.keyFormat);
        ivField.setText(p.iv);
        ivFormatBox.setSelectedItem(p.ivFormat);
        ivModeBox.setSelectedItem(p.ivMode);
        encodingBox.setSelectedItem(p.bodyEncoding);
        scopeBox.setSelectedItem(p.bodyScope);
        jsonField.setText(p.jsonField);
        charsetBox.setSelectedItem(p.charset);
        reqBox.setSelected(p.onRequest);
        respBox.setSelected(p.onResponse);
        commentField.setText(p.comment);
        setFormEnabled(true);
        syncFieldStates();
        updateScriptHint();
        updateCipherHint();
        showValidation(p);
        loading = false;
    }

    private void onAdd() {
        Profile p = new Profile();
        p.name = "新配置 " + (ctx.config().profiles.size() + 1);
        p.cipher = "AES/CBC/PKCS5Padding";
        ctx.config().profiles.add(p);
        ctx.commit("新建配置方案");
        reload();
        for (int i = 0; i < model.size(); i++) {
            if (model.get(i).id.equals(p.id)) {
                list.setSelectedIndex(i);
                break;
            }
        }
    }

    private void onCopy() {
        if (current == null) {
            return;
        }
        Profile copy = current.copy();
        ctx.config().profiles.add(copy);
        ctx.commit("复制配置方案");
        reload();
        for (int i = 0; i < model.size(); i++) {
            if (model.get(i).id.equals(copy.id)) {
                list.setSelectedIndex(i);
                break;
            }
        }
    }

    private void onDelete() {
        if (current == null) {
            return;
        }
        long used = ctx.config().rules.stream()
                .filter(r -> current.id.equals(r.profileId)).count();
        String msg = used > 0
                ? "该方案被 " + used + " 条规则引用，删除后这些规则会失效。确定删除？"
                : "确定删除配置方案「" + current.name + "」？";
        if (!Ui.confirm(this, "删除配置方案", msg)) {
            return;
        }
        ctx.config().profiles.removeIf(p -> p.id.equals(current.id));
        if (current.id.equals(ctx.config().fallbackProfileId)) {
            ctx.config().fallbackProfileId = "";
        }
        current = null;
        ctx.commit("删除配置方案");
        reload();
    }

    /* ==================== 表单 ==================== */

    private void setFormEnabled(boolean on) {
        for (Component c : new Component[]{nameField, enabledBox, cipherBox, keyField, keyFormatBox,
                ivField, ivFormatBox, ivModeBox, encodingBox, scopeBox, jsonField, charsetBox,
                reqBox, respBox, commentField}) {
            c.setEnabled(on);
        }
    }

    private void syncFieldStates() {
        boolean scriptMode = engineBox.getSelectedItem() != null
                && engineBox.getSelectedItem() != Profile.Engine.BUILTIN;
        // 脚本模式：内置算法那套字段整体禁用（由脚本自己决定怎么加解密）
        for (Component c : new Component[]{cipherBox, keyField, keyFormatBox, ivField, ivFormatBox,
                ivModeBox, encodingBox, scopeBox, jsonField}) {
            c.setEnabled(!scriptMode && current != null);
        }
        scriptField.setEnabled(scriptMode && current != null);
        boolean json = !scriptMode && scopeBox.getSelectedItem() == Profile.BodyScope.JSON_FIELD;
        jsonField.setEnabled(json && current != null);
        CryptoEngine.IvMode mode = (CryptoEngine.IvMode) ivModeBox.getSelectedItem();
        // 固定 IV 必填；自动模式可选（留空则只按 IV||CT 处理）；IV||CT / 无 IV 不需要填
        boolean ivUsable = mode == CryptoEngine.IvMode.FIXED || mode == CryptoEngine.IvMode.AUTO;
        ivField.setEnabled(ivUsable && current != null);
        ivFormatBox.setEnabled(ivUsable && current != null);
    }

    private void updateScriptHint() {
        Profile.Engine e = (Profile.Engine) engineBox.getSelectedItem();
        if (e == null || e == Profile.Engine.BUILTIN) {
            scriptHint.setText("四个脚本接口：clientToBurp / burpToServer / serverToBurp / burpToClient");
            scriptHint.setForeground(Ui.MUTED);
            return;
        }
        if (e == Profile.Engine.SCRIPT_CMD) {
            scriptHint.setText("外部命令：Body 从 stdin 进、新 Body 从 stdout 出；"
                    + "环境变量 BC_STAGE / BC_URL / BC_METHOD 可用");
            scriptHint.setForeground(Ui.MUTED);
            return;
        }
        Profile probe = new Profile();
        probe.engine = Profile.Engine.SCRIPT_JS;
        probe.scriptPath = scriptField.getText().trim();
        java.io.File f = burp.script.ScriptRuntime.resolve(probe);
        if (f == null || !f.isFile()) {
            scriptHint.setText("脚本目录：" + burp.script.ScriptRuntime.scriptsDir().getAbsolutePath());
            scriptHint.setForeground(Ui.WARN);
            return;
        }
        java.util.List<String> hooks = burp.script.JsScriptRunner.hooksOf(f);
        if (hooks.isEmpty()) {
            scriptHint.setText("✗ 脚本编译失败或没有实现任何钩子：" + f.getName());
            scriptHint.setForeground(Ui.ERR);
            return;
        }
        scriptHint.setText("✓ 已实现钩子（" + hooks.size() + "/4）：" + String.join(", ", hooks));
        scriptHint.setForeground(Ui.OK);
    }

    private void onPickScript() {
        javax.swing.JFileChooser chooser = new javax.swing.JFileChooser();
        java.io.File dir = burp.script.ScriptRuntime.scriptsDir();
        if (dir.isDirectory()) {
            chooser.setCurrentDirectory(dir);
        }
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("脚本 (*.js)", "js"));
        if (chooser.showOpenDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
            return;
        }
        java.io.File f = chooser.getSelectedFile();
        String path = f.getAbsolutePath();
        java.io.File scripts = burp.script.ScriptRuntime.scriptsDir();
        if (scripts.isDirectory() && path.startsWith(scripts.getAbsolutePath() + java.io.File.separator)) {
            path = path.substring(scripts.getAbsolutePath().length() + 1);   // 存相对路径
        }
        scriptField.setText(path);
        updateScriptHint();
        markDirty();
    }

    private void onMakeTemplate() {
        try {
            String hint = nameField.getText().trim();
            java.io.File f = burp.script.ScriptRuntime.writeTemplate(hint);
            scriptField.setText(f.getName());
            engineBox.setSelectedItem(Profile.Engine.SCRIPT_JS);
            syncFieldStates();
            updateScriptHint();
            markDirty();
            Ui.info(this, "已生成脚本模板", f.getAbsolutePath()
                    + "\n\n里面已写好四个接口（clientToBurp / burpToServer / serverToBurp / burpToClient），"
                    + "\n把 KEY、IV 改成目标值，把用不到的接口删掉即可。");
        } catch (Exception e) {
            Ui.error(this, "生成模板失败", String.valueOf(e));
        }
    }

    private void onOpenScriptDir() {
        try {
            java.io.File dir = burp.script.ScriptRuntime.scriptsDir();
            if (!dir.isDirectory()) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
            }
            java.awt.Desktop.getDesktop().open(dir);
        } catch (Exception e) {
            Ui.error(this, "打不开目录", String.valueOf(e) + "\n\n路径："
                    + burp.script.ScriptRuntime.scriptsDir());
        }
    }

    private void updateCipherHint() {
        String cipher = String.valueOf(cipherBox.getEditor().getItem());
        try {
            var spec = burp.crypto.CipherSpec.of(cipher);
            cipherHint.setText(spec.describe());
            cipherHint.setForeground(Ui.MUTED);
        } catch (CryptoException e) {
            cipherHint.setText(e.getMessage());
            cipherHint.setForeground(Ui.ERR);
        }
    }

    private void showValidation(Profile p) {
        String err = p.validate();
        if (err == null) {
            status.setText("✓ 配置可用");
            status.setForeground(Ui.OK);
        } else {
            status.setText("✗ " + err);
            status.setForeground(Ui.ERR);
        }
    }

    private void markDirty() {
        if (!loading) {
            status.setText("参数已修改，点「保存并应用」生效");
            status.setForeground(Ui.WARN);
        }
    }

    /** 用当前表单内容拼一个临时方案（不落盘），供保存/测试共用。 */
    private Profile fromForm(Profile target) throws CryptoException {
        Profile p = target == null ? new Profile() : target;
        String cipher = String.valueOf(cipherBox.getEditor().getItem()).trim();
        boolean scriptMode = engineBox.getSelectedItem() != null
                && engineBox.getSelectedItem() != Profile.Engine.BUILTIN;
        if (!scriptMode && cipher.isEmpty()) {
            throw new CryptoException("算法不能为空");
        }
        if (scriptMode && scriptField.getText().trim().isEmpty()) {
            throw new CryptoException("脚本方式下必须填脚本文件或外部命令");
        }
        if (cipher.isEmpty()) {
            cipher = "AES/CBC/PKCS5Padding";
        }
        p.engine = (Profile.Engine) engineBox.getSelectedItem();
        p.scriptPath = scriptField.getText().trim();
        p.cipher = cipher;
        p.name = nameField.getText().trim().isEmpty() ? cipher : nameField.getText().trim();
        p.enabled = enabledBox.isSelected();
        p.key = keyField.getText();
        p.keyFormat = (KeyMaterial.Format) keyFormatBox.getSelectedItem();
        p.iv = ivField.getText();
        p.ivFormat = (KeyMaterial.Format) ivFormatBox.getSelectedItem();
        p.ivMode = (CryptoEngine.IvMode) ivModeBox.getSelectedItem();
        p.bodyEncoding = (Profile.BodyEncoding) encodingBox.getSelectedItem();
        p.bodyScope = (Profile.BodyScope) scopeBox.getSelectedItem();
        p.jsonField = jsonField.getText().trim().isEmpty() ? "data" : jsonField.getText().trim();
        p.charset = String.valueOf(charsetBox.getSelectedItem());
        p.onRequest = reqBox.isSelected();
        p.onResponse = respBox.isSelected();
        p.comment = commentField.getText();
        return p;
    }

    private void onSave() {
        if (current == null) {
            return;
        }
        Profile p;
        try {
            p = fromForm(current);
        } catch (CryptoException e) {
            Ui.error(this, "配置有误", e.getMessage());
            return;
        }
        p.touch();
        String err = p.validate();
        if (err != null) {
            if (!Ui.confirm(this, "配置自检未通过",
                    err + "\n\n仍然保存吗？（自检未通过的方案在运行时会保持原始报文不动）")) {
                return;
            }
        }
        ctx.commit("保存方案「" + p.name + "」");
        reload();
        Ui.info(this, "已保存", "配置方案「" + p.name + "」已保存并生效。\n\n"
                + (err == null ? "自检：通过" : "自检：" + err));
    }

    private void onSelfTest() {
        try {
            Profile p = fromForm(current == null ? new Profile() : current.copy());
            String err = p.validate();
            if (err == null && p.isScript()) {
                java.util.List<String> hooks = burp.script.ScriptRuntime.hooks(p);
                Ui.info(this, "自检通过", "脚本方案可用。\n\n方式：" + p.engine.label()
                        + "\n脚本：" + p.scriptPath
                        + "\n已实现钩子：" + (hooks.isEmpty() ? "（外部命令，四个阶段都由命令自己判断）"
                        : String.join(", ", hooks)));
                return;
            }
            if (err == null) {
                byte[] ct = p.toEngine().encrypt("BurpCryptCat".getBytes(Codec.charset(p.charset)));
                Ui.info(this, "自检通过", "配置可用。\n\n算法：" + p.cipher
                        + "\n示例密文：" + Codec.preview(
                                new String(ct, Codec.charset(p.charset)), 120));
            } else {
                Ui.error(this, "自检未通过", err);
            }
        } catch (Exception e) {
            Ui.error(this, "自检未通过", String.valueOf(e.getMessage()));
        }
    }

    private void onTestEncrypt() {
        runTest(true);
    }

    private void onTestDecrypt() {
        runTest(false);
    }

    private void runTest(boolean encrypt) {
        try {
            Profile p = fromForm(current == null ? new Profile() : current.copy());
            var cs = Codec.charset(p.charset);
            String input = testIn.getText();
            burp.script.ScriptStage stage = encrypt
                    ? burp.script.ScriptStage.BURP_TO_SERVER
                    : burp.script.ScriptStage.CLIENT_TO_BURP;
            burp.transform.TransformResult r = burp.transform.MessageTransform.apply(p, stage,
                    "http://burpcrypto.test/", "POST", java.util.List.of(), input.getBytes(cs));
            if (r.changed()) {
                testOut.setText(new String(r.body, cs));
            } else {
                testOut.setText("未改动（" + r.kind.label()
                        + (r.detail == null || r.detail.isEmpty() ? "" : "：" + r.detail) + "）");
            }
        } catch (CryptoException ex) {
            testOut.setText("失败：" + ex.getMessage());
        } catch (RuntimeException ex) {
            testOut.setText("失败：" + ex);
        }
    }

    /* ==================== 导入导出 ==================== */

    private void onExport() {
        var chooser = new javax.swing.JFileChooser();
        chooser.setSelectedFile(new File("burpcrypto-config.ini"));
        if (chooser.showSaveDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            Files.writeString(chooser.getSelectedFile().toPath(), ctx.config().toIni());
            Ui.info(this, "导出成功", chooser.getSelectedFile().getAbsolutePath());
        } catch (Exception e) {
            Ui.error(this, "导出失败", String.valueOf(e));
        }
    }

    private void onImport() {
        var chooser = new javax.swing.JFileChooser();
        if (chooser.showOpenDialog(this) != javax.swing.JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            String text = Files.readString(chooser.getSelectedFile().toPath());
            AppConfig cfg = AppConfig.fromIni(text);
            if (!Ui.confirm(this, "导入配置",
                    "将用文件里的 " + cfg.profiles.size() + " 个方案 / " + cfg.rules.size()
                            + " 条规则覆盖当前配置，确定？")) {
                return;
            }
            ctx.config().copyFrom(cfg);
            ctx.commit("导入配置");
            current = null;
            reload();
        } catch (Exception e) {
            Ui.error(this, "导入失败", String.valueOf(e));
        }
    }

    /* ==================== 渲染 ==================== */

    private static final class Renderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean selected, boolean focus) {
            super.getListCellRendererComponent(list, value, index, selected, focus);
            if (value instanceof Profile p) {
                setText((p.enabled ? "" : "◌ ") + p.name);
                if (!selected) {
                    setForeground(p.enabled ? Color.DARK_GRAY : Ui.MUTED);
                }
                setFont(getFont().deriveFont(Font.PLAIN, 12f));
            }
            return this;
        }
    }
}
