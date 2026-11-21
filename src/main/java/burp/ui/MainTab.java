package burp.ui;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;

/**
 * 插件主界面：顶栏（标题 + 总开关 + 实时状态）+ 五个分页。
 */
public final class MainTab extends JPanel {

    private final UiContext ctx;
    private final JLabel status = new JLabel();
    private final JCheckBox masterSwitch = new JCheckBox("总开关");
    private boolean loading;

    public MainTab(UiContext ctx) {
        super(new BorderLayout());
        this.ctx = ctx;

        add(buildHeader(), BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("① 配置方案", new ProfilePanel(ctx));
        tabs.addTab("② 生效规则", new RulePanel(ctx));
        tabs.addTab("③ 明文查看器", new LogPanel(ctx));
        tabs.addTab("④ 全局设置", new SettingsPanel(ctx));
        tabs.addTab("帮助", new HelpPanel(ctx));
        add(tabs, BorderLayout.CENTER);

        ctx.setStatusSink(this::refreshStatus);
        ctx.onConfigChanged(this::refreshStatus);
        refreshStatus();
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout(10, 0));
        header.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, new Color(0xDDDDDD)),
                new EmptyBorder(8, 12, 8, 12)));

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JLabel title = new JLabel("BurpCryptCat");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 15f));
        left.add(title);
        left.add(Ui.hint("Body 透明加解密 · Proxy / Repeater / Intruder"));
        header.add(left, BorderLayout.WEST);

        status.setFont(status.getFont().deriveFont(Font.PLAIN, 12f));
        header.add(status, BorderLayout.CENTER);

        masterSwitch.addActionListener(this::onMasterSwitch);
        header.add(masterSwitch, BorderLayout.EAST);
        return header;
    }

    private void onMasterSwitch(ActionEvent e) {
        if (loading) {
            return;
        }
        ctx.config().masterEnabled = masterSwitch.isSelected();
        ctx.commit(masterSwitch.isSelected() ? "打开总开关" : "关闭总开关");
    }

    private void refreshStatus() {
        loading = true;
        masterSwitch.setSelected(ctx.config().masterEnabled);
        loading = false;
        String text = ctx.config().statusText();
        status.setText(text
                + (ctx.lastSaveHint().isEmpty() ? "" : "    |    " + ctx.lastSaveHint()));
        boolean active = ctx.config().masterEnabled
                && ctx.config().profiles.stream().anyMatch(p -> p.enabled)
                && (ctx.config().rules.stream().anyMatch(r -> r.enabled)
                || !ctx.config().fallbackProfileId.isEmpty());
        status.setForeground(active ? Ui.OK : Ui.WARN);
    }
}
