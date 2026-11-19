package burp.ui;

import burp.config.AppConfig;
import burp.config.Profile;
import burp.config.Rule;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;

/**
 * 「生效规则」页：按 Host / URL 决定哪些请求、响应用哪套配置方案。
 *
 * <p>规则从上到下匹配，第一条命中的生效；都没命中时用「全局设置」里的兜底方案。</p>
 */
public final class RulePanel extends JPanel {

    private final UiContext ctx;
    private final RuleTableModel model = new RuleTableModel();
    private final JTable table = new JTable(model);
    private final JLabel legend = Ui.hint(" ");

    public RulePanel(UiContext ctx) {
        super(new BorderLayout(6, 6));
        this.ctx = ctx;
        setBorder(new EmptyBorder(10, 12, 10, 12));

        JPanel head = new JPanel(new BorderLayout(6, 2));
        head.add(Ui.label("生效规则（自上而下匹配，第一条命中即生效）", true), BorderLayout.NORTH);
        head.add(legend, BorderLayout.SOUTH);
        add(head, BorderLayout.NORTH);

        table.setRowHeight(24);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getTableHeader().setReorderingAllowed(false);
        table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    onEdit();
                }
            }
        });
        add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        buttons.add(Ui.button("新增规则", this::onAdd));
        buttons.add(Ui.button("编辑", this::onEdit));
        buttons.add(Ui.button("删除", this::onDelete));
        buttons.add(Ui.button("上移", () -> onMove(-1)));
        buttons.add(Ui.button("下移", () -> onMove(1)));
        add(buttons, BorderLayout.SOUTH);

        ctx.onConfigChanged(this::reload);
        reload();
    }

    /* ==================== 数据 ==================== */

    private void reload() {
        model.fireTableDataChanged();
        int enabled = 0;
        for (Rule r : ctx.config().rules) {
            if (r.enabled) {
                enabled++;
            }
        }
        legend.setText("共 " + ctx.config().rules.size() + " 条，启用 " + enabled + " 条。"
                + "匹配方式：Host 支持 *.example.com；URL 通配支持 * 和 ?；URL 正则用 Java 正则语法。");
    }

    private void onAdd() {
        if (ctx.config().profiles.isEmpty()) {
            Ui.error(this, "没有配置方案", "请先在「配置方案」页新建一个方案。");
            return;
        }
        Rule rule = new Rule(ctx.config().profiles.get(0).id, Rule.MatchType.HOST, "*");
        if (!editDialog(rule, "新增规则")) {
            return;
        }
        ctx.config().rules.add(rule);
        ctx.commit("新增规则");
        reload();
        table.setRowSelectionInterval(ctx.config().rules.size() - 1, ctx.config().rules.size() - 1);
    }

    private void onEdit() {
        int i = table.getSelectedRow();
        if (i < 0 || i >= ctx.config().rules.size()) {
            return;
        }
        Rule rule = ctx.config().rules.get(i);
        if (editDialog(rule, "编辑规则")) {
            rule.touch();
            ctx.commit("修改规则");
            reload();
        }
    }

    private void onDelete() {
        int i = table.getSelectedRow();
        if (i < 0 || i >= ctx.config().rules.size()) {
            return;
        }
        Rule rule = ctx.config().rules.get(i);
        if (!Ui.confirm(this, "删除规则", "删除规则「" + rule.pattern + "」？")) {
            return;
        }
        ctx.config().rules.remove(i);
        ctx.commit("删除规则");
        reload();
    }

    private void onMove(int delta) {
        int i = table.getSelectedRow();
        List<Rule> rules = ctx.config().rules;
        int j = i + delta;
        if (i < 0 || j < 0 || j >= rules.size()) {
            return;
        }
        Rule r = rules.remove(i);
        rules.add(j, r);
        ctx.commit("调整规则顺序");
        reload();
        table.setRowSelectionInterval(j, j);
    }

    /* ==================== 编辑对话框 ==================== */

    private boolean editDialog(Rule rule, String title) {
        JComboBox<Rule.MatchType> typeBox = new JComboBox<>(Rule.MatchType.values());
        typeBox.setSelectedItem(rule.matchType);
        JTextField patternField = new JTextField(rule.pattern, 34);

        List<Profile> profiles = new ArrayList<>(ctx.config().profiles);
        JComboBox<Profile> profileBox = new JComboBox<>(profiles.toArray(new Profile[0]));
        for (Profile p : profiles) {
            if (p.id.equals(rule.profileId)) {
                profileBox.setSelectedItem(p);
            }
        }
        JCheckBox reqBox = new JCheckBox("请求（密文↔明文）", rule.onRequest);
        JCheckBox respBox = new JCheckBox("响应（密文↔明文）", rule.onResponse);
        JTextField commentField = new JTextField(rule.comment, 34);

        JLabel tip = Ui.hint("Host 例：api.example.com 或 *.example.com     URL 通配例：https://a.com/gw/*");
        tip.setForeground(Ui.MUTED);

        Ui.Form form = new Ui.Form();
        form.add("匹配方式", typeBox);
        form.add("匹配内容", patternField);
        form.add("", tip);
        form.add("使用方案", profileBox);
        JPanel dir = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        dir.add(reqBox);
        dir.add(respBox);
        form.add("处理方向", dir);
        form.add("备注", commentField);

        JPanel wrap = new JPanel(new BorderLayout(6, 6));
        wrap.setBorder(new EmptyBorder(10, 12, 10, 12));
        wrap.add(form.build(), BorderLayout.CENTER);
        wrap.setPreferredSize(new Dimension(560, 300));

        int ok = javax.swing.JOptionPane.showConfirmDialog(this, wrap, title,
                javax.swing.JOptionPane.OK_CANCEL_OPTION, javax.swing.JOptionPane.PLAIN_MESSAGE);
        if (ok != javax.swing.JOptionPane.OK_OPTION) {
            return false;
        }
        rule.matchType = (Rule.MatchType) typeBox.getSelectedItem();
        rule.pattern = patternField.getText().trim();
        Profile selected = (Profile) profileBox.getSelectedItem();
        rule.profileId = selected == null ? "" : selected.id;
        rule.onRequest = reqBox.isSelected();
        rule.onResponse = respBox.isSelected();
        rule.comment = commentField.getText();
        if (rule.pattern.isEmpty()) {
            rule.pattern = "*";
        }
        String err = rule.validate(ctx.config());
        if (err != null) {
            Ui.error(this, "规则有误", err);
            return false;
        }
        return true;
    }

    /* ==================== 表格模型 ==================== */

    private final class RuleTableModel extends AbstractTableModel {

        private final String[] columns = {"启用", "匹配方式", "匹配内容", "配置方案", "方向", "备注"};

        @Override
        public int getRowCount() {
            return ctx.config().rules.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return columnIndex == 0 ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 0;
        }

        @Override
        public Object getValueAt(int row, int col) {
            Rule r = ctx.config().rules.get(row);
            return switch (col) {
                case 0 -> r.enabled;
                case 1 -> r.matchType.label();
                case 2 -> r.pattern;
                case 3 -> {
                    Profile p = ctx.config().profile(r.profileId);
                    yield p == null ? "⚠ 未指定" : p.name;
                }
                case 4 -> (r.onRequest ? "请求 " : "") + (r.onResponse ? "响应" : "");
                default -> r.comment;
            };
        }

        @Override
        public void setValueAt(Object value, int row, int col) {
            if (col != 0) {
                return;
            }
            Rule r = ctx.config().rules.get(row);
            r.enabled = Boolean.TRUE.equals(value);
            ctx.commit("切换规则启用状态");
            fireTableRowsUpdated(row, row);
            reload();
        }
    }
}
