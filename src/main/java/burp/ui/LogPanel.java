package burp.ui;

import burp.transform.PlaintextLog;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 「明文查看器」：实时流水，显示每条被解密/加密的报文及其明文。
 *
 * <p>这就是需求里"Proxy 请求方向能直接读到请求 Body 明文"的那个视图：
 * 双开列表 → 点开任意一条 → 看到完整明文，可一键复制。</p>
 */
public final class LogPanel extends JPanel {

    private final UiContext ctx;
    private final LogTableModel model = new LogTableModel();
    private final JTable table = new JTable(model);
    private final JTextField filterField = new JTextField(18);
    private final JCheckBox onlyDecryptBox = new JCheckBox("只看解密", false);
    private final JLabel counter = Ui.hint(" ");

    private final AtomicBoolean refreshQueued = new AtomicBoolean();
    private List<PlaintextLog.Entry> view = new ArrayList<>();

    public LogPanel(UiContext ctx) {
        super(new BorderLayout(6, 6));
        this.ctx = ctx;
        setBorder(new EmptyBorder(10, 12, 10, 12));

        JPanel head = new JPanel(new BorderLayout(6, 2));
        head.add(Ui.label("明文查看器（加解密流水）", true), BorderLayout.NORTH);
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        filterRow.add(new JLabel("过滤"));
        filterRow.add(filterField);
        filterRow.add(onlyDecryptBox);
        filterRow.add(Ui.button("刷新", this::refresh));
        filterRow.add(Ui.button("清空", () -> {
            ctx.service.log().clear();
            refresh();
        }));
        filterRow.add(Ui.button("详情", this::showDetail));
        filterRow.add(counter);
        head.add(filterRow, BorderLayout.SOUTH);
        add(head, BorderLayout.NORTH);

        table.setRowHeight(22);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getTableHeader().setReorderingAllowed(false);
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    showDetail();
                }
            }
        });
        add(new JScrollPane(table), BorderLayout.CENTER);

        filterField.addActionListener(e -> refresh());
        filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                refresh();
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                refresh();
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                refresh();
            }
        });
        onlyDecryptBox.addActionListener(e -> refresh());

        ctx.service.log().addListener(this::queueRefresh);
        refresh();
    }

    private void queueRefresh() {
        if (refreshQueued.compareAndSet(false, true)) {
            SwingUtilities.invokeLater(() -> {
                refreshQueued.set(false);
                refresh();
            });
        }
    }

    private void refresh() {
        String f = filterField.getText().trim().toLowerCase();
        boolean onlyDecrypt = onlyDecryptBox.isSelected();
        List<PlaintextLog.Entry> all = ctx.service.log().snapshot();
        List<PlaintextLog.Entry> out = new ArrayList<>();
        for (PlaintextLog.Entry e : all) {
            if (onlyDecrypt && e.kind != burp.transform.TransformResult.Kind.DECRYPTED) {
                continue;
            }
            if (!f.isEmpty()) {
                String hay = ((e.url == null ? "" : e.url) + " " + (e.plaintext == null ? "" : e.plaintext)
                        + " " + e.source + " " + e.direction + " " + e.detail).toLowerCase();
                if (!hay.contains(f)) {
                    continue;
                }
            }
            out.add(e);
        }
        view = out;
        model.fireTableDataChanged();
        counter.setText("显示 " + out.size() + " / 共 " + all.size() + " 条");
    }

    private void showDetail() {
        int i = table.getSelectedRow();
        if (i < 0 || i >= view.size()) {
            return;
        }
        PlaintextLog.Entry e = view.get(i);
        StringBuilder sb = new StringBuilder();
        sb.append("时间 : ").append(e.time).append('\n');
        sb.append("来源 : ").append(e.source).append(" / ").append(e.direction).append('\n');
        sb.append("结果 : ").append(e.kind.label());
        if (e.detail != null && !e.detail.isEmpty()) {
            sb.append("（").append(e.detail).append("）");
        }
        sb.append('\n');
        sb.append("请求 : ").append(e.method).append(' ').append(e.url).append('\n');
        sb.append("────────────────────────────────────────\n");
        sb.append(e.plaintext == null ? "（该条没有可展示的明文）" : e.plaintext);
        Ui.showText(this, "明文详情", sb.toString());
    }

    private final class LogTableModel extends AbstractTableModel {

        private final String[] columns = {"时间", "工具", "方向", "结果", "方法", "Host", "明文摘要"};

        @Override
        public int getRowCount() {
            return view.size();
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
        public Object getValueAt(int row, int col) {
            PlaintextLog.Entry e = view.get(row);
            return switch (col) {
                case 0 -> e.time;
                case 1 -> e.source;
                case 2 -> e.direction;
                case 3 -> e.kind.label() + (e.detail == null || e.detail.isEmpty() ? "" : " · " + e.detail);
                case 4 -> e.method;
                case 5 -> e.host;
                default -> e.plaintextPreview(300);
            };
        }
    }
}
