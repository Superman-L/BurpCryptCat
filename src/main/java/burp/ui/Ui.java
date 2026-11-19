package burp.ui;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

/** 一组 Swing 小工具，避免每个面板重复写布局代码。 */
public final class Ui {

    public static final Color OK = new Color(0x2E7D32);
    public static final Color WARN = new Color(0xB26A00);
    public static final Color ERR = new Color(0xC62828);
    public static final Color MUTED = new Color(0x757575);

    private Ui() {
    }

    public static JPanel panel(String title) {
        JPanel p = new JPanel(new BorderLayout(6, 6));
        p.setBorder(new EmptyBorder(10, 12, 10, 12));
        if (title != null && !title.isEmpty()) {
            JLabel l = new JLabel(title);
            l.setFont(l.getFont().deriveFont(Font.BOLD, 13f));
            p.add(l, BorderLayout.NORTH);
        }
        return p;
    }

    public static JLabel label(String text, boolean bold) {
        JLabel l = new JLabel(text);
        if (bold) {
            l.setFont(l.getFont().deriveFont(Font.BOLD));
        }
        return l;
    }

    public static JLabel hint(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(MUTED);
        l.setFont(l.getFont().deriveFont(11f));
        return l;
    }

    public static JButton button(String text, Runnable action) {
        JButton b = new JButton(text);
        b.addActionListener(e -> action.run());
        return b;
    }

    public static JScrollPane scroll(Component c) {
        JScrollPane sp = new JScrollPane(c);
        sp.setBorder(BorderFactory.createEtchedBorder());
        return sp;
    }

    public static JTextArea textArea(int rows, int cols, boolean editable) {
        JTextArea ta = new JTextArea(rows, cols);
        ta.setLineWrap(true);
        ta.setWrapStyleWord(false);
        ta.setEditable(editable);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return ta;
    }

    public static JPanel row(Component left, Component right, int leftWidth) {
        JPanel p = new JPanel(new BorderLayout(8, 0));
        if (left != null) {
            JPanel wrap = new JPanel(new BorderLayout());
            wrap.add(left, BorderLayout.WEST);
            wrap.setPreferredSize(new Dimension(leftWidth, 26));
            p.add(wrap, BorderLayout.WEST);
        }
        if (right != null) {
            p.add(right, BorderLayout.CENTER);
        }
        return p;
    }

    public static JPanel vertical(Component... comps) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        for (Component c : comps) {
            p.add(c);
            p.add(Box.createVerticalStrut(6));
        }
        return p;
    }

    /** 两列表单：左列标签右列控件。 */
    public static final class Form {
        private final JPanel panel = new JPanel(new GridBagLayout());
        private int row = 0;

        public Form() {
            panel.setBorder(new EmptyBorder(4, 0, 4, 0));
        }

        public Form add(String label, Component field) {
            return add(label, field, null);
        }

        public Form add(String label, Component field, String hint) {
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(3, 0, 3, 8);
            c.anchor = GridBagConstraints.WEST;
            c.gridx = 0;
            c.gridy = row;
            c.weightx = 0;
            c.fill = GridBagConstraints.NONE;
            panel.add(label(label, false), c);

            JPanel wrap = new JPanel(new BorderLayout(6, 0));
            wrap.add(field, BorderLayout.CENTER);
            if (hint != null) {
                wrap.add(hint(hint), BorderLayout.SOUTH);
            }
            c.gridx = 1;
            c.weightx = 1;
            c.fill = GridBagConstraints.HORIZONTAL;
            panel.add(wrap, c);
            row++;
            return this;
        }

        /** 占满两列的整行控件（例如测试台）。 */
        public Form addFull(Component field) {
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(3, 0, 3, 0);
            c.gridx = 0;
            c.gridy = row;
            c.gridwidth = 2;
            c.weightx = 1;
            c.weighty = 1;
            c.fill = GridBagConstraints.BOTH;
            panel.add(field, c);
            row++;
            return this;
        }

        public JPanel build() {
            return panel;
        }

        public void addRow(JComponent comp) {
            panel.add(comp, new GridBagConstraints());
        }
    }

    /* ==================== 对话框 ==================== */

    public static void info(Component parent, String title, String message) {
        JOptionPane.showMessageDialog(parent, message, title, JOptionPane.INFORMATION_MESSAGE);
    }

    public static void error(Component parent, String title, String message) {
        JOptionPane.showMessageDialog(parent, message, title, JOptionPane.ERROR_MESSAGE);
    }

    public static boolean confirm(Component parent, String title, String message) {
        return JOptionPane.showConfirmDialog(parent, message, title,
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE) == JOptionPane.OK_OPTION;
    }

    public static void copy(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }

    /** 明文详情对话框：大一点的等宽文本区 + 复制/关闭。 */
    public static void showText(Component parent, String title, String text) {
        JTextArea ta = textArea(24, 100, true);
        ta.setText(text == null ? "" : text);
        ta.setCaretPosition(0);
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.add(scroll(ta), BorderLayout.CENTER);
        JPanel buttons = new JPanel(new BorderLayout());
        buttons.add(button("复制全部", () -> copy(ta.getText())), BorderLayout.WEST);
        p.add(buttons, BorderLayout.SOUTH);
        p.setPreferredSize(new Dimension(860, 520));
        JOptionPane.showMessageDialog(parent, p, title, JOptionPane.PLAIN_MESSAGE);
    }
}
