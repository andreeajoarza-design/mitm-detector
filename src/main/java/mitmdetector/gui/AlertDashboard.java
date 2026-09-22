package mitmdetector.gui;

import mitmdetector.alert.Alert;
import mitmdetector.alert.AlertListener;
import mitmdetector.alert.Severity;
import mitmdetector.capture.PacketCaptureEngine;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * Live Swing view of the alerts a capture produces: a table of alerts colored by severity, with a
 * running packet/alert count and a button to stop the capture.
 *
 * <p>Registered as one more {@link AlertListener} on the {@code AlertManager}, next to
 * {@link mitmdetector.alert.ConsoleAlertListener} and
 * {@link mitmdetector.alert.FileAlertListener} (see {@code MitmDetectorApp}, the
 * {@code --gui} flag): the detectors and the alert manager are unaware this listener exists, they
 * just get one more subscriber. {@link #onAlert} runs on the capture thread, so every update to
 * Swing state is marshalled to the event dispatch thread with {@link SwingUtilities#invokeLater}.
 *
 * <p>This is a view onto a capture started elsewhere: it does not start or configure capture
 * itself, only stop it, through the same {@link PacketCaptureEngine#close()} that a console run
 * reaches through Ctrl+C.
 */
public final class AlertDashboard implements AlertListener {

    private static final Color CRITICAL_COLOR = new Color(0xE5, 0x39, 0x35);
    private static final Color HIGH_COLOR = new Color(0xFB, 0x8C, 0x00);
    private static final Color MEDIUM_COLOR = new Color(0xFD, 0xD8, 0x35);
    private static final Color LOW_COLOR = new Color(0xC5, 0xE1, 0xA5);

    private final PacketCaptureEngine engine;
    private final AlertTableModel model = new AlertTableModel();
    private final JFrame frame = new JFrame("MITM Detector");
    private final JLabel statsLabel = new JLabel();
    private final JButton stopButton = new JButton("Oprește captura");
    private final Timer statsTimer;

    public AlertDashboard(PacketCaptureEngine engine) {
        this.engine = engine;

        JTable table = new JTable(model);
        table.setDefaultRenderer(Object.class, new SeverityRowRenderer());
        table.setFillsViewportHeight(true);
        table.setRowHeight(22);
        table.getColumnModel().getColumn(5).setPreferredWidth(360);

        stopButton.addActionListener(e -> stopCapture());

        JPanel top = new JPanel(new BorderLayout());
        top.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        top.add(statsLabel, BorderLayout.WEST);
        top.add(stopButton, BorderLayout.EAST);

        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                stopCapture();
            }
        });
        frame.setLayout(new BorderLayout());
        frame.add(top, BorderLayout.NORTH);
        frame.add(new JScrollPane(table), BorderLayout.CENTER);
        frame.setSize(900, 500);
        frame.setLocationRelativeTo(null);

        statsTimer = new Timer(1000, e -> updateStats());
        statsTimer.start();
        updateStats();
    }

    public void setVisible(boolean visible) {
        frame.setVisible(visible);
    }

    @Override
    public void onAlert(Alert alert) {
        SwingUtilities.invokeLater(() -> {
            model.addAlert(alert);
            updateStats();
        });
    }

    /** Stops the capture on its own thread, so a slow shutdown never freezes the event dispatch thread. */
    private void stopCapture() {
        if (!stopButton.isEnabled()) {
            return;
        }
        stopButton.setEnabled(false);
        statsTimer.stop();
        Thread stopper = new Thread(engine::close, "gui-stop");
        stopper.setDaemon(true);
        stopper.start();
    }

    private void updateStats() {
        statsLabel.setText("Pachete: %d  ·  Alerte: %d (CRITICAL %d · HIGH %d · MEDIUM %d · LOW %d)".formatted(
                engine.packetCount(), model.totalCount(),
                model.countOf(Severity.CRITICAL), model.countOf(Severity.HIGH),
                model.countOf(Severity.MEDIUM), model.countOf(Severity.LOW)));
    }

    /** Colors each row by the severity of its alert; selection highlighting still takes priority. */
    private final class SeverityRowRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                c.setBackground(colorFor(model.alertAt(row).severity()));
                c.setForeground(Color.BLACK);
            }
            return c;
        }

        private Color colorFor(Severity severity) {
            return switch (severity) {
                case CRITICAL -> CRITICAL_COLOR;
                case HIGH -> HIGH_COLOR;
                case MEDIUM -> MEDIUM_COLOR;
                case LOW -> LOW_COLOR;
            };
        }
    }
}
