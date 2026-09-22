package mitmdetector.gui;

import mitmdetector.alert.Alert;
import mitmdetector.alert.Severity;

import javax.swing.table.AbstractTableModel;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Table model backing the live alert view in {@link AlertDashboard}.
 *
 * <p>Alerts are kept newest first and capped at {@link #MAX_ROWS}, so a long-running capture does
 * not grow the table without bound. The per-severity counts, however, keep counting every alert
 * ever added, even ones since trimmed from the table, the same way {@code PacketCaptureEngine}
 * keeps counting packets rather than only the ones still visible somewhere.
 *
 * <p>Not thread safe: every method must be called on the Swing event dispatch thread, same as any
 * other {@link javax.swing.table.TableModel}. {@link AlertDashboard} is the one place that calls it.
 */
public final class AlertTableModel extends AbstractTableModel {

    public static final int MAX_ROWS = 500;

    private static final String[] COLUMNS = {"Ora", "Tip", "Severitate", "IP sursă", "MAC sursă", "Mesaj"};
    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final List<Alert> rows = new ArrayList<>();
    private final Map<Severity, Integer> counts = new EnumMap<>(Severity.class);

    /** Adds an alert as the new first row, evicting the oldest row once {@link #MAX_ROWS} is passed. */
    public void addAlert(Alert alert) {
        rows.add(0, alert);
        counts.merge(alert.severity(), 1, Integer::sum);
        fireTableRowsInserted(0, 0);
        if (rows.size() > MAX_ROWS) {
            int oldest = rows.size() - 1;
            rows.remove(oldest);
            fireTableRowsDeleted(oldest, oldest);
        }
    }

    /** The alert behind a given row, for the severity-based row coloring in {@link AlertDashboard}. */
    public Alert alertAt(int row) {
        return rows.get(row);
    }

    /** How many alerts of this severity have been added so far, including ones since trimmed from the table. */
    public int countOf(Severity severity) {
        return counts.getOrDefault(severity, 0);
    }

    /** How many alerts have been added so far, of any severity. */
    public int totalCount() {
        return counts.values().stream().mapToInt(Integer::intValue).sum();
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int row, int column) {
        Alert alert = rows.get(row);
        return switch (column) {
            case 0 -> TIME_FORMAT.format(alert.timestamp());
            case 1 -> alert.type().name();
            case 2 -> alert.severity().name();
            case 3 -> alert.sourceIp();
            case 4 -> alert.sourceMac();
            case 5 -> alert.message();
            default -> throw new IllegalArgumentException("column " + column);
        };
    }
}
