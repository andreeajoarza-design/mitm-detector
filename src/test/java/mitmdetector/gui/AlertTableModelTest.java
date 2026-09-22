package mitmdetector.gui;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import mitmdetector.alert.Alert;
import mitmdetector.alert.AlertType;
import mitmdetector.alert.Severity;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AlertTableModelTest {

    private static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");

    private AlertTableModel model;

    @BeforeEach
    void setUp() {
        model = new AlertTableModel();
    }

    private static Alert alert(Instant timestamp, AlertType type, Severity severity) {
        return new Alert(timestamp, type, severity, "test", "192.168.1.10", "aa:aa:aa:aa:aa:01");
    }

    @Test
    void newestAlertIsFirstRow() {
        model.addAlert(alert(T0, AlertType.ARP_SPOOFING, Severity.CRITICAL));
        model.addAlert(alert(T0.plusSeconds(1), AlertType.ARP_UNSOLICITED_FLOOD, Severity.MEDIUM));

        assertEquals(2, model.getRowCount());
        assertEquals(AlertType.ARP_UNSOLICITED_FLOOD, model.alertAt(0).type());
        assertEquals(AlertType.ARP_SPOOFING, model.alertAt(1).type());
    }

    @Test
    void columnsExposeTheFieldsOfAnAlert() {
        model.addAlert(alert(T0, AlertType.DNS_ANSWER_CHANGED, Severity.HIGH));

        assertEquals(AlertType.DNS_ANSWER_CHANGED.name(), model.getValueAt(0, 1));
        assertEquals(Severity.HIGH.name(), model.getValueAt(0, 2));
        assertEquals("192.168.1.10", model.getValueAt(0, 3));
        assertEquals("aa:aa:aa:aa:aa:01", model.getValueAt(0, 4));
        assertEquals("test", model.getValueAt(0, 5));
    }

    @Test
    void countsAreKeptBySeverityAndSurviveTrimming() {
        for (int i = 0; i < AlertTableModel.MAX_ROWS + 5; i++) {
            model.addAlert(alert(T0.plusSeconds(i), AlertType.ARP_SPOOFING, Severity.CRITICAL));
        }

        assertEquals(AlertTableModel.MAX_ROWS, model.getRowCount());
        assertEquals(AlertTableModel.MAX_ROWS + 5, model.countOf(Severity.CRITICAL));
        assertEquals(AlertTableModel.MAX_ROWS + 5, model.totalCount());
    }

    @Test
    void oldestRowIsDroppedOnceTheCapIsReached() {
        for (int i = 0; i < AlertTableModel.MAX_ROWS; i++) {
            model.addAlert(alert(T0.plusSeconds(i), AlertType.ARP_SPOOFING, Severity.LOW));
        }
        model.addAlert(alert(T0.plusSeconds(999), AlertType.HTTP_DOWNGRADE_PAGE, Severity.CRITICAL));

        assertEquals(AlertTableModel.MAX_ROWS, model.getRowCount());
        assertEquals(AlertType.HTTP_DOWNGRADE_PAGE, model.alertAt(0).type());
        assertEquals(AlertType.ARP_SPOOFING, model.alertAt(model.getRowCount() - 1).type());
    }
}
