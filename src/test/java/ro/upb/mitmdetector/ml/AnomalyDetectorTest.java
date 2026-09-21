package ro.upb.mitmdetector.ml;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.Packet;
import ro.upb.mitmdetector.alert.Alert;
import ro.upb.mitmdetector.alert.AlertManager;
import ro.upb.mitmdetector.alert.AlertType;
import ro.upb.mitmdetector.alert.Severity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.BiConsumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnomalyDetectorTest {

    private static final String GATEWAY_MAC = "aa:aa:aa:aa:aa:01";
    private static final String GATEWAY_IP = "192.168.1.1";
    private static final String VICTIM_MAC = "bb:bb:bb:bb:bb:10";
    private static final String VICTIM_IP = "192.168.1.10";
    private static final String ATTACKER_MAC = "cc:cc:cc:cc:cc:66";
    private static final String ATTACKER_IP = "192.168.1.66";
    private static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");

    /**
     * Sends the traffic of a quiet home network in 10 s windows. Most windows have a few DNS lookups and web
     * responses, a few have many (browsing bursts), and ARP is rare, as in a real capture: the counts are
     * exponentially distributed, so large values are uncommon.
     */
    private static void normalTraffic(int windowCount, long seed, BiConsumer<Packet, Instant> out) {
        Random random = new Random(seed);
        for (int w = 0; w < windowCount; w++) {
            Instant base = T0.plusSeconds(w * 10L);
            int at = 0;
            if (random.nextDouble() < 0.15) {   // an ARP exchange in about one window in seven
                out.accept(TrafficTestPackets.arpRequest(VICTIM_MAC, VICTIM_IP, GATEWAY_IP), base.plusMillis(at += 100));
                out.accept(TrafficTestPackets.arpReply(GATEWAY_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), base.plusMillis(at += 10));
            }
            for (int i = exponential(random, 4); i > 0; i--) {   // DNS lookups, mean 4, sometimes 15 or more
                out.accept(TrafficTestPackets.udp(VICTIM_MAC, GATEWAY_MAC, VICTIM_IP, GATEWAY_IP, 40000 + i, 53), base.plusMillis(at += 5));
                out.accept(TrafficTestPackets.udp(GATEWAY_MAC, VICTIM_MAC, GATEWAY_IP, VICTIM_IP, 53, 40000 + i), base.plusMillis(at += 5));
            }
            for (int i = exponential(random, 3); i > 0; i--) {   // web responses, mean 3
                out.accept(TrafficTestPackets.tcp(GATEWAY_MAC, VICTIM_MAC, "203.0.113.10", VICTIM_IP, 80, 50000 + i), base.plusMillis(at += 5));
            }
        }
    }

    private static int exponential(Random random, double mean) {
        return (int) (-Math.log(1 - random.nextDouble()) * mean);
    }

    private static double[][] baseline() {
        List<double[]> rows = new ArrayList<>();
        TrafficWindows windows = new TrafficWindows(sample -> rows.add(sample.features()));
        normalTraffic(200, 5, windows::inspect);
        windows.flush();
        return rows.toArray(new double[0][]);
    }

    /** 40 ARP replies in 5 seconds, announcing six different addresses, all from the attacker's MAC. */
    private static void arpFlood(BiConsumer<Packet, Instant> out, Instant start) {
        for (int i = 0; i < 40; i++) {
            out.accept(TrafficTestPackets.arpReply(ATTACKER_MAC, "192.168.1." + (1 + i % 6), VICTIM_MAC, VICTIM_IP),
                    start.plusMillis(i * 125L));
        }
    }

    @Test
    void trafficLikeTheBaselineRaisesNothing() {
        AlertManager alerts = new AlertManager();
        AnomalyDetector detector = new AnomalyDetector(alerts, baseline());
        normalTraffic(50, 99, detector::inspect);
        detector.flush();
        assertTrue(alerts.history().isEmpty(), "unexpected alerts: " + alerts.history());
    }

    @Test
    void arpFloodFromOneSenderIsFlagged() {
        AlertManager alerts = new AlertManager();
        AnomalyDetector detector = new AnomalyDetector(alerts, baseline());
        normalTraffic(10, 99, detector::inspect);
        arpFlood(detector::inspect, T0.plusSeconds(100));
        normalTraffic(1, 3, (p, t) -> detector.inspect(p, t.plusSeconds(200)));   // moves on to a later window
        detector.flush();

        List<Alert> found = alerts.history().stream().filter(a -> a.type() == AlertType.ML_ANOMALY).toList();
        assertEquals(1, found.size(), "history: " + alerts.history());
        Alert alert = found.get(0);
        assertEquals(Severity.MEDIUM, alert.severity());
        assertEquals(ATTACKER_MAC, alert.sourceMac());
        assertTrue(alert.sourceIp().startsWith("192.168.1."), alert.sourceIp());
        assertTrue(alert.message().contains("arpReplies 40"), alert.message());
        assertEquals(1, alerts.history().size(), "history: " + alerts.history());
    }

    @Test
    void lastWindowIsScoredOnFlush() {
        AlertManager alerts = new AlertManager();
        AnomalyDetector detector = new AnomalyDetector(alerts, baseline());
        arpFlood(detector::inspect, T0.plusSeconds(100));
        assertTrue(alerts.history().isEmpty());
        detector.flush();
        assertEquals(1, alerts.history().size());
    }

    @Test
    void alertTimeIsTheEndOfTheWindow() {
        AlertManager alerts = new AlertManager();
        AnomalyDetector detector = new AnomalyDetector(alerts, baseline());
        arpFlood(detector::inspect, T0.plusSeconds(100));
        detector.flush();
        assertEquals(T0.plusSeconds(110), alerts.history().get(0).timestamp());
    }

    @Test
    void thresholdIsNeverBelowTheMinimumAndTheSameForTheSameBaseline() {
        AnomalyDetector first = new AnomalyDetector(new AlertManager(), baseline());
        AnomalyDetector second = new AnomalyDetector(new AlertManager(), baseline());
        assertTrue(first.threshold() >= AnomalyDetector.MIN_THRESHOLD);
        assertEquals(first.threshold(), second.threshold(), 0.0);
        assertTrue(first.summary().startsWith("Baseline: "), first.summary());
    }

    @Test
    void baselineWithTooFewWindowsIsRejected() {
        double[][] small = new double[AnomalyDetector.MIN_BASELINE_WINDOWS - 1][];
        for (int i = 0; i < small.length; i++) {
            small[i] = new double[]{i, 0, 0, 0, 0, 0, 1, 0};
        }
        assertThrows(IllegalArgumentException.class, () -> new AnomalyDetector(new AlertManager(), small));
    }
}
