package ro.upb.mitmdetector.detector;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ro.upb.mitmdetector.alert.Alert;
import ro.upb.mitmdetector.alert.AlertManager;
import ro.upb.mitmdetector.alert.AlertType;
import ro.upb.mitmdetector.alert.Severity;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static ro.upb.mitmdetector.detector.ArpTestPackets.reply;
import static ro.upb.mitmdetector.detector.ArpTestPackets.replyWithSpoofedEthernetSource;
import static ro.upb.mitmdetector.detector.ArpTestPackets.request;

class ArpDetectorTest {

    private static final String GATEWAY_IP = "192.168.1.1";
    private static final String GATEWAY_MAC = "aa:aa:aa:aa:aa:01";
    private static final String VICTIM_IP = "192.168.1.10";
    private static final String VICTIM_MAC = "bb:bb:bb:bb:bb:10";
    private static final String ATTACKER_IP = "192.168.1.66";
    private static final String ATTACKER_MAC = "cc:cc:cc:cc:cc:66";

    private static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");

    private AlertManager alerts;
    private ArpDetector detector;

    @BeforeEach
    void setUp() {
        alerts = new AlertManager();
        detector = new ArpDetector(alerts);
    }

    private static Instant at(long seconds) {
        return T0.plusSeconds(seconds);
    }

    private List<Alert> ofType(AlertType type) {
        return alerts.history().stream().filter(a -> a.type() == type).toList();
    }

    @Test
    void normalRequestAndReplyRaiseNothing() {
        detector.inspect(request(VICTIM_MAC, VICTIM_IP, GATEWAY_IP), at(0));
        detector.inspect(reply(GATEWAY_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(1));

        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void sameBindingRepeatedIsNotAnAlert() {
        for (int i = 0; i < 20; i++) {
            detector.inspect(request(VICTIM_MAC, VICTIM_IP, GATEWAY_IP), at(i));
            detector.inspect(reply(GATEWAY_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(i));
        }
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void gatewayIpAnnouncedWithAttackerMacIsHigh() {
        detector.inspect(request(VICTIM_MAC, VICTIM_IP, GATEWAY_IP), at(0));
        detector.inspect(reply(GATEWAY_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(1));

        // Attacker answers a later request for the gateway with its own MAC.
        detector.inspect(request(VICTIM_MAC, VICTIM_IP, GATEWAY_IP), at(30));
        detector.inspect(reply(ATTACKER_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(31));

        List<Alert> spoofing = ofType(AlertType.ARP_SPOOFING);
        assertEquals(1, spoofing.size());
        assertEquals(Severity.HIGH, spoofing.get(0).severity());
        assertEquals(GATEWAY_IP, spoofing.get(0).sourceIp());
        assertEquals(ATTACKER_MAC, spoofing.get(0).sourceMac());
    }

    @Test
    void attackerMacThatAlreadyOwnsAnotherIpIsCritical() {
        // Attacker is a normal host first.
        detector.inspect(request(ATTACKER_MAC, ATTACKER_IP, GATEWAY_IP), at(0));
        detector.inspect(reply(GATEWAY_MAC, GATEWAY_IP, ATTACKER_MAC, ATTACKER_IP), at(1));

        // Then it claims the gateway IP too.
        detector.inspect(request(VICTIM_MAC, VICTIM_IP, GATEWAY_IP), at(20));
        detector.inspect(reply(ATTACKER_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(21));

        List<Alert> spoofing = ofType(AlertType.ARP_SPOOFING);
        assertEquals(1, spoofing.size());
        assertEquals(Severity.CRITICAL, spoofing.get(0).severity());
    }

    @Test
    void repeatedForgedPacketsAreCollapsedByCooldown() {
        detector.inspect(reply(GATEWAY_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(0));
        for (int i = 1; i <= 5; i++) {
            detector.inspect(reply(ATTACKER_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(i));
        }
        assertEquals(1, ofType(AlertType.ARP_SPOOFING).size());
    }

    @Test
    void forgedPacketsAfterCooldownAlertAgain() {
        detector.inspect(reply(GATEWAY_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(0));
        detector.inspect(reply(ATTACKER_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(1));
        detector.inspect(reply(ATTACKER_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(60));
        assertEquals(2, ofType(AlertType.ARP_SPOOFING).size());
    }

    @Test
    void ethernetSourceDifferentFromArpSenderIsFlagged() {
        detector.inspect(replyWithSpoofedEthernetSource(ATTACKER_MAC, GATEWAY_MAC,
                GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(0));

        List<Alert> mismatch = ofType(AlertType.ARP_HEADER_MISMATCH);
        assertEquals(1, mismatch.size());
        assertEquals(Severity.MEDIUM, mismatch.get(0).severity());
    }

    @Test
    void manyUnsolicitedRepliesAreFlagged() {
        // Poisoning tool re-announces every second, nobody asked.
        for (int i = 0; i < ArpDetector.UNSOLICITED_THRESHOLD; i++) {
            detector.inspect(reply(ATTACKER_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(i));
        }
        assertEquals(1, ofType(AlertType.ARP_UNSOLICITED_FLOOD).size());
    }

    @Test
    void fewUnsolicitedRepliesAreTolerated() {
        // One gratuitous reply, e.g. a host booting up.
        detector.inspect(reply(GATEWAY_MAC, GATEWAY_IP, GATEWAY_MAC, GATEWAY_IP), at(0));
        assertTrue(ofType(AlertType.ARP_UNSOLICITED_FLOOD).isEmpty());
    }

    @Test
    void repliesToRealRequestsNeverCountAsUnsolicited() {
        for (int i = 0; i < 30; i++) {
            detector.inspect(request(VICTIM_MAC, VICTIM_IP, GATEWAY_IP), at(i));
            detector.inspect(reply(GATEWAY_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(i));
        }
        assertTrue(ofType(AlertType.ARP_UNSOLICITED_FLOOD).isEmpty());
    }

    @Test
    void replyAfterRequestExpiredCountsAsUnsolicited() {
        detector.inspect(request(VICTIM_MAC, VICTIM_IP, GATEWAY_IP), at(0));
        // The request is older than REQUEST_TTL (5 s) by the time these replies arrive.
        for (int i = 0; i < ArpDetector.UNSOLICITED_THRESHOLD; i++) {
            detector.inspect(reply(ATTACKER_MAC, GATEWAY_IP, VICTIM_MAC, VICTIM_IP), at(6 + i));
        }
        assertEquals(1, ofType(AlertType.ARP_UNSOLICITED_FLOOD).size());
    }

    @Test
    void arpProbeFromZeroAddressDoesNotCreateBinding() {
        detector.inspect(request(VICTIM_MAC, "0.0.0.0", VICTIM_IP), at(0));
        detector.inspect(request(ATTACKER_MAC, "0.0.0.0", VICTIM_IP), at(1));
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void nonArpPacketsAreIgnored() {
        org.pcap4j.packet.Packet notArp = new org.pcap4j.packet.UnknownPacket.Builder()
                .rawData(new byte[]{1, 2, 3}).build();
        detector.inspect(notArp, at(0));
        assertTrue(alerts.history().isEmpty());
    }
}
