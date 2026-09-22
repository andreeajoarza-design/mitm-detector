package mitmdetector.detector;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.Packet;
import mitmdetector.alert.Alert;
import mitmdetector.alert.AlertManager;
import mitmdetector.alert.AlertType;
import mitmdetector.alert.Severity;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IcmpRedirectDetectorTest {

    private static final String GATEWAY_IP = "192.168.1.1";
    private static final String GATEWAY_MAC = "aa:aa:aa:aa:aa:01";
    private static final String VICTIM_IP = "192.168.1.10";
    private static final String VICTIM_MAC = "bb:bb:bb:bb:bb:10";
    private static final String ATTACKER_IP = "192.168.1.66";
    private static final String ATTACKER_MAC = "cc:cc:cc:cc:cc:66";
    private static final String THIRD_PARTY_IP = "192.168.1.50";

    private static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");

    private AlertManager alerts;
    private IcmpRedirectDetector detector;

    @BeforeEach
    void setUp() {
        alerts = new AlertManager();
        detector = new IcmpRedirectDetector(alerts);
    }

    private void send(Packet packet, long seconds) {
        detector.inspect(packet, T0.plusSeconds(seconds));
    }

    private void redirect(String senderMac, String senderIp, String newGatewayIp, long seconds) {
        send(IcmpRedirectTestPackets.redirect(senderMac, senderIp, VICTIM_MAC, VICTIM_IP, newGatewayIp), seconds);
    }

    private List<Alert> ofType(AlertType type) {
        return alerts.history().stream().filter(a -> a.type() == type).toList();
    }

    @Test
    void repeatedRedirectsFromTheKnownGatewayRaiseNothing() {
        redirect(GATEWAY_MAC, GATEWAY_IP, THIRD_PARTY_IP, 0);   // learns the gateway
        redirect(GATEWAY_MAC, GATEWAY_IP, THIRD_PARTY_IP, 20);  // same IP, same MAC: legitimate
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void sameGatewayIpFromADifferentMacIsSpoofing() {
        redirect(GATEWAY_MAC, GATEWAY_IP, THIRD_PARTY_IP, 0);            // learns the gateway
        redirect(ATTACKER_MAC, GATEWAY_IP, ATTACKER_IP, 30);             // claims to be the gateway, wrong MAC

        List<Alert> spoofed = ofType(AlertType.ICMP_REDIRECT_SPOOFED_SENDER);
        assertEquals(1, spoofed.size());
        assertEquals(Severity.CRITICAL, spoofed.get(0).severity());
        assertEquals(GATEWAY_IP, spoofed.get(0).sourceIp());
        assertEquals(ATTACKER_MAC, spoofed.get(0).sourceMac());
        assertEquals(1, alerts.history().size());
    }

    @Test
    void untrustedSenderRedirectingToItselfIsCritical() {
        redirect(GATEWAY_MAC, GATEWAY_IP, THIRD_PARTY_IP, 0);        // learns the gateway
        redirect(ATTACKER_MAC, ATTACKER_IP, ATTACKER_IP, 30);        // "use me instead"

        List<Alert> untrusted = ofType(AlertType.ICMP_REDIRECT_UNTRUSTED_SENDER);
        assertEquals(1, untrusted.size());
        assertEquals(Severity.CRITICAL, untrusted.get(0).severity());
        assertEquals(ATTACKER_IP, untrusted.get(0).sourceIp());
        assertEquals(ATTACKER_MAC, untrusted.get(0).sourceMac());
    }

    @Test
    void untrustedSenderRedirectingToAThirdAddressIsHigh() {
        redirect(GATEWAY_MAC, GATEWAY_IP, THIRD_PARTY_IP, 0);            // learns the gateway
        redirect(ATTACKER_MAC, ATTACKER_IP, THIRD_PARTY_IP, 30);         // points elsewhere, not at itself

        List<Alert> untrusted = ofType(AlertType.ICMP_REDIRECT_UNTRUSTED_SENDER);
        assertEquals(1, untrusted.size());
        assertEquals(Severity.HIGH, untrusted.get(0).severity());
    }
}
