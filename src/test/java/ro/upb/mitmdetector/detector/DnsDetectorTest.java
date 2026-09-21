package ro.upb.mitmdetector.detector;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.Packet;
import ro.upb.mitmdetector.alert.Alert;
import ro.upb.mitmdetector.alert.AlertManager;
import ro.upb.mitmdetector.alert.AlertType;
import ro.upb.mitmdetector.alert.Severity;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static ro.upb.mitmdetector.detector.DnsTestPackets.query;
import static ro.upb.mitmdetector.detector.DnsTestPackets.response;

class DnsDetectorTest {

    private static final String CLIENT_IP = "192.168.1.10";
    private static final String CLIENT_MAC = "bb:bb:bb:bb:bb:10";
    private static final String RESOLVER_IP = "192.168.1.1";
    private static final String RESOLVER_MAC = "aa:aa:aa:aa:aa:01";
    private static final String ATTACKER_MAC = "cc:cc:cc:cc:cc:66";
    private static final String ATTACKER_IP = "192.168.1.66";

    private static final String NAME = "www.example.com";
    private static final String PUBLIC_A = "198.51.100.7";
    private static final String PUBLIC_B = "203.0.113.9";

    private static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");

    private AlertManager alerts;
    private DnsDetector detector;

    @BeforeEach
    void setUp() {
        alerts = new AlertManager();
        detector = new DnsDetector(alerts);
    }

    private static Instant at(long seconds, long millis) {
        return T0.plusSeconds(seconds).plusMillis(millis);
    }

    private void send(Packet packet, long seconds, long millis) {
        detector.inspect(packet, at(seconds, millis));
    }

    private void clientQuery(long seconds, int id, String name) {
        send(query(CLIENT_MAC, CLIENT_IP, RESOLVER_MAC, RESOLVER_IP, id, name), seconds, 0);
    }

    /** Response that claims to come from the resolver, sent by the machine with the given MAC. */
    private void answer(String senderMac, long seconds, long millis, int id, String name, String... addresses) {
        send(response(senderMac, RESOLVER_IP, CLIENT_MAC, CLIENT_IP, id, name, addresses), seconds, millis);
    }

    /** A complete, normal lookup: query, then the resolver's answer 20 ms later. */
    private void lookup(long seconds, int id, String name, String... addresses) {
        clientQuery(seconds, id, name);
        answer(RESOLVER_MAC, seconds, 20, id, name, addresses);
    }

    private List<Alert> ofType(AlertType type) {
        return alerts.history().stream().filter(a -> a.type() == type).toList();
    }

    @Test
    void normalLookupsRaiseNothing() {
        lookup(0, 1, NAME, PUBLIC_A);
        lookup(10, 2, NAME, PUBLIC_A);
        lookup(20, 3, "mail.example.com", PUBLIC_B);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void identicalDuplicateResponseIsNotAConflict() {
        lookup(0, 1, NAME, PUBLIC_A);
        answer(RESOLVER_MAC, 0, 40, 1, NAME, PUBLIC_A);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void addressRotationBetweenPublicAddressesIsNotAnAlert() {
        lookup(0, 1, NAME, PUBLIC_A);
        lookup(10, 2, NAME, PUBLIC_A);
        lookup(20, 3, NAME, PUBLIC_B);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void privateAddressForNameWithPublicHistoryIsHigh() {
        lookup(0, 1, NAME, PUBLIC_A);
        lookup(10, 2, NAME, PUBLIC_A);

        clientQuery(30, 3, NAME);
        send(response(ATTACKER_MAC, RESOLVER_IP, CLIENT_MAC, CLIENT_IP, 3, NAME, ATTACKER_IP), 30, 3);

        List<Alert> changed = ofType(AlertType.DNS_ANSWER_CHANGED);
        assertEquals(1, changed.size());
        assertEquals(Severity.HIGH, changed.get(0).severity());
        assertEquals(RESOLVER_IP, changed.get(0).sourceIp());
        assertEquals(ATTACKER_MAC, changed.get(0).sourceMac());
    }

    @Test
    void privateAddressWithoutHistoryIsNotAlerted() {
        // First time this name is seen: no baseline, so nothing to compare with.
        lookup(0, 1, NAME, ATTACKER_IP);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void internalNameKeepsResolvingToPrivateAddress() {
        lookup(0, 1, "intranet.local", "192.168.1.50");
        lookup(10, 2, "intranet.local", "192.168.1.50");
        lookup(20, 3, "intranet.local", "192.168.1.51");
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void forgedAnswerIsNotLearnedAsNormal() {
        lookup(0, 1, NAME, PUBLIC_A);
        lookup(10, 2, NAME, PUBLIC_A);

        for (int i = 0; i < 2; i++) {
            long t = 30 + i * 30L;
            clientQuery(t, 10 + i, NAME);
            send(response(ATTACKER_MAC, RESOLVER_IP, CLIENT_MAC, CLIENT_IP, 10 + i, NAME, ATTACKER_IP), t, 3);
        }
        // Still flagged the second time, even though the same forged answer was seen before.
        assertEquals(2, ofType(AlertType.DNS_ANSWER_CHANGED).size());
    }

    @Test
    void conflictingResponsesFromDifferentMacsAreCritical() {
        clientQuery(0, 5, NAME);
        answer(ATTACKER_MAC, 0, 3, 5, NAME, PUBLIC_B);   // the fast forged answer
        answer(RESOLVER_MAC, 0, 30, 5, NAME, PUBLIC_A);  // the real one, a bit later

        List<Alert> conflicts = ofType(AlertType.DNS_CONFLICTING_RESPONSES);
        assertEquals(1, conflicts.size());
        assertEquals(Severity.CRITICAL, conflicts.get(0).severity());
        assertEquals(ATTACKER_MAC, conflicts.get(0).sourceMac());
        assertEquals(RESOLVER_IP, conflicts.get(0).sourceIp());
        assertEquals(1, alerts.history().size());
    }

    @Test
    void conflictingResponsesFromSameMacAreHigh() {
        clientQuery(0, 5, NAME);
        answer(RESOLVER_MAC, 0, 20, 5, NAME, PUBLIC_A);
        answer(RESOLVER_MAC, 0, 40, 5, NAME, PUBLIC_B);

        List<Alert> conflicts = ofType(AlertType.DNS_CONFLICTING_RESPONSES);
        assertEquals(1, conflicts.size());
        assertEquals(Severity.HIGH, conflicts.get(0).severity());
    }

    @Test
    void secondResponseAfterTheWindowIsNotCompared() {
        clientQuery(0, 5, NAME);
        answer(RESOLVER_MAC, 0, 20, 5, NAME, PUBLIC_A);
        answer(RESOLVER_MAC, 8, 0, 5, NAME, PUBLIC_B);   // 8 s later, the window is 5 s
        assertTrue(ofType(AlertType.DNS_CONFLICTING_RESPONSES).isEmpty());
    }

    @Test
    void unsolicitedResponseAfterWarmUpIsMedium() {
        lookup(0, 1, NAME, PUBLIC_A);

        answer(ATTACKER_MAC, 20, 0, 9, "login.example.com", ATTACKER_IP);

        List<Alert> unsolicited = ofType(AlertType.DNS_UNSOLICITED_RESPONSE);
        assertEquals(1, unsolicited.size());
        assertEquals(Severity.MEDIUM, unsolicited.get(0).severity());
        assertEquals(ATTACKER_MAC, unsolicited.get(0).sourceMac());
    }

    @Test
    void unsolicitedResponseDuringWarmUpIsIgnored() {
        // The capture may have started after the query was sent.
        answer(RESOLVER_MAC, 0, 0, 9, NAME, PUBLIC_A);
        answer(RESOLVER_MAC, 5, 0, 10, NAME, PUBLIC_A);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void responseToExpiredQueryIsUnsolicited() {
        clientQuery(0, 3, NAME);
        answer(RESOLVER_MAC, 15, 0, 3, NAME, PUBLIC_A);   // the query is older than 10 s by now
        assertEquals(1, ofType(AlertType.DNS_UNSOLICITED_RESPONSE).size());
    }

    @Test
    void responseWithWrongTransactionIdIsUnsolicited() {
        lookup(0, 1, NAME, PUBLIC_A);
        clientQuery(20, 2, NAME);
        answer(ATTACKER_MAC, 20, 3, 0x7777, NAME, PUBLIC_B);   // guessed the id wrong
        assertEquals(1, ofType(AlertType.DNS_UNSOLICITED_RESPONSE).size());
    }

    @Test
    void udpTrafficOnOtherPortsIsIgnored() {
        byte[] dns = DnsTestPackets.dnsResponse(1, NAME, ATTACKER_IP);
        send(DnsTestPackets.udp(ATTACKER_MAC, CLIENT_MAC, RESOLVER_IP, CLIENT_IP, 123, 5000, dns), 0, 0);
        send(DnsTestPackets.udp(ATTACKER_MAC, CLIENT_MAC, RESOLVER_IP, CLIENT_IP, 123, 5000, dns), 30, 0);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void malformedDnsPayloadIsIgnored() {
        byte[] garbage = {1, 2, 3, 4, 5, 6, 7, 8, 9};
        send(DnsTestPackets.udp(RESOLVER_MAC, CLIENT_MAC, RESOLVER_IP, CLIENT_IP, 53, 40001, garbage), 0, 0);
        send(DnsTestPackets.udp(CLIENT_MAC, RESOLVER_MAC, CLIENT_IP, RESOLVER_IP, 40001, 53, garbage), 30, 0);
        assertTrue(alerts.history().isEmpty());
    }
}
