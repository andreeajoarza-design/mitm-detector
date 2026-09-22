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
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static mitmdetector.detector.DhcpTestPackets.ACK;
import static mitmdetector.detector.DhcpTestPackets.NAK;
import static mitmdetector.detector.DhcpTestPackets.OFFER;

class DhcpDetectorTest {

    private static final String SERVER_IP = "192.168.1.1";
    private static final String SERVER_MAC = "aa:aa:aa:aa:aa:01";
    private static final String SECOND_IP = "192.168.1.2";
    private static final String SECOND_MAC = "aa:aa:aa:aa:aa:02";
    private static final String ROGUE_IP = "192.168.1.66";
    private static final String ROGUE_MAC = "cc:cc:cc:cc:cc:66";
    private static final String CLIENT_MAC = "bb:bb:bb:bb:bb:10";

    private static final String[] REAL_SETTINGS = {"192.168.1.1"};
    private static final String[] ROGUE_SETTINGS = {"192.168.1.66"};
    private static final String[] SECOND_SETTINGS = {"192.168.1.2"};
    private static final String[] NONE = {};

    private static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");

    private AlertManager alerts;
    private DhcpDetector detector;

    @BeforeEach
    void setUp() {
        alerts = new AlertManager();
        detector = new DhcpDetector(alerts);
    }

    private void send(Packet packet, long seconds, long millis) {
        detector.inspect(packet, T0.plusSeconds(seconds).plusMillis(millis));
    }

    private void reply(String mac, String ip, int type, int xid, String[] settings, long seconds, long millis) {
        send(DhcpTestPackets.reply(mac, ip, type, xid, CLIENT_MAC, settings, settings), seconds, millis);
    }

    private void realServer(int type, int xid, long seconds, long millis) {
        reply(SERVER_MAC, SERVER_IP, type, xid, REAL_SETTINGS, seconds, millis);
    }

    private List<Alert> ofType(AlertType type) {
        return alerts.history().stream().filter(a -> a.type() == type).toList();
    }

    @Test
    void normalExchangesFromOneServerRaiseNothing() {
        send(DhcpTestPackets.discover(CLIENT_MAC, 1), 0, 0);
        realServer(OFFER, 1, 0, 20);
        realServer(ACK, 1, 0, 60);
        send(DhcpTestPackets.discover(CLIENT_MAC, 2), 20, 0);
        realServer(OFFER, 2, 20, 20);
        realServer(ACK, 2, 20, 60);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void secondServerIsFlaggedAsRogue() {
        realServer(OFFER, 1, 0, 0);
        reply(ROGUE_MAC, ROGUE_IP, OFFER, 2, ROGUE_SETTINGS, 30, 0);

        List<Alert> rogue = ofType(AlertType.DHCP_ROGUE_SERVER);
        assertEquals(1, rogue.size());
        assertEquals(Severity.HIGH, rogue.get(0).severity());
        assertEquals(ROGUE_IP, rogue.get(0).sourceIp());
        assertEquals(ROGUE_MAC, rogue.get(0).sourceMac());
        assertEquals(1, alerts.history().size());
    }

    @Test
    void rogueThatAnswersFirstIsBlamedForTheConflict() {
        realServer(OFFER, 1, 0, 0);

        reply(ROGUE_MAC, ROGUE_IP, OFFER, 5, ROGUE_SETTINGS, 30, 5);   // fast rogue answer
        realServer(OFFER, 5, 30, 20);                                  // the real server, a bit later

        assertEquals(2, alerts.history().size());
        assertEquals(1, ofType(AlertType.DHCP_ROGUE_SERVER).size());
        List<Alert> conflicts = ofType(AlertType.DHCP_CONFLICTING_OFFERS);
        assertEquals(1, conflicts.size());
        assertEquals(Severity.CRITICAL, conflicts.get(0).severity());
        assertEquals(ROGUE_IP, conflicts.get(0).sourceIp());
        assertEquals(ROGUE_MAC, conflicts.get(0).sourceMac());
    }

    @Test
    void rogueThatAnswersSecondIsBlamedForTheConflict() {
        realServer(OFFER, 1, 0, 0);

        realServer(OFFER, 5, 30, 5);
        reply(ROGUE_MAC, ROGUE_IP, OFFER, 5, ROGUE_SETTINGS, 30, 20);

        List<Alert> conflicts = ofType(AlertType.DHCP_CONFLICTING_OFFERS);
        assertEquals(1, conflicts.size());
        assertEquals(ROGUE_IP, conflicts.get(0).sourceIp());
        assertEquals(ROGUE_MAC, conflicts.get(0).sourceMac());
    }

    @Test
    void sameIpFromAnotherMacIsImpersonation() {
        realServer(OFFER, 1, 0, 0);
        reply(ROGUE_MAC, SERVER_IP, OFFER, 2, ROGUE_SETTINGS, 30, 0);

        List<Alert> rogue = ofType(AlertType.DHCP_ROGUE_SERVER);
        assertEquals(1, rogue.size());
        assertEquals(Severity.CRITICAL, rogue.get(0).severity());
        assertEquals(SERVER_IP, rogue.get(0).sourceIp());
        assertEquals(ROGUE_MAC, rogue.get(0).sourceMac());
        assertEquals(1, alerts.history().size());
    }

    @Test
    void knownServerHandingOutAnotherGatewayIsFlagged() {
        realServer(OFFER, 1, 0, 0);
        reply(SERVER_MAC, SERVER_IP, OFFER, 2, ROGUE_SETTINGS, 20, 0);

        List<Alert> changed = ofType(AlertType.DHCP_CONFIG_CHANGED);
        assertEquals(1, changed.size());
        assertEquals(Severity.HIGH, changed.get(0).severity());
        assertEquals(SERVER_IP, changed.get(0).sourceIp());
        assertEquals(1, alerts.history().size());
    }

    @Test
    void replyWithoutGatewayOrDnsIsNotAChange() {
        realServer(OFFER, 1, 0, 0);
        reply(SERVER_MAC, SERVER_IP, ACK, 2, NONE, 20, 0);   // e.g. an ACK to a DHCPINFORM
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void secondServerWithSameSettingsIsRogueButNotAConflict() {
        realServer(OFFER, 1, 0, 0);
        realServer(OFFER, 5, 30, 0);
        reply(SECOND_MAC, SECOND_IP, OFFER, 5, REAL_SETTINGS, 30, 10);

        assertEquals(1, ofType(AlertType.DHCP_ROGUE_SERVER).size());
        assertTrue(ofType(AlertType.DHCP_CONFLICTING_OFFERS).isEmpty());
    }

    @Test
    void trustedListAcceptsBothRedundantServers() {
        detector = new DhcpDetector(alerts, Set.of(SERVER_IP, SECOND_IP));
        realServer(OFFER, 5, 0, 0);
        reply(SECOND_MAC, SECOND_IP, OFFER, 5, REAL_SETTINGS, 0, 10);
        realServer(ACK, 5, 0, 50);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void trustedServersWithDifferentSettingsStillConflict() {
        detector = new DhcpDetector(alerts, Set.of(SERVER_IP, SECOND_IP));
        realServer(OFFER, 5, 0, 0);
        reply(SECOND_MAC, SECOND_IP, OFFER, 5, SECOND_SETTINGS, 0, 10);

        List<Alert> conflicts = ofType(AlertType.DHCP_CONFLICTING_OFFERS);
        assertEquals(1, conflicts.size());
        assertEquals(Severity.CRITICAL, conflicts.get(0).severity());
        assertEquals(SECOND_IP, conflicts.get(0).sourceIp());   // both accepted: the newer reply is blamed
        assertEquals(1, alerts.history().size());
    }

    @Test
    void trustedListRejectsUnlistedServerEvenAsFirstReply() {
        detector = new DhcpDetector(alerts, Set.of(SERVER_IP));
        reply(ROGUE_MAC, ROGUE_IP, OFFER, 1, ROGUE_SETTINGS, 0, 0);
        realServer(OFFER, 2, 20, 0);

        List<Alert> rogue = ofType(AlertType.DHCP_ROGUE_SERVER);
        assertEquals(1, rogue.size());
        assertEquals(ROGUE_IP, rogue.get(0).sourceIp());
        assertEquals(1, alerts.history().size());
    }

    @Test
    void nakFromUnknownServerIsFlagged() {
        realServer(OFFER, 1, 0, 0);
        send(DhcpTestPackets.reply(ROGUE_MAC, ROGUE_IP, NAK, 2, CLIENT_MAC, NONE, NONE), 30, 0);
        assertEquals(1, ofType(AlertType.DHCP_ROGUE_SERVER).size());
    }

    @Test
    void rogueServerIsNeverLearnedAsNormal() {
        realServer(OFFER, 1, 0, 0);
        reply(ROGUE_MAC, ROGUE_IP, OFFER, 2, ROGUE_SETTINGS, 30, 0);
        reply(ROGUE_MAC, ROGUE_IP, OFFER, 3, ROGUE_SETTINGS, 60, 0);
        assertEquals(2, ofType(AlertType.DHCP_ROGUE_SERVER).size());
    }

    @Test
    void repliesFarApartAreNotComparedForConflicts() {
        realServer(OFFER, 1, 0, 0);
        realServer(OFFER, 5, 30, 0);
        reply(SECOND_MAC, SECOND_IP, OFFER, 5, SECOND_SETTINGS, 38, 0);   // window is 5 s

        assertTrue(ofType(AlertType.DHCP_CONFLICTING_OFFERS).isEmpty());
        assertEquals(1, ofType(AlertType.DHCP_ROGUE_SERVER).size());
    }

    @Test
    void clientMessagesAndOtherPortsAreIgnored() {
        realServer(OFFER, 1, 0, 0);
        send(DhcpTestPackets.discover(CLIENT_MAC, 2), 30, 0);

        byte[] fake = DhcpTestPackets.dhcp(2, 3, CLIENT_MAC, OFFER, ROGUE_IP, ROGUE_SETTINGS, ROGUE_SETTINGS);
        send(DnsTestPackets.udp(ROGUE_MAC, CLIENT_MAC, ROGUE_IP, "192.168.1.10", 5000, 68, fake), 31, 0);
        send(DnsTestPackets.udp(ROGUE_MAC, CLIENT_MAC, ROGUE_IP, "192.168.1.10", 68, 67, fake), 32, 0);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void malformedPayloadIsIgnored() {
        byte[] garbage = {1, 2, 3, 4, 5, 6, 7, 8, 9};
        send(DnsTestPackets.udp(ROGUE_MAC, CLIENT_MAC, ROGUE_IP, "255.255.255.255", 67, 68, garbage), 0, 0);
        realServer(OFFER, 1, 10, 0);
        assertTrue(alerts.history().isEmpty());
    }
}
