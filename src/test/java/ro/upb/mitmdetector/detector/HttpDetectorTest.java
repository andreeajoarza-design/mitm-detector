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
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpDetectorTest {

    private static final String CLIENT_IP = "192.168.1.10";
    private static final String CLIENT_MAC = "bb:bb:bb:bb:bb:10";
    private static final String GATEWAY_MAC = "aa:aa:aa:aa:aa:01";
    private static final String ATTACKER_MAC = "cc:cc:cc:cc:cc:66";
    private static final String SERVER_IP = "203.0.113.10";
    private static final String HOST = "shop.example.net";
    private static final int PORT = 50000;

    private static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");

    private AlertManager alerts;
    private HttpDetector detector;

    @BeforeEach
    void setUp() {
        alerts = new AlertManager();
        detector = new HttpDetector(alerts);
    }

    private void send(Packet packet, long seconds) {
        detector.inspect(packet, T0.plusSeconds(seconds));
    }

    private void request(String host, String path, int port, long seconds) {
        send(HttpTestPackets.get(CLIENT_MAC, GATEWAY_MAC, CLIENT_IP, SERVER_IP, port, host, path), seconds);
    }

    /** The real site tells the client to go to HTTPS. */
    private void learn(long seconds) {
        request(HOST, "/", PORT, seconds);
        send(HttpTestPackets.redirect(GATEWAY_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, PORT, 301,
                "https://" + HOST + "/"), seconds);
    }

    private void pageFrom(String mac, String contentType, int port, long seconds) {
        send(HttpTestPackets.ok(mac, CLIENT_MAC, SERVER_IP, CLIENT_IP, port, contentType), seconds);
    }

    private List<Alert> ofType(AlertType type) {
        return alerts.history().stream().filter(a -> a.type() == type).toList();
    }

    @Test
    void repeatedRedirectsAreNormal() {
        learn(0);
        learn(20);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void htmlPageFromHostThatNeverRedirectedIsNormal() {
        request("plain.example.org", "/", PORT, 0);
        pageFrom(GATEWAY_MAC, "text/html", PORT, 0);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void htmlPageAfterHttpsRedirectIsFlagged() {
        learn(0);
        request(HOST, "/", PORT + 1, 20);
        pageFrom(GATEWAY_MAC, "text/html; charset=utf-8", PORT + 1, 20);

        List<Alert> page = ofType(AlertType.HTTP_DOWNGRADE_PAGE);
        assertEquals(1, page.size());
        assertEquals(Severity.HIGH, page.get(0).severity());        // same MAC as the redirect
        assertEquals(SERVER_IP, page.get(0).sourceIp());
        assertEquals(GATEWAY_MAC, page.get(0).sourceMac());
        assertEquals(1, alerts.history().size());
    }

    @Test
    void pageFromAnotherMacIsCritical() {
        learn(0);
        request(HOST, "/account", PORT + 1, 20);
        pageFrom(ATTACKER_MAC, "text/html", PORT + 1, 20);

        List<Alert> page = ofType(AlertType.HTTP_DOWNGRADE_PAGE);
        assertEquals(1, page.size());
        assertEquals(Severity.CRITICAL, page.get(0).severity());
        assertEquals(ATTACKER_MAC, page.get(0).sourceMac());
    }

    @Test
    void nonHtmlResourceOverHttpIsIgnored() {
        learn(0);
        request(HOST, "/logo.png", PORT + 1, 20);
        pageFrom(GATEWAY_MAC, "image/png", PORT + 1, 20);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void acmeChallengeIsIgnored() {
        learn(0);
        request(HOST, "/.well-known/acme-challenge/abc123?x=1", PORT + 1, 20);
        pageFrom(GATEWAY_MAC, "text/html", PORT + 1, 20);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void redirectDowngradedToHttpIsFlagged() {
        learn(0);
        request(HOST, "/login", PORT + 1, 20);
        send(HttpTestPackets.redirect(ATTACKER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, PORT + 1, 302,
                "http://www." + HOST + "/login"), 20);

        List<Alert> downgrade = ofType(AlertType.HTTP_DOWNGRADE_REDIRECT);
        assertEquals(1, downgrade.size());
        assertEquals(Severity.CRITICAL, downgrade.get(0).severity());
        assertEquals(ATTACKER_MAC, downgrade.get(0).sourceMac());
        assertEquals(1, alerts.history().size());
    }

    @Test
    void redirectToHttpForAnUnknownHostIsIgnored() {
        request("plain.example.org", "/", PORT, 0);
        send(HttpTestPackets.redirect(GATEWAY_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, PORT, 301,
                "http://www.plain.example.org/"), 0);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void redirectToAnotherDomainIsNotLearned() {
        request(HOST, "/", PORT, 0);
        send(HttpTestPackets.redirect(GATEWAY_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, PORT, 302,
                "https://tracker.other.example/r?u=1"), 0);

        request(HOST, "/", PORT + 1, 20);
        pageFrom(GATEWAY_MAC, "text/html", PORT + 1, 20);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void redirectToWwwVariantIsLearned() {
        request(HOST, "/", PORT, 0);
        send(HttpTestPackets.redirect(GATEWAY_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, PORT, 308,
                "https://www." + HOST + "/"), 0);

        request(HOST, "/", PORT + 1, 20);
        pageFrom(GATEWAY_MAC, "text/html", PORT + 1, 20);
        assertEquals(1, ofType(AlertType.HTTP_DOWNGRADE_PAGE).size());
    }

    @Test
    void listedHostIsProtectedFromTheStart() {
        detector = new HttpDetector(alerts, Set.of("Shop.Example.NET"));
        request(HOST, "/", PORT, 0);
        pageFrom(ATTACKER_MAC, "text/html", PORT, 0);

        List<Alert> page = ofType(AlertType.HTTP_DOWNGRADE_PAGE);
        assertEquals(1, page.size());
        assertEquals(Severity.HIGH, page.get(0).severity());   // no earlier MAC to compare with
    }

    @Test
    void hostHeaderPortAndCaseAreIgnored() {
        learn(0);
        request("SHOP.example.net:80", "/", PORT + 1, 20);
        pageFrom(GATEWAY_MAC, "text/html", PORT + 1, 20);
        assertEquals(1, ofType(AlertType.HTTP_DOWNGRADE_PAGE).size());
    }

    @Test
    void responseWithoutRequestIsIgnored() {
        learn(0);
        pageFrom(ATTACKER_MAC, "text/html", PORT + 7, 20);
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void requestExpiresBeforeTheResponse() {
        learn(0);
        request(HOST, "/", PORT + 1, 20);
        pageFrom(ATTACKER_MAC, "text/html", PORT + 1, 60);   // 40 s later, limit is 30 s
        assertTrue(alerts.history().isEmpty());
    }

    @Test
    void flaggedPageDoesNotChangeWhatIsKnownAboutTheHost() {
        learn(0);
        request(HOST, "/", PORT + 1, 20);
        pageFrom(ATTACKER_MAC, "text/html", PORT + 1, 20);
        request(HOST, "/", PORT + 2, 40);
        pageFrom(ATTACKER_MAC, "text/html", PORT + 2, 40);   // past the alert cooldown: flagged again
        assertEquals(2, ofType(AlertType.HTTP_DOWNGRADE_PAGE).size());
    }

    @Test
    void otherPortsAndNonHttpPayloadsAreIgnored() {
        learn(0);
        send(HttpTestPackets.tcp(CLIENT_MAC, GATEWAY_MAC, CLIENT_IP, SERVER_IP, PORT + 1, 8080,
                HttpTestPackets.bytes("GET / HTTP/1.1\r\nHost: " + HOST + "\r\n\r\n")), 20);
        send(HttpTestPackets.tcp(ATTACKER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 8080, PORT + 1,
                HttpTestPackets.bytes("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")), 20);

        request(HOST, "/", PORT + 2, 30);
        send(HttpTestPackets.tcp(ATTACKER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 80, PORT + 2,
                new byte[]{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}), 30);
        assertTrue(alerts.history().isEmpty());
    }
}
