package mitmdetector.detector;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import mitmdetector.alert.Alert;
import mitmdetector.alert.AlertManager;
import mitmdetector.alert.AlertType;
import mitmdetector.alert.Severity;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Detects rogue DHCP servers on a local network (IPv4).
 *
 * <p>A rogue server answers clients' DISCOVER broadcasts with its own settings, usually naming itself
 * as the default gateway and DNS server, which puts it in the middle of the client's traffic.
 * A DHCP server is identified here by its IP address together with the MAC address it sends from.
 * Three checks, applied to OFFER, ACK and NAK messages (UDP port 67 to 68):
 * <ol>
 *   <li><b>Rogue server.</b> With no trusted list, the first server seen is taken as the real one, and a
 *       reply from any other IP address is HIGH. With a trusted list, a reply from an address not on it is
 *       HIGH. A reply that uses the IP of a known server but comes from another MAC is CRITICAL: someone
 *       is impersonating the server.</li>
 *   <li><b>Conflicting offers.</b> Two different servers answer the same client request (same transaction
 *       id and client MAC) within {@link #CONFLICT_WINDOW} with a different gateway or DNS server: CRITICAL.
 *       Two servers that offer the same settings are not flagged here, as happens with redundant servers.</li>
 *   <li><b>Configuration change.</b> The first OFFER or ACK from a server sets its baseline gateway and DNS
 *       servers. A later reply from the same server that names a different gateway or DNS server is HIGH,
 *       which catches an attacker who copied the server's IP and MAC but not its settings.</li>
 * </ol>
 *
 * <p>Known limitations: without a trusted list, a rogue server that answers before the real one is ever
 * seen becomes the baseline (cold start); a second legitimate server is reported as rogue unless it is
 * on the trusted list; a server that legitimately serves different scopes with different gateways triggers
 * the change check; relay agents and IPv6 (DHCPv6) are not handled. Only replies that reach the capturing
 * machine can be seen: broadcast replies do, replies sent to the client's own address do not unless the
 * detector runs on that client or on a mirrored port.
 *
 * <p>Thread safety: {@link #inspect} is synchronized.
 */
public final class DhcpDetector implements Detector {

    /** How long the first reply of an exchange is kept to compare a later one against it. */
    public static final Duration CONFLICT_WINDOW = Duration.ofSeconds(5);

    private static final int SERVER_PORT = 67;
    private static final int CLIENT_PORT = 68;

    private record ExchangeKey(int xid, String clientMac) { }

    /** What is known about one accepted server. */
    private static final class Server {
        final String mac;
        Set<String> routers = Set.of();
        Set<String> dnsServers = Set.of();

        Server(String mac) {
            this.mac = mac;
        }
    }

    /** The first reply seen for an exchange. */
    private record SeenReply(String ip, String mac, Set<String> routers, Set<String> dnsServers,
                             Instant time, boolean identityAccepted) { }

    private final AlertManager alerts;
    private final Set<String> trustedServers;
    private final Map<String, Server> servers = new HashMap<>();
    private final Map<ExchangeKey, SeenReply> recent = new HashMap<>();

    /** Learns the real server from the first reply it sees. */
    public DhcpDetector(AlertManager alerts) {
        this(alerts, Set.of());
    }

    /**
     * @param trustedServers IP addresses of the legitimate DHCP servers; if empty, the first server
     *                       seen is taken as the legitimate one
     */
    public DhcpDetector(AlertManager alerts, Set<String> trustedServers) {
        this.alerts = alerts;
        this.trustedServers = Set.copyOf(trustedServers);
    }

    @Override
    public synchronized void inspect(Packet packet, Instant timestamp) {
        EthernetPacket ethernet = packet.get(EthernetPacket.class);
        IpV4Packet ip = packet.get(IpV4Packet.class);
        UdpPacket udp = packet.get(UdpPacket.class);
        if (ethernet == null || ip == null || udp == null || udp.getPayload() == null) {
            return;
        }
        int srcPort = udp.getHeader().getSrcPort().value() & 0xFFFF;
        int dstPort = udp.getHeader().getDstPort().value() & 0xFFFF;
        if (srcPort != SERVER_PORT || dstPort != CLIENT_PORT) {
            return;
        }
        DhcpMessage message = DhcpMessage.parse(udp.getPayload().getRawData()).orElse(null);
        if (message == null || !message.isServerReply()) {
            return;
        }

        String serverIp = ip.getHeader().getSrcAddr().getHostAddress();
        String serverMac = ethernet.getHeader().getSrcAddr().toString();
        expire(timestamp);

        boolean identityAccepted = checkServer(serverIp, serverMac, timestamp);
        if (!message.carriesConfiguration()) {
            return;
        }
        if (identityAccepted) {
            checkConfiguration(message, serverIp, serverMac, timestamp);
        }
        checkConflict(message, serverIp, serverMac, identityAccepted, timestamp);
    }

    /** Returns true if the reply comes from an accepted server. */
    private boolean checkServer(String serverIp, String serverMac, Instant ts) {
        Server known = servers.get(serverIp);
        if (known != null) {
            if (known.mac.equals(serverMac)) {
                return true;
            }
            alerts.raise(new Alert(ts, AlertType.DHCP_ROGUE_SERVER, Severity.CRITICAL,
                    "DHCP server %s was seen with MAC %s, now a reply with the same IP comes from MAC %s"
                            .formatted(serverIp, known.mac, serverMac),
                    serverIp, serverMac));
            return false;
        }
        if (!trustedServers.isEmpty() && !trustedServers.contains(serverIp)) {
            alerts.raise(new Alert(ts, AlertType.DHCP_ROGUE_SERVER, Severity.HIGH,
                    "DHCP reply from %s, which is not one of the trusted servers %s"
                            .formatted(serverIp, trustedServers),
                    serverIp, serverMac));
            return false;
        }
        if (trustedServers.isEmpty() && !servers.isEmpty()) {
            alerts.raise(new Alert(ts, AlertType.DHCP_ROGUE_SERVER, Severity.HIGH,
                    "DHCP reply from %s, but the network's DHCP server so far is %s"
                            .formatted(serverIp, servers.keySet()),
                    serverIp, serverMac));
            return false;
        }
        servers.put(serverIp, new Server(serverMac));
        return true;
    }

    private void checkConfiguration(DhcpMessage message, String serverIp, String serverMac, Instant ts) {
        Server server = servers.get(serverIp);
        boolean routerChanged = differs(server.routers, message.routers());
        boolean dnsChanged = differs(server.dnsServers, message.dnsServers());
        if (routerChanged || dnsChanged) {
            alerts.raise(new Alert(ts, AlertType.DHCP_CONFIG_CHANGED, Severity.HIGH,
                    "DHCP server %s used to hand out router %s and DNS %s, now it offers router %s and DNS %s"
                            .formatted(serverIp, server.routers, server.dnsServers,
                                    message.routers(), message.dnsServers()),
                    serverIp, serverMac));
            return;
        }
        // The baseline is filled from the first reply that names a gateway or DNS server.
        if (server.routers.isEmpty()) {
            server.routers = message.routers();
        }
        if (server.dnsServers.isEmpty()) {
            server.dnsServers = message.dnsServers();
        }
    }

    private void checkConflict(DhcpMessage message, String serverIp, String serverMac,
                               boolean identityAccepted, Instant ts) {
        ExchangeKey key = new ExchangeKey(message.xid(), message.clientMac());
        SeenReply prior = recent.get(key);
        if (prior == null) {
            recent.put(key, new SeenReply(serverIp, serverMac, message.routers(), message.dnsServers(),
                    ts, identityAccepted));
            return;
        }
        boolean sameServer = prior.ip().equals(serverIp) && prior.mac().equals(serverMac);
        boolean conflict = differs(prior.routers(), message.routers()) || differs(prior.dnsServers(), message.dnsServers());
        if (sameServer || !conflict) {
            return;
        }
        // Blame the one that is not the accepted server. If that does not settle it, blame the newer reply.
        boolean blamePrior = !prior.identityAccepted() && identityAccepted;
        String blamedIp = blamePrior ? prior.ip() : serverIp;
        String blamedMac = blamePrior ? prior.mac() : serverMac;
        alerts.raise(new Alert(ts, AlertType.DHCP_CONFLICTING_OFFERS, Severity.CRITICAL,
                ("Two servers answered DHCP exchange 0x%08x from client %s with different settings: "
                        + "%s (MAC %s) says router %s, DNS %s; %s (MAC %s) says router %s, DNS %s")
                        .formatted(message.xid(), message.clientMac(),
                                prior.ip(), prior.mac(), prior.routers(), prior.dnsServers(),
                                serverIp, serverMac, message.routers(), message.dnsServers()),
                blamedIp, blamedMac));
    }

    /** True when both sets name addresses and they are not the same. A missing option is not a difference. */
    private static boolean differs(Set<String> a, Set<String> b) {
        return !a.isEmpty() && !b.isEmpty() && !a.equals(b);
    }

    private void expire(Instant now) {
        recent.values().removeIf(reply -> Duration.between(reply.time(), now).compareTo(CONFLICT_WINDOW) > 0);
    }
}
