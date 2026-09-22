package mitmdetector.ml;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.ArpOperation;
import mitmdetector.detector.Detector;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Consumer;

/**
 * Cuts the traffic into windows of {@link #WINDOW} and counts, for each sender (Ethernet source MAC),
 * a few things about what it sent in that window. Every finished window is passed to a consumer as
 * one {@link Sample} per sender, with the counts as a feature vector in the order of {@link #FEATURES}.
 *
 * <p>Windows follow the capture timestamps and are aligned to multiples of {@link #WINDOW} since the
 * epoch. A window is finished when the first packet of a later window arrives, or when
 * {@link #flush()} is called at the end of the capture. Windows without any packet produce nothing.
 *
 * <p>Thread safety: {@link #inspect} and {@link #flush} are synchronized.
 */
public final class TrafficWindows implements Detector {

    public static final Duration WINDOW = Duration.ofSeconds(10);

    /** Order of the values in {@link Sample#features()}. */
    public static final List<String> FEATURES = List.of(
            "packets",        // all packets sent
            "arpRequests",    // ARP requests sent
            "arpReplies",     // ARP replies sent
            "arpSenderIps",   // different IP addresses announced as sender in ARP packets
            "dnsResponses",   // UDP packets from port 53
            "dhcpReplies",    // UDP packets from port 67
            "destinations",   // different destination IPv4 addresses
            "httpResponses"); // TCP packets with data from port 80

    /** Limits that keep memory bounded when someone floods the network with random addresses. */
    private static final int MAX_SENDERS_PER_WINDOW = 5_000;
    private static final int MAX_ADDRESSES_PER_SENDER = 1_000;

    /**
     * One sender in one finished window.
     *
     * @param windowEnd end of the window
     * @param mac       Ethernet source address of the sender
     * @param ip        last IPv4 address the sender used in the window, or "unknown"
     * @param features  the counts, see {@link #FEATURES}
     */
    public record Sample(Instant windowEnd, String mac, String ip, double[] features) { }

    private static final class Counts {
        int packets;
        int arpRequests;
        int arpReplies;
        int dnsResponses;
        int dhcpReplies;
        int httpResponses;
        final Set<String> arpSenderIps = new HashSet<>();
        final Set<String> destinations = new HashSet<>();
        String lastIp = "unknown";

        double[] toFeatures() {
            return new double[]{packets, arpRequests, arpReplies, arpSenderIps.size(),
                    dnsResponses, dhcpReplies, destinations.size(), httpResponses};
        }
    }

    private final Consumer<Sample> sink;
    private final Map<String, Counts> current = new TreeMap<>();   // sorted by MAC: same order on every run
    private long currentWindow = Long.MIN_VALUE;

    public TrafficWindows(Consumer<Sample> sink) {
        this.sink = sink;
    }

    @Override
    public synchronized void inspect(Packet packet, Instant timestamp) {
        EthernetPacket ethernet = packet.get(EthernetPacket.class);
        if (ethernet == null) {
            return;
        }
        long window = Math.floorDiv(timestamp.toEpochMilli(), WINDOW.toMillis());
        if (currentWindow == Long.MIN_VALUE) {
            currentWindow = window;
        } else if (window > currentWindow) {
            flush();
            currentWindow = window;
        }   // an older timestamp (out-of-order capture) is counted in the current window

        String mac = ethernet.getHeader().getSrcAddr().toString();
        Counts counts = current.get(mac);
        if (counts == null) {
            if (current.size() >= MAX_SENDERS_PER_WINDOW) {
                return;
            }
            counts = new Counts();
            current.put(mac, counts);
        }
        count(counts, packet);
    }

    /** Finishes the current window, if it has any packets. Call it at the end of a capture. */
    @Override
    public synchronized void flush() {
        if (current.isEmpty()) {
            currentWindow = Long.MIN_VALUE;
            return;
        }
        Instant end = Instant.ofEpochMilli((currentWindow + 1) * WINDOW.toMillis());
        for (Map.Entry<String, Counts> entry : current.entrySet()) {
            Counts counts = entry.getValue();
            sink.accept(new Sample(end, entry.getKey(), counts.lastIp, counts.toFeatures()));
        }
        current.clear();
        currentWindow = Long.MIN_VALUE;
    }

    private static void count(Counts counts, Packet packet) {
        counts.packets++;

        IpV4Packet ip = packet.get(IpV4Packet.class);
        if (ip != null) {
            counts.lastIp = ip.getHeader().getSrcAddr().getHostAddress();
            if (counts.destinations.size() < MAX_ADDRESSES_PER_SENDER) {
                counts.destinations.add(ip.getHeader().getDstAddr().getHostAddress());
            }
        }

        ArpPacket arp = packet.get(ArpPacket.class);
        if (arp != null) {
            ArpOperation operation = arp.getHeader().getOperation();
            if (ArpOperation.REQUEST.equals(operation)) {
                counts.arpRequests++;
            } else if (ArpOperation.REPLY.equals(operation)) {
                counts.arpReplies++;
            }
            String senderIp = arp.getHeader().getSrcProtocolAddr().getHostAddress();
            if (counts.arpSenderIps.size() < MAX_ADDRESSES_PER_SENDER) {
                counts.arpSenderIps.add(senderIp);
            }
            if (!"0.0.0.0".equals(senderIp)) {
                counts.lastIp = senderIp;
            }
        }

        UdpPacket udp = packet.get(UdpPacket.class);
        if (udp != null) {
            int srcPort = udp.getHeader().getSrcPort().value() & 0xFFFF;
            if (srcPort == 53) {
                counts.dnsResponses++;
            } else if (srcPort == 67) {
                counts.dhcpReplies++;
            }
        }

        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp != null && tcp.getPayload() != null
                && (tcp.getHeader().getSrcPort().value() & 0xFFFF) == 80) {
            counts.httpResponses++;
        }
    }
}
