package mitmdetector.detector;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;
import mitmdetector.alert.Alert;
import mitmdetector.alert.AlertManager;
import mitmdetector.alert.AlertType;
import mitmdetector.alert.Severity;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Detects ARP spoofing (ARP cache poisoning), the usual first step of a MITM attack on a LAN.
 *
 * <p>Three checks:
 * <ol>
 *   <li><b>Binding change.</b> The detector remembers which MAC first claimed each IP. If a later
 *       ARP packet claims the same IP with a different MAC, an alert is raised. It is CRITICAL when
 *       the new MAC already owns another IP (an attacker announcing the gateway's IP with its own
 *       MAC while keeping its real address), HIGH otherwise.</li>
 *   <li><b>Header mismatch.</b> The Ethernet source MAC and the sender MAC inside the ARP payload
 *       should be equal. Forged packets often get this wrong.</li>
 *   <li><b>Unsolicited replies.</b> A reply is expected only after a request. A host that sends
 *       {@value #UNSOLICITED_THRESHOLD} or more replies within {@link #UNSOLICITED_WINDOW} without a
 *       matching request looks like a poisoning tool re-announcing its forged binding.</li>
 * </ol>
 *
 * <p>Known limitation: the first binding seen for an IP is trusted (no baseline exists yet), so an
 * attack that starts before the detector does is not caught by check 1.
 *
 * <p>Thread safety: {@link #inspect} is synchronized, the capture thread is the only caller in practice.
 */
public final class ArpDetector implements Detector {

    /** How long a request stays valid as the "question" for a reply. */
    public static final Duration REQUEST_TTL = Duration.ofSeconds(5);
    /** Sliding window for counting unsolicited replies. */
    public static final Duration UNSOLICITED_WINDOW = Duration.ofSeconds(10);
    public static final int UNSOLICITED_THRESHOLD = 5;

    private static final String UNSPECIFIED_IP = "0.0.0.0"; // used by ARP probes (address conflict detection)

    /** requester asked "who has target?" */
    private record RequestKey(String requesterIp, String targetIp) { }

    private final AlertManager alerts;
    private final Map<String, MacAddress> bindings = new HashMap<>();
    private final Map<MacAddress, Set<String>> ipsByMac = new HashMap<>();
    private final Map<RequestKey, Instant> pendingRequests = new HashMap<>();
    private final Map<MacAddress, Deque<Instant>> unsolicitedReplies = new HashMap<>();
    /** When a flood alert was last raised for a MAC, so that one flood gives one alert per window. */
    private final Map<MacAddress, Instant> lastFloodAlert = new HashMap<>();

    public ArpDetector(AlertManager alerts) {
        this.alerts = alerts;
    }

    @Override
    public synchronized void inspect(Packet packet, Instant timestamp) {
        EthernetPacket ethernet = packet.get(EthernetPacket.class);
        ArpPacket arp = packet.get(ArpPacket.class);
        if (ethernet == null || arp == null) {
            return;
        }
        ArpPacket.ArpHeader header = arp.getHeader();
        if (!ArpHardwareType.ETHERNET.equals(header.getHardwareType())
                || !EtherType.IPV4.equals(header.getProtocolType())) {
            return; // only Ethernet + IPv4 ARP is relevant here
        }

        String senderIp = ip(header.getSrcProtocolAddr());
        String targetIp = ip(header.getDstProtocolAddr());
        MacAddress senderMac = header.getSrcHardwareAddr();
        MacAddress ethernetSource = ethernet.getHeader().getSrcAddr();

        checkHeaderMismatch(timestamp, senderIp, senderMac, ethernetSource);

        if (ArpOperation.REQUEST.equals(header.getOperation())) {
            pendingRequests.put(new RequestKey(senderIp, targetIp), timestamp);
        } else if (ArpOperation.REPLY.equals(header.getOperation())) {
            // In a reply the sender is the host that was asked, the target is the original requester.
            checkSolicited(timestamp, senderIp, targetIp, senderMac);
        }

        if (!UNSPECIFIED_IP.equals(senderIp)) {
            checkBinding(timestamp, senderIp, senderMac);
        }
        expireOldRequests(timestamp);
    }

    private void checkHeaderMismatch(Instant ts, String senderIp, MacAddress arpMac, MacAddress ethMac) {
        if (arpMac.equals(ethMac)) {
            return;
        }
        alerts.raise(new Alert(ts, AlertType.ARP_HEADER_MISMATCH, Severity.MEDIUM,
                "Ethernet source %s differs from ARP sender hardware address %s".formatted(ethMac, arpMac),
                senderIp, arpMac.toString()));
    }

    private void checkBinding(Instant ts, String senderIp, MacAddress senderMac) {
        MacAddress known = bindings.get(senderIp);
        if (known == null) {
            bindings.put(senderIp, senderMac);
            ipsByMac.computeIfAbsent(senderMac, m -> new HashSet<>()).add(senderIp);
            return;
        }
        if (known.equals(senderMac)) {
            return;
        }

        // Keep the original binding: if the change is an attack, the next forged packet is flagged again.
        Set<String> otherIps = ipsByMac.get(senderMac);
        boolean macAlreadyKnown = otherIps != null && !otherIps.isEmpty();
        Severity severity = macAlreadyKnown ? Severity.CRITICAL : Severity.HIGH;
        String detail = macAlreadyKnown
                ? " New MAC already owns %s, so one host now claims several addresses.".formatted(otherIps)
                : "";
        alerts.raise(new Alert(ts, AlertType.ARP_SPOOFING, severity,
                "IP %s moved from MAC %s to MAC %s.%s".formatted(senderIp, known, senderMac, detail),
                senderIp, senderMac.toString()));
    }

    private void checkSolicited(Instant ts, String replierIp, String requesterIp, MacAddress replierMac) {
        Instant asked = pendingRequests.get(new RequestKey(requesterIp, replierIp));
        boolean solicited = asked != null && Duration.between(asked, ts).compareTo(REQUEST_TTL) <= 0;
        if (solicited) {
            return;
        }

        Deque<Instant> recent = unsolicitedReplies.computeIfAbsent(replierMac, m -> new ArrayDeque<>());
        recent.addLast(ts);
        while (!recent.isEmpty() && Duration.between(recent.peekFirst(), ts).compareTo(UNSOLICITED_WINDOW) > 0) {
            recent.removeFirst();
        }
        Instant lastAlert = lastFloodAlert.get(replierMac);
        boolean alertedRecently = lastAlert != null
                && Duration.between(lastAlert, ts).compareTo(UNSOLICITED_WINDOW) < 0;
        // The alert is per sender MAC, not per announced IP: a flood that announces many addresses is one event.
        if (recent.size() >= UNSOLICITED_THRESHOLD && !alertedRecently) {
            lastFloodAlert.put(replierMac, ts);
            alerts.raise(new Alert(ts, AlertType.ARP_UNSOLICITED_FLOOD, Severity.MEDIUM,
                    "%d ARP replies without a request in %d s from this host"
                            .formatted(recent.size(), UNSOLICITED_WINDOW.toSeconds()),
                    replierIp, replierMac.toString()));
        }
    }

    private void expireOldRequests(Instant now) {
        Iterator<Map.Entry<RequestKey, Instant>> it = pendingRequests.entrySet().iterator();
        while (it.hasNext()) {
            if (Duration.between(it.next().getValue(), now).compareTo(REQUEST_TTL) > 0) {
                it.remove();
            }
        }
    }

    private static String ip(InetAddress address) {
        return address.getHostAddress();
    }
}
