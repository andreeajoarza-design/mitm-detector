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
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Detects DNS spoofing on a local network (IPv4, DNS over UDP port 53).
 *
 * <p>A DNS spoofer sees the victim's query and races a forged response to it. The forged response
 * must carry the same transaction id and port, so it looks valid, and it usually points the name
 * to the attacker's own machine. Three checks:
 * <ol>
 *   <li><b>Conflicting responses.</b> A query gets one answer from the resolver. If a second response
 *       with the same client, transaction id and name but a different set of addresses arrives within
 *       {@link #RESPONSE_WINDOW}, one of the two is forged. It is CRITICAL when the two come from different
 *       MAC addresses (a second machine is answering for the resolver), HIGH otherwise.</li>
 *   <li><b>Unsolicited response.</b> A response for a query the client never sent, or sent more than
 *       {@link #QUERY_TTL} ago, is MEDIUM. Alerts of this kind are held back during the first
 *       {@link #QUERY_TTL} after the first DNS packet, because responses to queries sent before the
 *       capture started would look unsolicited.</li>
 *   <li><b>Private answer for a public name.</b> A name that has only ever resolved to public addresses
 *       and now resolves to a private one (10/8, 172.16/12, 192.168/16, loopback, link-local) is HIGH.
 *       Attackers on a LAN usually point the victim at a machine on that LAN. Any change between two
 *       public addresses is ignored on purpose: CDNs and load balancers rotate addresses all the time.</li>
 * </ol>
 *
 * <p>The detector only learns from responses it has no reason to doubt: an answer is added to the
 * history {@link #RESPONSE_WINDOW} after it arrived, and only if it was solicited and no second
 * conflicting response showed up. Otherwise a forged answer would become the "normal" one.
 *
 * <p>Known limitations: no baseline exists for a name seen for the first time (cold start); answers
 * over TCP, DNS over TLS/HTTPS and IPv6 are not inspected; only A records are compared.
 *
 * <p>Thread safety: {@link #inspect} is synchronized.
 */
public final class DnsDetector implements Detector {

    /** How long a query stays valid as the "question" for a response. */
    public static final Duration QUERY_TTL = Duration.ofSeconds(10);
    /** How long the first response is kept to compare a later one against it. */
    public static final Duration RESPONSE_WINDOW = Duration.ofSeconds(5);

    private static final int DNS_PORT = 53;
    private static final int MAX_HISTORY_NAMES = 10_000;
    private static final int MAX_ADDRESSES_PER_NAME = 64;

    /** Identifies one query/response exchange from the client's point of view. */
    private record QueryKey(String clientIp, int id, String qname) { }

    /** The first response seen for an exchange. */
    private static final class SeenResponse {
        final Set<String> answers;
        final String responderIp;
        final String responderMac;
        final Instant time;
        final boolean solicited;
        boolean suspicious;

        SeenResponse(Set<String> answers, String responderIp, String responderMac, Instant time,
                     boolean solicited, boolean suspicious) {
            this.answers = answers;
            this.responderIp = responderIp;
            this.responderMac = responderMac;
            this.time = time;
            this.solicited = solicited;
            this.suspicious = suspicious;
        }
    }

    private final AlertManager alerts;
    private final Map<QueryKey, Instant> pendingQueries = new HashMap<>();
    private final Map<QueryKey, SeenResponse> responses = new HashMap<>();
    /** Least recently used names are dropped first, so memory stays bounded. */
    private final Map<String, Set<String>> history = new LinkedHashMap<>(256, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Set<String>> eldest) {
            return size() > MAX_HISTORY_NAMES;
        }
    };
    private Instant firstSeen;

    public DnsDetector(AlertManager alerts) {
        this.alerts = alerts;
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
        if (srcPort != DNS_PORT && dstPort != DNS_PORT) {
            return;
        }
        DnsMessage message = DnsMessage.parse(udp.getPayload().getRawData()).orElse(null);
        if (message == null) {
            return;
        }

        String srcIp = ip.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ip.getHeader().getDstAddr().getHostAddress();
        String srcMac = ethernet.getHeader().getSrcAddr().toString();

        if (firstSeen == null) {
            firstSeen = timestamp;
        }
        expire(timestamp);

        if (!message.response() && dstPort == DNS_PORT) {
            pendingQueries.put(new QueryKey(srcIp, message.id(), message.qname()), timestamp);
        } else if (message.response() && srcPort == DNS_PORT) {
            handleResponse(message, srcIp, dstIp, srcMac, timestamp);
        }
    }

    private void handleResponse(DnsMessage message, String responderIp, String clientIp,
                                String responderMac, Instant ts) {
        QueryKey key = new QueryKey(clientIp, message.id(), message.qname());
        Set<String> answers = message.ipv4Answers();
        boolean solicited = pendingQueries.containsKey(key);
        boolean suspicious = !solicited;

        if (!solicited && Duration.between(firstSeen, ts).compareTo(QUERY_TTL) >= 0) {
            alerts.raise(new Alert(ts, AlertType.DNS_UNSOLICITED_RESPONSE, Severity.MEDIUM,
                    "Response for %s (id 0x%04x) to %s, but no matching query was seen"
                            .formatted(message.qname(), message.id(), clientIp),
                    responderIp, responderMac));
        }

        suspicious |= checkPrivateAnswer(message, answers, responderIp, responderMac, ts);

        SeenResponse prior = responses.get(key);
        if (prior == null) {
            responses.put(key, new SeenResponse(answers, responderIp, responderMac, ts, solicited, suspicious));
        } else if (!prior.answers.equals(answers)) {
            prior.suspicious = true;
            // DNS alone cannot tell which of the two is forged. Spoofing tools race to answer first,
            // so the alert points at the first responder and the message lists both.
            Severity severity = prior.responderMac.equals(responderMac) ? Severity.HIGH : Severity.CRITICAL;
            alerts.raise(new Alert(ts, AlertType.DNS_CONFLICTING_RESPONSES, severity,
                    "Two different answers for %s (id 0x%04x) to %s: %s from MAC %s, then %s from MAC %s. One is forged."
                            .formatted(message.qname(), message.id(), clientIp,
                                    prior.answers, prior.responderMac, answers, responderMac),
                    prior.responderIp, prior.responderMac));
        }
    }

    /** Returns true if an alert was raised. */
    private boolean checkPrivateAnswer(DnsMessage message, Set<String> answers, String responderIp,
                                       String responderMac, Instant ts) {
        Set<String> known = history.get(message.qname());
        if (known == null || known.isEmpty() || answers.isEmpty()) {
            return false;
        }
        if (known.stream().anyMatch(DnsDetector::isPrivate)) {
            return false; // an internal name, private addresses are normal for it
        }
        List<String> newPrivate = answers.stream()
                .filter(a -> isPrivate(a) && !known.contains(a))
                .sorted()
                .toList();
        if (newPrivate.isEmpty()) {
            return false;
        }
        alerts.raise(new Alert(ts, AlertType.DNS_ANSWER_CHANGED, Severity.HIGH,
                "%s always resolved to public addresses %s, now it answers with private address %s"
                        .formatted(message.qname(), known, newPrivate),
                responderIp, responderMac));
        return true;
    }

    /** Drops old queries, and moves responses that stayed unchallenged into the history. */
    private void expire(Instant now) {
        pendingQueries.values().removeIf(time -> Duration.between(time, now).compareTo(QUERY_TTL) > 0);

        Iterator<Map.Entry<QueryKey, SeenResponse>> it = responses.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<QueryKey, SeenResponse> entry = it.next();
            SeenResponse response = entry.getValue();
            if (Duration.between(response.time, now).compareTo(RESPONSE_WINDOW) > 0) {
                if (response.solicited && !response.suspicious) {
                    learn(entry.getKey().qname(), response.answers);
                }
                it.remove();
            }
        }
    }

    private void learn(String qname, Set<String> answers) {
        if (answers.isEmpty()) {
            return;
        }
        Set<String> known = history.computeIfAbsent(qname, name -> new HashSet<>());
        for (String address : answers) {
            if (known.size() >= MAX_ADDRESSES_PER_NAME) {
                break;
            }
            known.add(address);
        }
    }

    /** RFC 1918 ranges, loopback, link-local and 0.0.0.0/8. Input is always dotted decimal. */
    static boolean isPrivate(String address) {
        String[] parts = address.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        int a = Integer.parseInt(parts[0]);
        int b = Integer.parseInt(parts[1]);
        return a == 10
                || a == 127
                || a == 0
                || (a == 172 && b >= 16 && b <= 31)
                || (a == 192 && b == 168)
                || (a == 169 && b == 254);
    }
}
