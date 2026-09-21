package ro.upb.mitmdetector.detector;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import ro.upb.mitmdetector.alert.Alert;
import ro.upb.mitmdetector.alert.AlertManager;
import ro.upb.mitmdetector.alert.AlertType;
import ro.upb.mitmdetector.alert.Severity;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Detects SSL stripping on a local network (IPv4, plain HTTP on TCP port 80).
 *
 * <p>In an SSL stripping attack the attacker sits between the victim and a website. The victim
 * asks for the site over plain HTTP, the attacker fetches the real page over HTTPS and hands it to the
 * victim over plain HTTP, with the https:// links rewritten. The victim never gets to HTTPS, and the
 * attacker reads everything. The site itself, on the other hand, sends anyone who asks over plain HTTP
 * to HTTPS with a redirect. The detector learns which hosts do that and reports two departures from it:
 * <ol>
 *   <li><b>Page instead of redirect.</b> A host that redirected to HTTPS earlier answers a plain HTTP
 *       request with an HTML page (2xx). Only text/html counts, because images or API calls served over
 *       HTTP by an otherwise HTTPS site are common and harmless. ACME challenge paths
 *       (/.well-known/acme-challenge/) are skipped, since certificate authorities fetch them over HTTP.</li>
 *   <li><b>Redirect to HTTP.</b> A host known to use HTTPS answers with a redirect whose Location
 *       is an http:// URL of the same site (the site itself or its www variant).</li>
 * </ol>
 * The severity is CRITICAL if the reply comes from a different MAC address than the earlier redirect
 * (someone else is answering for the site) and HIGH otherwise.
 *
 * <p>A host is learned as HTTPS-only from a 301, 302, 303, 307 or 308 response to a plain HTTP request
 * whose Location is an https:// URL of the same site. Nothing else is learned, so a page or a redirect
 * that raised an alert never becomes the normal behaviour of that host. A list of known HTTPS-only
 * hosts can also be given at construction, which removes the cold start for those hosts.
 *
 * <p>Known limitations: a host never seen redirecting (and not on the list) is not protected (cold start);
 * sites on the browsers' HSTS preload list are never requested over plain HTTP, so there is nothing to
 * see for them; requests are matched to responses by connection using only the first TCP segment
 * of each, with no stream reassembly; HTTPS traffic (port 443), IPv6 and other ports are not inspected.
 *
 * <p>Thread safety: {@link #inspect} is synchronized.
 */
public final class HttpDetector implements Detector {

    /** How long a request waits for its response. */
    public static final Duration REQUEST_TTL = Duration.ofSeconds(30);

    private static final int HTTP_PORT = 80;
    private static final int MAX_HOSTS = 10_000;
    private static final int MAX_PENDING_REQUESTS = 10_000;
    private static final String ACME_PREFIX = "/.well-known/acme-challenge/";

    /** One client connection to one server. */
    private record Flow(String clientIp, int clientPort, String serverIp) { }

    private record PendingRequest(String host, String path, Instant time) { }

    /** What is known about a host that uses HTTPS. The MAC and time are null for listed hosts. */
    private record HttpsHost(String responderMac, Instant learnedAt) {
        String describe() {
            return learnedAt == null ? "it is on the list of HTTPS-only hosts"
                    : "it redirected to HTTPS at " + learnedAt;
        }
    }

    private final AlertManager alerts;
    /** Oldest request first: expiry only needs to look at the front. */
    private final Map<Flow, PendingRequest> pending = new LinkedHashMap<>();
    /** Least recently used hosts are dropped first, so memory stays bounded. */
    private final Map<String, HttpsHost> httpsHosts = new LinkedHashMap<>(256, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, HttpsHost> eldest) {
            return size() > MAX_HOSTS;
        }
    };

    public HttpDetector(AlertManager alerts) {
        this(alerts, Set.of());
    }

    /** @param knownHttpsHosts host names that are known to require HTTPS, for example "bank.example" */
    public HttpDetector(AlertManager alerts, Set<String> knownHttpsHosts) {
        this.alerts = alerts;
        for (String name : new HashSet<>(knownHttpsHosts)) {
            String host = HttpMessage.normalizeHost(name);
            if (host != null) {
                httpsHosts.put(host, new HttpsHost(null, null));
            }
        }
    }

    @Override
    public synchronized void inspect(Packet packet, Instant timestamp) {
        EthernetPacket ethernet = packet.get(EthernetPacket.class);
        IpV4Packet ip = packet.get(IpV4Packet.class);
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (ethernet == null || ip == null || tcp == null || tcp.getPayload() == null) {
            return;
        }
        byte[] payload = tcp.getPayload().getRawData();
        if (payload == null || payload.length == 0) {
            return;
        }

        int srcPort = tcp.getHeader().getSrcPort().value() & 0xFFFF;
        int dstPort = tcp.getHeader().getDstPort().value() & 0xFFFF;
        if (srcPort != HTTP_PORT && dstPort != HTTP_PORT) {
            return;
        }
        HttpMessage message = HttpMessage.parse(payload).orElse(null);
        if (message == null) {
            return;
        }

        String srcIp = ip.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ip.getHeader().getDstAddr().getHostAddress();
        String srcMac = ethernet.getHeader().getSrcAddr().toString();
        expire(timestamp);

        if (message.request() && dstPort == HTTP_PORT) {
            rememberRequest(message, srcIp, srcPort, dstIp, timestamp);
        } else if (!message.request() && srcPort == HTTP_PORT) {
            handleResponse(message, srcIp, dstIp, dstPort, srcMac, timestamp);
        }
    }

    private void rememberRequest(HttpMessage message, String clientIp, int clientPort, String serverIp, Instant ts) {
        if (message.host() == null) {
            return;   // HTTP/1.0 without Host: nothing to match a host against
        }
        Flow flow = new Flow(clientIp, clientPort, serverIp);
        pending.remove(flow);   // a new request on the same connection replaces the old one and goes to the back
        pending.put(flow, new PendingRequest(message.host(), path(message.target()), ts));
        if (pending.size() > MAX_PENDING_REQUESTS) {
            pending.remove(pending.keySet().iterator().next());
        }
    }

    private void handleResponse(HttpMessage message, String serverIp, String clientIp, int clientPort,
                                String serverMac, Instant ts) {
        PendingRequest request = pending.remove(new Flow(clientIp, clientPort, serverIp));
        if (request == null) {
            return;
        }
        String host = request.host();
        HttpsHost known = httpsHosts.get(host);

        if (message.isRedirect()) {
            String scheme = message.locationScheme();
            boolean sameSite = sameSite(host, message.locationHost());
            if ("https".equals(scheme) && sameSite) {
                if (known == null) {
                    httpsHosts.put(host, new HttpsHost(serverMac, ts));
                }
            } else if ("http".equals(scheme) && sameSite && known != null) {
                raise(AlertType.HTTP_DOWNGRADE_REDIRECT, known, serverIp, serverMac, ts,
                        "%s is known to use HTTPS (%s), but a plain HTTP request for it was answered with a redirect to %s"
                                .formatted(host, known.describe(), message.location()));
            }
        } else if (message.isSuccess() && message.isHtml() && known != null
                && !request.path().startsWith(ACME_PREFIX)) {
            raise(AlertType.HTTP_DOWNGRADE_PAGE, known, serverIp, serverMac, ts,
                    "%s is known to use HTTPS (%s), but a plain HTTP request for %s was answered with an HTML page (status %d). This is what SSL stripping looks like"
                            .formatted(host, known.describe(), request.path(), message.status()));
        }
    }

    private void raise(AlertType type, HttpsHost known, String serverIp, String serverMac, Instant ts, String text) {
        boolean otherResponder = known.responderMac() != null && !known.responderMac().equals(serverMac);
        Severity severity = otherResponder ? Severity.CRITICAL : Severity.HIGH;
        String message = otherResponder
                ? text + "; the reply comes from MAC %s, the earlier redirect came from MAC %s"
                        .formatted(serverMac, known.responderMac())
                : text;
        alerts.raise(new Alert(ts, type, severity, message, serverIp, serverMac));
    }

    /** True if both names are the same site: equal, or one is the other with a "www." prefix. */
    private static boolean sameSite(String host, String other) {
        return other != null && (host.equals(other) || other.equals("www." + host) || host.equals("www." + other));
    }

    /** The request target without the query string. */
    private static String path(String target) {
        int query = target.indexOf('?');
        return query >= 0 ? target.substring(0, query) : target;
    }

    private void expire(Instant now) {
        Iterator<PendingRequest> it = pending.values().iterator();
        while (it.hasNext() && Duration.between(it.next().time(), now).compareTo(REQUEST_TTL) > 0) {
            it.remove();
        }
    }
}
