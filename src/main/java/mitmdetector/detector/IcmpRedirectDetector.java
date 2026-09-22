package mitmdetector.detector;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4RedirectPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.util.MacAddress;
import mitmdetector.alert.Alert;
import mitmdetector.alert.AlertManager;
import mitmdetector.alert.AlertType;
import mitmdetector.alert.Severity;

import java.time.Instant;

/**
 * Detects forged ICMP Redirect messages (ICMP type 5): a MITM technique similar in spirit to ARP
 * spoofing, but at the routing layer instead of the link layer. A router is allowed to tell a host
 * "use a different gateway for this destination"; an attacker abuses the same message to tell the
 * host "route through me instead".
 *
 * <p>Two checks:
 * <ol>
 *   <li><b>Spoofed sender.</b> The detector remembers which MAC address is bound to the known
 *       gateway IP (the first Redirect sender seen is trusted — the same cold-start assumption as
 *       {@link ArpDetector}). A later Redirect that claims to come from that same gateway IP but a
 *       different Ethernet MAC is forged: CRITICAL.</li>
 *   <li><b>Untrusted sender.</b> A host that is not the known gateway sends a Redirect at all. It is
 *       CRITICAL when the new gateway it names is itself (the classic "route through me" MITM
 *       pattern), HIGH when it names some other address (still not a legitimate router message, just
 *       less conclusively an attack on its own).</li>
 * </ol>
 *
 * <p>Known limitation: same cold start as the other detectors — the first Redirect sender is trusted
 * as the real gateway, so an attack already running when the detector starts is not caught by check 1.
 *
 * <p>Thread safety: {@link #inspect} is synchronized, the capture thread is the only caller in practice.
 */
public final class IcmpRedirectDetector implements Detector {

    private final AlertManager alerts;
    private String knownGatewayIp;
    private MacAddress knownGatewayMac;

    public IcmpRedirectDetector(AlertManager alerts) {
        this.alerts = alerts;
    }

    @Override
    public synchronized void inspect(Packet packet, Instant timestamp) {
        EthernetPacket ethernet = packet.get(EthernetPacket.class);
        IpV4Packet ip = packet.get(IpV4Packet.class);
        IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
        if (ethernet == null || ip == null || icmp == null
                || !IcmpV4Type.REDIRECT.equals(icmp.getHeader().getType())) {
            return;
        }
        IcmpV4RedirectPacket redirect = packet.get(IcmpV4RedirectPacket.class);
        if (redirect == null) {
            return;
        }

        String senderIp = ip.getHeader().getSrcAddr().getHostAddress();
        MacAddress senderMac = ethernet.getHeader().getSrcAddr();
        String newGatewayIp = redirect.getHeader().getGatewayInternetAddress().getHostAddress();

        if (knownGatewayIp == null) {
            knownGatewayIp = senderIp;
            knownGatewayMac = senderMac;
            return;
        }

        if (senderIp.equals(knownGatewayIp)) {
            checkSpoofedSender(timestamp, senderIp, senderMac);
            return;
        }

        checkUntrustedSender(timestamp, senderIp, senderMac, newGatewayIp);
    }

    private void checkSpoofedSender(Instant ts, String senderIp, MacAddress senderMac) {
        if (senderMac.equals(knownGatewayMac)) {
            return;
        }
        alerts.raise(new Alert(ts, AlertType.ICMP_REDIRECT_SPOOFED_SENDER, Severity.CRITICAL,
                "ICMP Redirect claims to be from the known gateway %s, but arrived from MAC %s instead of %s"
                        .formatted(senderIp, senderMac, knownGatewayMac),
                senderIp, senderMac.toString()));
    }

    private void checkUntrustedSender(Instant ts, String senderIp, MacAddress senderMac, String newGatewayIp) {
        boolean toSelf = newGatewayIp.equals(senderIp);
        Severity severity = toSelf ? Severity.CRITICAL : Severity.HIGH;
        String detail = toSelf
                ? "names itself as the new gateway"
                : "names %s as the new gateway".formatted(newGatewayIp);
        alerts.raise(new Alert(ts, AlertType.ICMP_REDIRECT_UNTRUSTED_SENDER, severity,
                "Host %s, not the known gateway %s, sent an ICMP Redirect and %s"
                        .formatted(senderIp, knownGatewayIp, detail),
                senderIp, senderMac.toString()));
    }
}
