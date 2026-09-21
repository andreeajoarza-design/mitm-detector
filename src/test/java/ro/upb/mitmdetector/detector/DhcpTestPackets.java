package ro.upb.mitmdetector.detector;

import org.pcap4j.packet.Packet;

import java.io.ByteArrayOutputStream;

/** Builds DHCP frames for tests. The UDP/IP/Ethernet wrapping is shared with the DNS tests. */
final class DhcpTestPackets {

    static final int DISCOVER = 1;
    static final int OFFER = 2;
    static final int ACK = 5;
    static final int NAK = 6;

    private static final String BROADCAST_MAC = "ff:ff:ff:ff:ff:ff";
    private static final String BROADCAST_IP = "255.255.255.255";

    private DhcpTestPackets() { }

    /** A broadcast reply from a server (OFFER, ACK or NAK). Router and DNS lists may be empty. */
    static Packet reply(String serverMac, String serverIp, int type, int xid, String clientMac,
                        String[] routers, String[] dnsServers) {
        byte[] payload = dhcp(2, xid, clientMac, type, serverIp, routers, dnsServers);
        return DnsTestPackets.udp(serverMac, BROADCAST_MAC, serverIp, BROADCAST_IP, 67, 68, payload);
    }

    /** A client's DISCOVER broadcast. */
    static Packet discover(String clientMac, int xid) {
        byte[] payload = dhcp(1, xid, clientMac, DISCOVER, null, new String[0], new String[0]);
        return DnsTestPackets.udp(clientMac, BROADCAST_MAC, "0.0.0.0", BROADCAST_IP, 68, 67, payload);
    }

    /** The bytes of a DHCP message: fixed 236-byte header, magic cookie, options. */
    static byte[] dhcp(int op, int xid, String clientMac, int type, String serverId,
                       String[] routers, String[] dnsServers) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(op);
        out.write(1);                                   // hardware type: Ethernet
        out.write(6);                                   // hardware address length
        out.write(0);                                   // hops
        out.writeBytes(new byte[]{(byte) (xid >>> 24), (byte) (xid >>> 16), (byte) (xid >>> 8), (byte) xid});
        out.writeBytes(new byte[2 + 2 + 4 + 4 + 4 + 4]); // secs, flags, ciaddr, yiaddr, siaddr, giaddr
        for (String part : clientMac.split(":")) {
            out.write(Integer.parseInt(part, 16));
        }
        out.writeBytes(new byte[10 + 64 + 128]);        // rest of chaddr, sname, file
        out.writeBytes(new byte[]{0x63, (byte) 0x82, 0x53, 0x63});   // magic cookie
        option(out, 53, new byte[]{(byte) type});
        if (serverId != null) {
            option(out, 54, address(serverId));
        }
        if (routers.length > 0) {
            option(out, 3, addresses(routers));
        }
        if (dnsServers.length > 0) {
            option(out, 6, addresses(dnsServers));
        }
        out.write(255);                                 // end
        return out.toByteArray();
    }

    private static void option(ByteArrayOutputStream out, int code, byte[] data) {
        out.write(code);
        out.write(data.length);
        out.writeBytes(data);
    }

    private static byte[] addresses(String[] list) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String item : list) {
            out.writeBytes(address(item));
        }
        return out.toByteArray();
    }

    private static byte[] address(String text) {
        String[] parts = text.split("\\.");
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            bytes[i] = (byte) Integer.parseInt(parts[i]);
        }
        return bytes;
    }
}
