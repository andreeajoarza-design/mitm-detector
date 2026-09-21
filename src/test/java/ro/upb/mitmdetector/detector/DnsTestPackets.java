package ro.upb.mitmdetector.detector;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Builds Ethernet/IPv4/UDP/DNS frames byte by byte for tests, without touching the network.
 * The frame is then decoded by Pcap4J exactly as a captured one would be.
 */
public final class DnsTestPackets {

    private DnsTestPackets() { }

    /** Client asks the resolver "what is the address of name?". */
    static Packet query(String clientMac, String clientIp, String resolverMac, String resolverIp,
                        int id, String name) {
        return udp(clientMac, resolverMac, clientIp, resolverIp, clientPort(id), 53, dnsQuery(id, name));
    }

    /** Resolver (or someone pretending to be it) answers with the given addresses. */
    static Packet response(String responderMac, String responderIp, String clientMac, String clientIp,
                           int id, String name, String... addresses) {
        return udp(responderMac, clientMac, responderIp, clientIp, 53, clientPort(id),
                dnsResponse(id, name, addresses));
    }

    /** Any UDP datagram with the given payload. */
    public static Packet udp(String srcMac, String dstMac, String srcIp, String dstIp,
                      int srcPort, int dstPort, byte[] payload) {
        int udpLength = 8 + payload.length;
        ByteBuffer frame = ByteBuffer.allocate(14 + 20 + udpLength);
        frame.put(mac(dstMac)).put(mac(srcMac)).putShort((short) 0x0800);          // Ethernet, type IPv4
        frame.put((byte) 0x45).put((byte) 0).putShort((short) (20 + udpLength));    // IPv4: version/IHL, TOS, length
        frame.putShort((short) 0).putShort((short) 0);                              // identification, flags/fragment
        frame.put((byte) 64).put((byte) 17).putShort((short) 0);                    // TTL, protocol UDP, checksum
        frame.put(ip(srcIp)).put(ip(dstIp));
        frame.putShort((short) srcPort).putShort((short) dstPort)                   // UDP header
                .putShort((short) udpLength).putShort((short) 0);
        frame.put(payload);
        try {
            return EthernetPacket.newPacket(frame.array(), 0, frame.capacity());
        } catch (IllegalRawDataException e) {
            throw new IllegalStateException("Test frame is not valid", e);
        }
    }

    static byte[] dnsQuery(int id, String name) {
        ByteBuffer message = ByteBuffer.allocate(12 + name.length() + 6);
        message.putShort((short) id).putShort((short) 0x0100)     // standard query, recursion desired
                .putShort((short) 1).putShort((short) 0).putShort((short) 0).putShort((short) 0);
        putName(message, name);
        message.putShort((short) 1).putShort((short) 1);          // type A, class IN
        return trim(message);
    }

    static byte[] dnsResponse(int id, String name, String... addresses) {
        ByteBuffer message = ByteBuffer.allocate(12 + name.length() + 6 + addresses.length * 16);
        message.putShort((short) id).putShort((short) 0x8180)     // response, recursion desired and available
                .putShort((short) 1).putShort((short) addresses.length).putShort((short) 0).putShort((short) 0);
        putName(message, name);
        message.putShort((short) 1).putShort((short) 1);
        for (String address : addresses) {
            message.putShort((short) 0xC00C)                      // name: pointer to the question at offset 12
                    .putShort((short) 1).putShort((short) 1)      // type A, class IN
                    .putInt(300)                                  // TTL
                    .putShort((short) 4).put(ip(address));
        }
        return trim(message);
    }

    private static void putName(ByteBuffer message, String name) {
        for (String label : name.split("\\.")) {
            byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
            message.put((byte) bytes.length).put(bytes);
        }
        message.put((byte) 0);
    }

    private static byte[] trim(ByteBuffer message) {
        byte[] result = new byte[message.position()];
        message.flip();
        message.get(result);
        return result;
    }

    private static int clientPort(int id) {
        return 40000 + (id & 0x0FFF);
    }

    private static byte[] mac(String text) {
        byte[] bytes = new byte[6];
        String[] parts = text.split(":");
        for (int i = 0; i < 6; i++) {
            bytes[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return bytes;
    }

    private static byte[] ip(String text) {
        byte[] bytes = new byte[4];
        String[] parts = text.split("\\.");
        for (int i = 0; i < 4; i++) {
            bytes[i] = (byte) Integer.parseInt(parts[i]);
        }
        return bytes;
    }
}
