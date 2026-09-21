package ro.upb.mitmdetector.detector;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/** Builds Ethernet/IPv4/TCP frames carrying HTTP text for tests. */
final class HttpTestPackets {

    private HttpTestPackets() { }

    /** A plain HTTP GET from the client towards a server (through the gateway MAC). */
    static Packet get(String clientMac, String gatewayMac, String clientIp, String serverIp,
                      int clientPort, String host, String path) {
        String text = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: test\r\n\r\n";
        return tcp(clientMac, gatewayMac, clientIp, serverIp, clientPort, 80, bytes(text));
    }

    /** A redirect (301, 302, ...) with the given Location. */
    static Packet redirect(String responderMac, String clientMac, String serverIp, String clientIp,
                           int clientPort, int status, String location) {
        String text = "HTTP/1.1 " + status + " Moved\r\nLocation: " + location
                + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        return tcp(responderMac, clientMac, serverIp, clientIp, 80, clientPort, bytes(text));
    }

    /** A 200 response with the given content type and a short body. */
    static Packet ok(String responderMac, String clientMac, String serverIp, String clientIp,
                     int clientPort, String contentType) {
        String body = "<html><body>hello</body></html>";
        String text = "HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\nContent-Length: " + body.length()
                + "\r\n\r\n" + body;
        return tcp(responderMac, clientMac, serverIp, clientIp, 80, clientPort, bytes(text));
    }

    /** Any TCP segment with the given payload. */
    static Packet tcp(String srcMac, String dstMac, String srcIp, String dstIp,
                      int srcPort, int dstPort, byte[] payload) {
        int tcpLength = 20 + payload.length;
        ByteBuffer frame = ByteBuffer.allocate(14 + 20 + tcpLength);
        frame.put(mac(dstMac)).put(mac(srcMac)).putShort((short) 0x0800);          // Ethernet, type IPv4
        frame.put((byte) 0x45).put((byte) 0).putShort((short) (20 + tcpLength));    // IPv4: version/IHL, TOS, length
        frame.putShort((short) 0).putShort((short) 0x4000);                         // identification, don't fragment
        frame.put((byte) 64).put((byte) 6).putShort((short) 0);                     // TTL, protocol TCP, checksum
        frame.put(ip(srcIp)).put(ip(dstIp));
        frame.putShort((short) srcPort).putShort((short) dstPort);                  // TCP header
        frame.putInt(1).putInt(1);                                                  // sequence, acknowledgement
        frame.put((byte) 0x50).put((byte) 0x18);                                    // data offset 5, flags PSH+ACK
        frame.putShort((short) 65535).putShort((short) 0).putShort((short) 0);      // window, checksum, urgent
        frame.put(payload);
        try {
            return EthernetPacket.newPacket(frame.array(), 0, frame.capacity());
        } catch (IllegalRawDataException e) {
            throw new IllegalStateException("Test frame is not valid", e);
        }
    }

    static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.ISO_8859_1);
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
