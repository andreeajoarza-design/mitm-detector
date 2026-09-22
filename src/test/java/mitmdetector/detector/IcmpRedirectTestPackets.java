package mitmdetector.detector;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

import java.nio.ByteBuffer;

/**
 * Builds Ethernet/IPv4/ICMP Redirect frames byte by byte for tests, without touching the network.
 * The IPv4 and ICMP checksums are left at zero, same as {@link DnsTestPackets}: Pcap4J does not
 * validate them while parsing, and the detectors never look at them either.
 */
final class IcmpRedirectTestPackets {

    /** ICMP Redirect, code 1: "redirect datagrams for the host". */
    private static final byte REDIRECT_FOR_HOST = 1;

    private IcmpRedirectTestPackets() { }

    /** senderMac/senderIp tells victimMac/victimIp to use newGatewayIp as gateway from now on. */
    static Packet redirect(String senderMac, String senderIp, String victimMac, String victimIp,
                           String newGatewayIp) {
        ByteBuffer frame = ByteBuffer.allocate(14 + 20 + 8);
        frame.put(mac(victimMac)).put(mac(senderMac)).putShort((short) 0x0800);  // Ethernet, type IPv4
        frame.put((byte) 0x45).put((byte) 0).putShort((short) (20 + 8));         // IPv4: version/IHL, TOS, length
        frame.putShort((short) 0).putShort((short) 0);                           // identification, flags/fragment
        frame.put((byte) 64).put((byte) 1).putShort((short) 0);                  // TTL, protocol ICMP, checksum
        frame.put(ip(senderIp)).put(ip(victimIp));
        frame.put((byte) 5).put(REDIRECT_FOR_HOST).putShort((short) 0);          // type=REDIRECT, code, checksum
        frame.put(ip(newGatewayIp));                                             // gateway address
        try {
            return EthernetPacket.newPacket(frame.array(), 0, frame.capacity());
        } catch (IllegalRawDataException e) {
            throw new IllegalStateException("Test frame is not valid", e);
        }
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
