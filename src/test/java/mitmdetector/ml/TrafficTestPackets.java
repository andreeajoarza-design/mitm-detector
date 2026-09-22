package mitmdetector.ml;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import mitmdetector.detector.DnsTestPackets;
import mitmdetector.detector.HttpTestPackets;

import java.nio.ByteBuffer;

/** Frames for the traffic-window tests. UDP and TCP frames come from the DNS and HTTP test helpers. */
final class TrafficTestPackets {

    static final String BROADCAST_MAC = "ff:ff:ff:ff:ff:ff";
    private static final byte[] EMPTY = new byte[0];

    private TrafficTestPackets() { }

    /** An ARP request from the sender asking who has targetIp. */
    static Packet arpRequest(String senderMac, String senderIp, String targetIp) {
        return arp(1, senderMac, BROADCAST_MAC, senderIp, "00:00:00:00:00:00", targetIp);
    }

    /** An ARP reply in which senderMac says it has senderIp. */
    static Packet arpReply(String senderMac, String senderIp, String targetMac, String targetIp) {
        return arp(2, senderMac, targetMac, senderIp, targetMac, targetIp);
    }

    /** A UDP packet with a payload of the given size, from srcPort to dstPort. */
    static Packet udp(String srcMac, String dstMac, String srcIp, String dstIp, int srcPort, int dstPort) {
        return DnsTestPackets.udp(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort, new byte[]{1, 2, 3, 4});
    }

    /** A TCP segment with data, from srcPort to dstPort. */
    static Packet tcp(String srcMac, String dstMac, String srcIp, String dstIp, int srcPort, int dstPort) {
        return HttpTestPackets.tcp(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort, new byte[]{1, 2, 3, 4});
    }

    /** A TCP segment without data (a bare acknowledgement). */
    static Packet tcpWithoutData(String srcMac, String dstMac, String srcIp, String dstIp, int srcPort, int dstPort) {
        return HttpTestPackets.tcp(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort, EMPTY);
    }

    private static Packet arp(int operation, String senderMac, String dstMac, String senderIp,
                              String targetMac, String targetIp) {
        ByteBuffer frame = ByteBuffer.allocate(42);
        frame.put(mac(dstMac)).put(mac(senderMac)).putShort((short) 0x0806);   // Ethernet, type ARP
        frame.putShort((short) 1).putShort((short) 0x0800).put((byte) 6).put((byte) 4)
                .putShort((short) operation);
        frame.put(mac(senderMac)).put(ip(senderIp)).put(mac(targetMac)).put(ip(targetIp));
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
