package ro.upb.mitmdetector.detector;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;

/** Builds ARP packets for tests without touching the network. */
final class ArpTestPackets {

    static final MacAddress BROADCAST = MacAddress.ETHER_BROADCAST_ADDRESS;

    private ArpTestPackets() { }

    /** "Who has targetIp? Tell senderIp." */
    static Packet request(String senderMac, String senderIp, String targetIp) {
        return build(ArpOperation.REQUEST, mac(senderMac), mac(senderMac), BROADCAST,
                MacAddress.getByName("00:00:00:00:00:00"), senderIp, targetIp);
    }

    /** "senderIp is at senderMac", sent to targetMac/targetIp. */
    static Packet reply(String senderMac, String senderIp, String targetMac, String targetIp) {
        return build(ArpOperation.REPLY, mac(senderMac), mac(senderMac), mac(targetMac),
                mac(targetMac), senderIp, targetIp);
    }

    /** Reply whose Ethernet source differs from the sender MAC in the ARP payload. */
    static Packet replyWithSpoofedEthernetSource(String ethernetSource, String arpSenderMac,
                                                 String senderIp, String targetMac, String targetIp) {
        return build(ArpOperation.REPLY, mac(ethernetSource), mac(arpSenderMac), mac(targetMac),
                mac(targetMac), senderIp, targetIp);
    }

    private static Packet build(ArpOperation op, MacAddress ethSrc, MacAddress arpSrcMac, MacAddress ethDst,
                                MacAddress arpDstMac, String senderIp, String targetIp) {
        ArpPacket.Builder arp = new ArpPacket.Builder();
        arp.hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .operation(op)
                .srcHardwareAddr(arpSrcMac)
                .srcProtocolAddr(inet(senderIp))
                .dstHardwareAddr(arpDstMac)
                .dstProtocolAddr(inet(targetIp));

        EthernetPacket.Builder eth = new EthernetPacket.Builder();
        eth.dstAddr(ethDst)
                .srcAddr(ethSrc)
                .type(EtherType.ARP)
                .payloadBuilder(arp)
                .paddingAtBuild(true);
        return eth.build();
    }

    private static MacAddress mac(String text) {
        return MacAddress.getByName(text);
    }

    private static InetAddress inet(String text) {
        try {
            return InetAddress.getByName(text);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(text, e);
        }
    }
}
