package ro.upb.mitmdetector.detector;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DhcpMessageTest {

    private static final String CLIENT = "bb:bb:bb:bb:bb:10";
    private static final String[] NONE = new String[0];

    @Test
    void parsesOfferWithRouterAndDns() {
        byte[] data = DhcpTestPackets.dhcp(2, 0xCAFE0001, CLIENT, DhcpTestPackets.OFFER, "192.168.1.1",
                new String[]{"192.168.1.1"}, new String[]{"192.168.1.1", "9.9.9.9"});
        DhcpMessage message = DhcpMessage.parse(data).orElseThrow();

        assertEquals(2, message.op());
        assertEquals(0xCAFE0001, message.xid());
        assertEquals(CLIENT, message.clientMac());
        assertEquals(DhcpMessage.OFFER, message.messageType());
        assertEquals(Set.of("192.168.1.1"), message.routers());
        assertEquals(Set.of("192.168.1.1", "9.9.9.9"), message.dnsServers());
        assertTrue(message.isServerReply());
        assertTrue(message.carriesConfiguration());
    }

    @Test
    void nakIsAServerReplyWithoutConfiguration() {
        DhcpMessage message = DhcpMessage.parse(
                DhcpTestPackets.dhcp(2, 1, CLIENT, DhcpTestPackets.NAK, "192.168.1.1", NONE, NONE)).orElseThrow();
        assertTrue(message.isServerReply());
        assertFalse(message.carriesConfiguration());
        assertTrue(message.routers().isEmpty());
    }

    @Test
    void discoverIsNotAServerReply() {
        DhcpMessage message = DhcpMessage.parse(
                DhcpTestPackets.dhcp(1, 1, CLIENT, DhcpTestPackets.DISCOVER, null, NONE, NONE)).orElseThrow();
        assertFalse(message.isServerReply());
    }

    @Test
    void messageWithoutMagicCookieIsRejected() {
        byte[] data = DhcpTestPackets.dhcp(2, 1, CLIENT, DhcpTestPackets.OFFER, "192.168.1.1", NONE, NONE);
        data[236] = 0;
        assertEquals(Optional.empty(), DhcpMessage.parse(data));
    }

    @Test
    void messageWithoutMessageTypeOptionIsRejected() {
        byte[] data = DhcpTestPackets.dhcp(2, 1, CLIENT, DhcpTestPackets.OFFER, "192.168.1.1", NONE, NONE);
        data[240] = 0;   // the first option (53) becomes padding
        data[241] = 0;
        data[242] = 0;
        assertEquals(Optional.empty(), DhcpMessage.parse(data));
    }

    @Test
    void truncatedOptionsAreRejected() {
        byte[] full = DhcpTestPackets.dhcp(2, 1, CLIENT, DhcpTestPackets.OFFER, "192.168.1.1",
                new String[]{"192.168.1.1"}, new String[]{"192.168.1.1"});
        // Cut in the middle of the router option (its data starts after 53, 54 and the 3/4 header).
        int routerOptionEnd = 240 + 3 + 6 + 6;
        byte[] truncated = Arrays.copyOf(full, routerOptionEnd - 2);
        assertEquals(Optional.empty(), DhcpMessage.parse(truncated));
    }

    @Test
    void routerOptionWithOddLengthIsRejected() {
        byte[] data = DhcpTestPackets.dhcp(2, 1, CLIENT, DhcpTestPackets.OFFER, null,
                new String[]{"192.168.1.1"}, NONE);
        // Options start at 240: 53,1,type (3 bytes), then 3,4,...: make the router length 3.
        data[240 + 3 + 1] = 3;
        assertEquals(Optional.empty(), DhcpMessage.parse(data));
    }

    @Test
    void shortOrNullInputIsRejected() {
        assertEquals(Optional.empty(), DhcpMessage.parse(null));
        assertEquals(Optional.empty(), DhcpMessage.parse(new byte[100]));
    }
}
