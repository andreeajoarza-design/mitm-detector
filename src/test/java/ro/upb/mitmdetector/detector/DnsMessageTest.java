package ro.upb.mitmdetector.detector;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DnsMessageTest {

    @Test
    void parsesQueryAndLowerCasesName() {
        DnsMessage message = DnsMessage.parse(DnsTestPackets.dnsQuery(0x1a2b, "WWW.Example.COM")).orElseThrow();

        assertEquals(0x1a2b, message.id());
        assertFalse(message.response());
        assertEquals("www.example.com", message.qname());
        assertEquals(1, message.qtype());
        assertTrue(message.ipv4Answers().isEmpty());
    }

    @Test
    void parsesResponseWithCompressedAnswerNames() {
        byte[] data = DnsTestPackets.dnsResponse(0x0102, "example.org", "198.51.100.7", "198.51.100.8");
        DnsMessage message = DnsMessage.parse(data).orElseThrow();

        assertTrue(message.response());
        assertEquals(0, message.rcode());
        assertEquals("example.org", message.qname());
        assertEquals(Set.of("198.51.100.7", "198.51.100.8"), message.ipv4Answers());
    }

    @Test
    void responseWithoutAnswersHasEmptyAddressSet() {
        DnsMessage message = DnsMessage.parse(DnsTestPackets.dnsResponse(7, "nothing.example")).orElseThrow();
        assertTrue(message.ipv4Answers().isEmpty());
    }

    @Test
    void tooShortMessageIsRejected() {
        assertEquals(Optional.empty(), DnsMessage.parse(new byte[]{1, 2, 3, 4, 5}));
        assertEquals(Optional.empty(), DnsMessage.parse(null));
    }

    @Test
    void truncatedMessageIsRejected() {
        byte[] full = DnsTestPackets.dnsResponse(9, "example.org", "198.51.100.7");
        for (int cut = 12; cut < full.length; cut++) {
            byte[] truncated = Arrays.copyOf(full, cut);
            assertEquals(Optional.empty(), DnsMessage.parse(truncated), "cut at " + cut);
        }
    }

    @Test
    void namePointingToItselfIsRejected() {
        byte[] data = new byte[12 + 2 + 4];
        data[5] = 1;                       // one question
        data[12] = (byte) 0xC0;            // pointer to offset 12, which is this pointer
        data[13] = 12;
        assertEquals(Optional.empty(), DnsMessage.parse(data));
    }

    @Test
    void messageWithTwoQuestionsIsIgnored() {
        byte[] data = DnsTestPackets.dnsQuery(5, "example.org");
        data[5] = 2;
        assertEquals(Optional.empty(), DnsMessage.parse(data));
    }
}
