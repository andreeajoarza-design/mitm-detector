package ro.upb.mitmdetector.detector;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * The parts of a DNS message the detector needs: transaction id, direction, the question name
 * and the IPv4 addresses from the answer section.
 *
 * <p>The message is parsed by hand from the raw UDP payload (RFC 1035). This keeps the detector
 * independent of how a given Pcap4J version decodes DNS, and every malformed input simply gives
 * {@link Optional#empty()} instead of an exception.
 *
 * @param id           16-bit transaction id chosen by the client
 * @param response     true for a response, false for a query
 * @param rcode        response code (0 = no error, 3 = name does not exist)
 * @param qname        name in the question, lower case, without the trailing dot
 * @param qtype        record type asked for (1 = A)
 * @param ipv4Answers  addresses from the A records of the answer section, dotted decimal
 */
record DnsMessage(int id, boolean response, int rcode, String qname, int qtype, Set<String> ipv4Answers) {

    private static final int HEADER_LENGTH = 12;
    private static final int TYPE_A = 1;
    private static final int CLASS_IN = 1;
    private static final int MAX_POINTER_JUMPS = 16;
    private static final int MAX_NAME_LENGTH = 255;

    /** A name read from the message and the offset of the first byte after it. */
    private record Name(String text, int next) { }

    /**
     * Parses one DNS message.
     *
     * @return the message, or empty if it is malformed or not a standard query/response
     *         (only messages with opcode 0 and exactly one question are accepted)
     */
    static Optional<DnsMessage> parse(byte[] data) {
        if (data == null || data.length < HEADER_LENGTH) {
            return Optional.empty();
        }
        int id = u16(data, 0);
        int flags = u16(data, 2);
        int opcode = (flags >> 11) & 0xF;
        int questionCount = u16(data, 4);
        int answerCount = u16(data, 6);
        if (opcode != 0 || questionCount != 1) {
            return Optional.empty();
        }

        Name question = readName(data, HEADER_LENGTH);
        if (question == null || question.next() + 4 > data.length) {
            return Optional.empty();
        }
        int qtype = u16(data, question.next());
        int pos = question.next() + 4;

        Set<String> addresses = new LinkedHashSet<>();
        for (int i = 0; i < answerCount; i++) {
            Name owner = readName(data, pos);
            if (owner == null || owner.next() + 10 > data.length) {
                return Optional.empty();
            }
            int type = u16(data, owner.next());
            int recordClass = u16(data, owner.next() + 2);
            int rdLength = u16(data, owner.next() + 8);
            int rdata = owner.next() + 10;
            if (rdata + rdLength > data.length) {
                return Optional.empty();
            }
            if (type == TYPE_A && recordClass == CLASS_IN && rdLength == 4) {
                addresses.add((data[rdata] & 0xFF) + "." + (data[rdata + 1] & 0xFF) + "."
                        + (data[rdata + 2] & 0xFF) + "." + (data[rdata + 3] & 0xFF));
            }
            pos = rdata + rdLength;
        }

        boolean response = (flags & 0x8000) != 0;
        return Optional.of(new DnsMessage(id, response, flags & 0xF, question.text(), qtype,
                Collections.unmodifiableSet(addresses)));
    }

    /** Reads a possibly compressed name starting at {@code offset}. Returns null if malformed. */
    private static Name readName(byte[] d, int offset) {
        StringBuilder text = new StringBuilder();
        int pos = offset;
        int next = -1;      // where the caller continues: right after the first pointer, if any
        int jumps = 0;
        while (true) {
            if (pos >= d.length) {
                return null;
            }
            int length = d[pos] & 0xFF;
            if (length == 0) {
                pos++;
                break;
            }
            if ((length & 0xC0) == 0xC0) {
                if (pos + 1 >= d.length) {
                    return null;
                }
                int target = ((length & 0x3F) << 8) | (d[pos + 1] & 0xFF);
                if (next < 0) {
                    next = pos + 2;
                }
                if (++jumps > MAX_POINTER_JUMPS || target >= d.length) {
                    return null;
                }
                pos = target;
                continue;
            }
            if ((length & 0xC0) != 0 || pos + 1 + length > d.length) {
                return null;
            }
            if (text.length() > 0) {
                text.append('.');
            }
            for (int i = 0; i < length; i++) {
                text.append((char) (d[pos + 1 + i] & 0xFF));
            }
            if (text.length() > MAX_NAME_LENGTH) {
                return null;
            }
            pos += 1 + length;
        }
        return new Name(text.toString().toLowerCase(Locale.ROOT), next >= 0 ? next : pos);
    }

    private static int u16(byte[] d, int offset) {
        return ((d[offset] & 0xFF) << 8) | (d[offset + 1] & 0xFF);
    }
}
