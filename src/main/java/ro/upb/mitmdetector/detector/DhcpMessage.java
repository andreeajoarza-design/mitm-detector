package ro.upb.mitmdetector.detector;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * The parts of a DHCP message the detector needs: direction, transaction id, client, message type,
 * and the gateway and DNS servers the server hands out.
 *
 * <p>Parsed by hand from the UDP payload (RFC 2131 fixed header, RFC 2132 options). Malformed input
 * gives {@link Optional#empty()} instead of an exception.
 *
 * @param op           1 = request from a client (BOOTREQUEST), 2 = reply from a server (BOOTREPLY)
 * @param xid          transaction id chosen by the client, shared by DISCOVER, OFFER, REQUEST and ACK
 * @param clientMac    hardware address of the client, lower case with colons
 * @param messageType  option 53: 1 DISCOVER, 2 OFFER, 3 REQUEST, 5 ACK, 6 NAK, ...
 * @param routers      option 3, the default gateways
 * @param dnsServers   option 6, the DNS servers
 */
record DhcpMessage(int op, int xid, String clientMac, int messageType, Set<String> routers, Set<String> dnsServers) {

    static final int OFFER = 2;
    static final int ACK = 5;
    static final int NAK = 6;

    private static final int FIXED_LENGTH = 236;
    private static final int OPTIONS_START = 240;
    private static final int OPTION_PAD = 0;
    private static final int OPTION_ROUTER = 3;
    private static final int OPTION_DNS = 6;
    private static final int OPTION_MESSAGE_TYPE = 53;
    private static final int OPTION_END = 255;

    /** A reply a server sends to a client: OFFER, ACK or NAK. */
    boolean isServerReply() {
        return op == 2 && (messageType == OFFER || messageType == ACK || messageType == NAK);
    }

    /** OFFER and ACK carry the network settings; a NAK does not. */
    boolean carriesConfiguration() {
        return messageType == OFFER || messageType == ACK;
    }

    /**
     * Parses one DHCP message.
     *
     * @return the message, or empty if it is malformed, not Ethernet, not DHCP (no magic cookie or
     *         no message type option)
     */
    static Optional<DhcpMessage> parse(byte[] d) {
        if (d == null || d.length <= OPTIONS_START) {
            return Optional.empty();
        }
        int op = d[0] & 0xFF;
        boolean ethernet = (d[1] & 0xFF) == 1 && (d[2] & 0xFF) == 6;   // hardware type, address length
        boolean cookie = (d[FIXED_LENGTH] & 0xFF) == 0x63 && (d[FIXED_LENGTH + 1] & 0xFF) == 0x82
                && (d[FIXED_LENGTH + 2] & 0xFF) == 0x53 && (d[FIXED_LENGTH + 3] & 0xFF) == 0x63;
        if ((op != 1 && op != 2) || !ethernet || !cookie) {
            return Optional.empty();
        }
        int xid = ((d[4] & 0xFF) << 24) | ((d[5] & 0xFF) << 16) | ((d[6] & 0xFF) << 8) | (d[7] & 0xFF);

        StringBuilder mac = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                mac.append(':');
            }
            mac.append(String.format("%02x", d[28 + i] & 0xFF));
        }

        int messageType = 0;
        Set<String> routers = new LinkedHashSet<>();
        Set<String> dns = new LinkedHashSet<>();
        int pos = OPTIONS_START;
        while (pos < d.length) {
            int code = d[pos] & 0xFF;
            if (code == OPTION_PAD) {
                pos++;
                continue;
            }
            if (code == OPTION_END) {
                break;
            }
            if (pos + 1 >= d.length) {
                return Optional.empty();
            }
            int length = d[pos + 1] & 0xFF;
            int start = pos + 2;
            if (start + length > d.length) {
                return Optional.empty();
            }
            switch (code) {
                case OPTION_MESSAGE_TYPE -> {
                    if (length != 1) {
                        return Optional.empty();
                    }
                    messageType = d[start] & 0xFF;
                }
                case OPTION_ROUTER -> {
                    if (!addAddresses(d, start, length, routers)) {
                        return Optional.empty();
                    }
                }
                case OPTION_DNS -> {
                    if (!addAddresses(d, start, length, dns)) {
                        return Optional.empty();
                    }
                }
                default -> { /* other options are not needed */ }
            }
            pos = start + length;
        }
        if (messageType == 0) {
            return Optional.empty();
        }
        return Optional.of(new DhcpMessage(op, xid, mac.toString(), messageType,
                Collections.unmodifiableSet(routers), Collections.unmodifiableSet(dns)));
    }

    /** Option data is a list of 4-byte addresses. Returns false if the length is not a multiple of 4. */
    private static boolean addAddresses(byte[] d, int start, int length, Set<String> into) {
        if (length % 4 != 0) {
            return false;
        }
        for (int i = start; i < start + length; i += 4) {
            into.add((d[i] & 0xFF) + "." + (d[i + 1] & 0xFF) + "." + (d[i + 2] & 0xFF) + "." + (d[i + 3] & 0xFF));
        }
        return true;
    }
}
