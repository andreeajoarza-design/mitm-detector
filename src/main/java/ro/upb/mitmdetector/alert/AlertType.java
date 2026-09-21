package ro.upb.mitmdetector.alert;

/** The kind of suspicious behaviour a detector reports. */
public enum AlertType {
    /** An IP address that was seen with one MAC is now announced with another MAC. */
    ARP_SPOOFING,
    /** The Ethernet source address differs from the sender hardware address inside the ARP payload. */
    ARP_HEADER_MISMATCH,
    /** Many ARP replies arrive from the same host without any matching request. */
    ARP_UNSOLICITED_FLOOD,
    /** Two different answers arrived for the same DNS query, so one of them is forged. */
    DNS_CONFLICTING_RESPONSES,
    /** A DNS response arrived for a query the client never sent (or sent long ago). */
    DNS_UNSOLICITED_RESPONSE,
    /** A name that always resolved to public addresses suddenly resolves to a private one. */
    DNS_ANSWER_CHANGED,
    /** A DHCP server that is not the known one answers clients, or someone answers with the known server's IP but another MAC. */
    DHCP_ROGUE_SERVER,
    /** Two different DHCP servers answer the same client request with different gateway or DNS settings. */
    DHCP_CONFLICTING_OFFERS,
    /** A known DHCP server suddenly hands out a different gateway or DNS server. */
    DHCP_CONFIG_CHANGED
}
