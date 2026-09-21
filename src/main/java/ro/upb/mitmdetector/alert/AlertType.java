package ro.upb.mitmdetector.alert;

/** The kind of suspicious behaviour a detector reports. */
public enum AlertType {
    /** An IP address that was seen with one MAC is now announced with another MAC. */
    ARP_SPOOFING,
    /** The Ethernet source address differs from the sender hardware address inside the ARP payload. */
    ARP_HEADER_MISMATCH,
    /** Many ARP replies arrive from the same host without any matching request. */
    ARP_UNSOLICITED_FLOOD
}
