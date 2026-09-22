package mitmdetector.detector;

import org.pcap4j.packet.Packet;

import java.time.Instant;

/** A single attack check. The capture engine calls it for every packet it sees. */
public interface Detector {

    /**
     * Examines one packet.
     *
     * @param packet    the full packet, starting at the Ethernet header
     * @param timestamp capture time of the packet (from the pcap header, not the wall clock)
     */
    void inspect(Packet packet, Instant timestamp);

    /**
     * Called once when the capture ends (end of a pcap file, or Ctrl+C on a live capture), so that a
     * detector that works on groups of packets can finish the last group. Most detectors need nothing here.
     */
    default void flush() { }
}
