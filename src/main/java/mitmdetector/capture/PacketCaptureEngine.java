package mitmdetector.capture;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import mitmdetector.detector.Detector;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Reads packets from a network interface (live) or from a pcap file (replay) on a background
 * thread and hands each one to every registered {@link Detector}.
 *
 * <p>Replaying a pcap file is useful for repeatable experiments: the same capture always
 * produces the same alerts.
 */
public final class PacketCaptureEngine implements AutoCloseable {

    private static final int SNAPLEN = 65536;
    private static final int READ_TIMEOUT_MS = 10;

    private final PcapNetworkInterface networkInterface; // null when replaying a file
    private final String pcapFile;                        // null when capturing live
    private final List<Detector> detectors = new CopyOnWriteArrayList<>();
    private final AtomicLong packetCount = new AtomicLong();
    private final AtomicLong arpPacketCount = new AtomicLong();

    private volatile PcapHandle handle;
    private Thread captureThread;

    private PacketCaptureEngine(PcapNetworkInterface networkInterface, String pcapFile) {
        this.networkInterface = networkInterface;
        this.pcapFile = pcapFile;
    }

    /** Live capture on the given interface, in promiscuous mode. */
    public static PacketCaptureEngine forInterface(PcapNetworkInterface networkInterface) {
        return new PacketCaptureEngine(networkInterface, null);
    }

    /** Replay of a previously saved capture (Wireshark / tcpdump .pcap file). */
    public static PacketCaptureEngine forFile(String pcapFile) {
        return new PacketCaptureEngine(null, pcapFile);
    }

    /** All interfaces libpcap (Npcap on Windows) can capture on. */
    public static List<PcapNetworkInterface> listInterfaces() throws PcapNativeException {
        return Pcaps.findAllDevs();
    }

    public void addDetector(Detector detector) {
        detectors.add(detector);
    }

    /** Packets seen so far, of any kind. */
    public long packetCount() {
        return packetCount.get();
    }

    /** ARP packets seen so far. */
    public long arpPacketCount() {
        return arpPacketCount.get();
    }

    /** Opens the source and starts reading on a new thread. */
    public synchronized void start() throws PcapNativeException {
        if (captureThread != null) {
            throw new IllegalStateException("Capture already started");
        }
        handle = (networkInterface != null)
                ? networkInterface.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS)
                : Pcaps.openOffline(pcapFile);
        String name = (networkInterface != null) ? networkInterface.getName() : pcapFile;
        captureThread = new Thread(this::captureLoop, "capture-" + name);
        captureThread.setDaemon(true);
        captureThread.start();
    }

    /** Blocks until the capture ends. For live capture that means until {@link #close()} is called. */
    public void awaitCompletion() throws InterruptedException {
        Thread thread = captureThread;
        if (thread != null) {
            thread.join();
        }
    }

    private void captureLoop() {
        PcapHandle h = handle;
        try {
            // -1 means "no packet limit". The lambda runs once per packet on this thread.
            h.loop(-1, (Packet packet) -> dispatch(packet, h.getTimestamp().toInstant()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (PcapNativeException | NotOpenException e) {
            System.err.println("Capture stopped: " + e.getMessage());
        } finally {
            for (Detector detector : detectors) {
                try {
                    detector.flush();
                } catch (RuntimeException e) {
                    System.err.println(detector.getClass().getSimpleName() + " failed: " + e);
                }
            }
        }
    }

    private void dispatch(Packet packet, Instant timestamp) {
        packetCount.incrementAndGet();
        if (packet.get(ArpPacket.class) != null) {
            arpPacketCount.incrementAndGet();
        }
        for (Detector detector : detectors) {
            try {
                detector.inspect(packet, timestamp);
            } catch (RuntimeException e) {
                // A bug in one detector must not stop capture or the other detectors.
                System.err.println(detector.getClass().getSimpleName() + " failed: " + e);
            }
        }
    }

    @Override
    public synchronized void close() {
        PcapHandle h = handle;
        if (h != null && h.isOpen()) {
            try {
                h.breakLoop();
            } catch (NotOpenException ignored) {
                // Already closed.
            }
        }
        if (captureThread != null) {
            try {
                captureThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (h != null && h.isOpen()) {
            h.close();
        }
    }
}
