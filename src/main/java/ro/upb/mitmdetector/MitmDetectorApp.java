package ro.upb.mitmdetector;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import ro.upb.mitmdetector.alert.AlertManager;
import ro.upb.mitmdetector.alert.ConsoleAlertListener;
import ro.upb.mitmdetector.alert.FileAlertListener;
import ro.upb.mitmdetector.capture.PacketCaptureEngine;
import ro.upb.mitmdetector.detector.ArpDetector;
import ro.upb.mitmdetector.detector.DhcpDetector;
import ro.upb.mitmdetector.detector.DnsDetector;
import ro.upb.mitmdetector.detector.HttpDetector;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Entry point.
 *
 * <pre>
 *   --list                 print the capture interfaces with their index
 *   --interface &lt;index&gt;    capture live on that interface until Ctrl+C
 *   --pcap &lt;file&gt;          replay a saved capture
 *   --dhcp-servers &lt;ip,ip&gt; optional, after the two arguments above: the legitimate DHCP servers
 *                          (without it, the first DHCP server seen is taken as the legitimate one)
 *   --https-hosts &lt;a,b&gt;    optional, after the two arguments above: host names known to require HTTPS
 *                          (without it, a host is learned once it is seen redirecting to HTTPS)
 * </pre>
 * Alerts go to the console and to alerts.log in the working directory.
 */
public final class MitmDetectorApp {

    private static final long STATS_INTERVAL_SECONDS = 5;

    private MitmDetectorApp() { }

    public static void main(String[] args) throws PcapNativeException, InterruptedException {
        if (args.length == 0) {
            usage();
            return;
        }

        if (args[0].equals("--list")) {
            printInterfaces(PacketCaptureEngine.listInterfaces());
            return;
        }
        if (args.length < 2) {
            usage();
            return;
        }

        AlertManager alerts = new AlertManager();
        alerts.addListener(new ConsoleAlertListener());
        alerts.addListener(new FileAlertListener(Path.of("alerts.log")));

        PacketCaptureEngine engine = switch (args[0]) {
            case "--interface" -> PacketCaptureEngine.forInterface(pickInterface(args[1]));
            case "--pcap" -> PacketCaptureEngine.forFile(args[1]);
            default -> null;
        };
        if (engine == null) {
            usage();
            return;
        }

        engine.addDetector(new ArpDetector(alerts));
        engine.addDetector(new DnsDetector(alerts));
        engine.addDetector(new DhcpDetector(alerts, listOption(args, "--dhcp-servers")));
        engine.addDetector(new HttpDetector(alerts, listOption(args, "--https-hosts")));

        Runtime.getRuntime().addShutdownHook(new Thread(engine::close));
        engine.start();
        System.out.println("Capture started. Press Ctrl+C to stop.");

        boolean live = args[0].equals("--interface");
        ScheduledExecutorService stats = null;
        if (live) {
            stats = Executors.newSingleThreadScheduledExecutor(task -> {
                Thread thread = new Thread(task, "stats");
                thread.setDaemon(true);
                return thread;
            });
            stats.scheduleAtFixedRate(() -> System.out.println(summary(engine, alerts)),
                    STATS_INTERVAL_SECONDS, STATS_INTERVAL_SECONDS, TimeUnit.SECONDS);
        }

        engine.awaitCompletion();
        if (stats != null) {
            stats.shutdownNow();
        }
        System.out.println("Capture finished. " + summary(engine, alerts));
    }

    private static String summary(PacketCaptureEngine engine, AlertManager alerts) {
        return "Packets: %d, ARP: %d, alerts: %d"
                .formatted(engine.packetCount(), engine.arpPacketCount(), alerts.history().size());
    }

    /** Reads an optional "name a,b,c" argument. An empty set means the option was not given. */
    private static Set<String> listOption(String[] args, String name) {
        Set<String> values = new HashSet<>();
        for (int i = 2; i + 1 < args.length; i++) {
            if (args[i].equals(name)) {
                for (String item : args[i + 1].split(",")) {
                    if (!item.isBlank()) {
                        values.add(item.trim());
                    }
                }
            }
        }
        return values;
    }

    private static PcapNetworkInterface pickInterface(String indexText) throws PcapNativeException {
        List<PcapNetworkInterface> all = PacketCaptureEngine.listInterfaces();
        int index = Integer.parseInt(indexText);
        if (index < 0 || index >= all.size()) {
            throw new IllegalArgumentException("Interface index out of range: " + index);
        }
        return all.get(index);
    }

    private static void printInterfaces(List<PcapNetworkInterface> all) {
        for (int i = 0; i < all.size(); i++) {
            PcapNetworkInterface nif = all.get(i);
            System.out.printf("%d: %s (%s)%n", i, nif.getDescription(), nif.getName());
        }
    }

    private static void usage() {
        System.out.println("Usage: --list | --interface <index> | --pcap <file> [--dhcp-servers <ip,ip>] [--https-hosts <a,b>]");
    }
}
