package ro.upb.mitmdetector.ml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.Packet;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrafficWindowsTest {

    private static final String SERVER_MAC = "aa:aa:aa:aa:aa:01";
    private static final String SERVER_IP = "192.168.1.1";
    private static final String CLIENT_MAC = "bb:bb:bb:bb:bb:10";
    private static final String CLIENT_IP = "192.168.1.10";
    private static final Instant T0 = Instant.parse("2026-01-01T10:00:00Z");

    private List<TrafficWindows.Sample> samples;
    private TrafficWindows windows;

    @BeforeEach
    void setUp() {
        samples = new ArrayList<>();
        windows = new TrafficWindows(samples::add);
    }

    private void send(Packet packet, double seconds) {
        windows.inspect(packet, T0.plusMillis((long) (seconds * 1000)));
    }

    @Test
    void countsWhatASenderDoesInOneWindow() {
        send(TrafficTestPackets.arpRequest(SERVER_MAC, SERVER_IP, CLIENT_IP), 1);
        send(TrafficTestPackets.arpReply(SERVER_MAC, SERVER_IP, CLIENT_MAC, CLIENT_IP), 2);
        send(TrafficTestPackets.arpReply(SERVER_MAC, SERVER_IP, CLIENT_MAC, CLIENT_IP), 3);
        send(TrafficTestPackets.arpReply(SERVER_MAC, "192.168.1.2", CLIENT_MAC, CLIENT_IP), 4);
        send(TrafficTestPackets.udp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 53, 40000), 5);
        send(TrafficTestPackets.udp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 53, 40001), 6);
        send(TrafficTestPackets.udp(SERVER_MAC, CLIENT_MAC, SERVER_IP, "255.255.255.255", 67, 68), 7);
        send(TrafficTestPackets.tcp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 80, 50000), 8);
        windows.flush();

        assertEquals(1, samples.size());
        TrafficWindows.Sample sample = samples.get(0);
        assertEquals(SERVER_MAC, sample.mac());
        assertEquals(SERVER_IP, sample.ip());
        assertEquals(Instant.parse("2026-01-01T10:00:10Z"), sample.windowEnd());
        //                              packets, arpReq, arpRep, arpIps, dns, dhcp, dest, http
        assertArrayEquals(new double[]{8, 1, 3, 2, 2, 1, 2, 1}, sample.features(), 0.0);
    }

    @Test
    void featureNamesMatchTheVectorLength() {
        assertEquals(8, TrafficWindows.FEATURES.size());
    }

    @Test
    void bareAcknowledgementsAndOtherPortsAreNotCounted() {
        send(TrafficTestPackets.tcpWithoutData(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 80, 50000), 1);
        send(TrafficTestPackets.tcp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 8080, 50000), 2);
        send(TrafficTestPackets.udp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 5353, 5353), 3);
        windows.flush();

        assertArrayEquals(new double[]{3, 0, 0, 0, 0, 0, 1, 0}, samples.get(0).features(), 0.0);
    }

    @Test
    void windowIsFinishedWhenALaterOneStarts() {
        send(TrafficTestPackets.udp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 53, 40000), 1);
        assertTrue(samples.isEmpty());

        send(TrafficTestPackets.udp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 53, 40000), 12);
        assertEquals(1, samples.size());
        assertEquals(Instant.parse("2026-01-01T10:00:10Z"), samples.get(0).windowEnd());

        windows.flush();
        assertEquals(2, samples.size());
        assertEquals(Instant.parse("2026-01-01T10:00:20Z"), samples.get(1).windowEnd());
    }

    @Test
    void windowsAreAlignedToMultiplesOfTenSeconds() {
        send(TrafficTestPackets.udp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 53, 40000), 9.9);
        send(TrafficTestPackets.udp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 53, 40000), 10.1);
        windows.flush();
        assertEquals(2, samples.size());
    }

    @Test
    void eachSenderGetsItsOwnSampleInMacOrder() {
        send(TrafficTestPackets.udp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 53, 40000), 1);
        send(TrafficTestPackets.udp(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, 40000, 53), 2);
        windows.flush();

        assertEquals(2, samples.size());
        assertEquals(SERVER_MAC, samples.get(0).mac());   // "aa..." sorts before "bb..."
        assertEquals(CLIENT_MAC, samples.get(1).mac());
        assertEquals(1, samples.get(0).features()[4]);    // one DNS response
        assertEquals(0, samples.get(1).features()[4]);
    }

    @Test
    void flushWithoutPacketsGivesNothing() {
        windows.flush();
        assertTrue(samples.isEmpty());
    }

    @Test
    void windowsAfterAFlushStartFresh() {
        send(TrafficTestPackets.udp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 53, 40000), 1);
        windows.flush();
        send(TrafficTestPackets.udp(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, 53, 40000), 2);
        windows.flush();
        assertEquals(2, samples.size());
        assertEquals(1, samples.get(1).features()[0]);
    }
}
