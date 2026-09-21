package ro.upb.mitmdetector.alert;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Central place where detectors raise alerts.
 *
 * <p>An attacker usually repeats the same forged packet every second or so, so the manager
 * drops a repeat of the same incident (same type, IP and MAC) that arrives within the
 * cooldown period. Time is taken from the alert itself, which keeps behaviour identical
 * for live capture and for replaying a pcap file.
 */
public final class AlertManager {

    public static final Duration DEFAULT_COOLDOWN = Duration.ofSeconds(10);

    private final Duration cooldown;
    private final List<AlertListener> listeners = new CopyOnWriteArrayList<>();
    private final Map<String, Instant> lastRaised = new ConcurrentHashMap<>();
    private final List<Alert> history = Collections.synchronizedList(new ArrayList<>());

    public AlertManager() {
        this(DEFAULT_COOLDOWN);
    }

    public AlertManager(Duration cooldown) {
        this.cooldown = cooldown;
    }

    public void addListener(AlertListener listener) {
        listeners.add(listener);
    }

    /**
     * Publishes an alert to all listeners unless it repeats a recent one.
     *
     * @return true if the alert was published, false if it was suppressed
     */
    public boolean raise(Alert alert) {
        Instant previous = lastRaised.get(alert.dedupKey());
        if (previous != null && Duration.between(previous, alert.timestamp()).abs().compareTo(cooldown) < 0) {
            return false;
        }
        lastRaised.put(alert.dedupKey(), alert.timestamp());
        history.add(alert);
        for (AlertListener listener : listeners) {
            try {
                listener.onAlert(alert);
            } catch (RuntimeException e) {
                // One broken listener must not stop the others or the capture thread.
                System.err.println("Alert listener failed: " + e);
            }
        }
        return true;
    }

    /** Snapshot of every alert published so far. */
    public List<Alert> history() {
        synchronized (history) {
            return List.copyOf(history);
        }
    }
}
