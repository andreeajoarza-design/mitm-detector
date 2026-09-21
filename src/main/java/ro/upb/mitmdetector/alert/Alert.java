package ro.upb.mitmdetector.alert;

import java.time.Instant;
import java.util.Objects;

/**
 * One finding produced by a detector.
 *
 * @param timestamp  capture time of the packet that triggered the alert
 * @param type       kind of attack suspected
 * @param severity   how serious the finding is
 * @param message    human readable explanation
 * @param sourceIp   IP address the packet claimed to come from
 * @param sourceMac  MAC address the packet claimed to come from
 */
public record Alert(
        Instant timestamp,
        AlertType type,
        Severity severity,
        String message,
        String sourceIp,
        String sourceMac) {

    public Alert {
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(sourceIp, "sourceIp");
        Objects.requireNonNull(sourceMac, "sourceMac");
    }

    /** Alerts with the same key are treated as repeats of one incident. */
    String dedupKey() {
        return type + "|" + sourceIp + "|" + sourceMac;
    }

    @Override
    public String toString() {
        return "[%s] [%s] %s %s (ip=%s, mac=%s)"
                .formatted(timestamp, severity, type, message, sourceIp, sourceMac);
    }
}
