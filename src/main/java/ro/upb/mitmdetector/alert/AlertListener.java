package ro.upb.mitmdetector.alert;

/** Receives every alert that passes the {@link AlertManager} filter. */
@FunctionalInterface
public interface AlertListener {
    void onAlert(Alert alert);
}
