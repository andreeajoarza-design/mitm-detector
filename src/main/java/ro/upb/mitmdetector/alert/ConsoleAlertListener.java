package ro.upb.mitmdetector.alert;

/** Prints alerts to standard output. */
public final class ConsoleAlertListener implements AlertListener {

    @Override
    public void onAlert(Alert alert) {
        System.out.println(alert);
    }
}
