package ro.upb.mitmdetector.ml;

import org.pcap4j.packet.Packet;
import ro.upb.mitmdetector.alert.Alert;
import ro.upb.mitmdetector.alert.AlertManager;
import ro.upb.mitmdetector.alert.AlertType;
import ro.upb.mitmdetector.alert.Severity;
import ro.upb.mitmdetector.detector.Detector;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Reports senders whose traffic in a {@link TrafficWindows#WINDOW} looks unlike the baseline.
 *
 * <p>The rule-based detectors look for known attacks. This one has no idea what an attack is: it learns
 * from a baseline of normal windows (see {@link BaselineFile}) with an {@link IsolationForest}, and
 * every finished window of every sender gets an anomaly score. A score above the threshold raises a
 * MEDIUM {@link AlertType#ML_ANOMALY} alert. It is a second opinion that can also notice attacks
 * for which no rule was written, and it is expected to be noisier than the rules.
 *
 * <p>An Isolation Forest is good at telling odd combinations of values from usual ones, but it does not
 * extrapolate: a value far beyond the training range scores about as high as the most extreme value
 * in the baseline, and no higher. A flood of 40 ARP replies would then look no stranger than a baseline
 * window with 2. So a window is also reported when one of its values is far above the baseline: more than
 * {@link #RANGE_FACTOR} times the baseline maximum and at least {@link #RANGE_MARGIN} more than it.
 *
 * <p>The threshold is the highest score any baseline window gets itself, plus {@link #MARGIN}, but never
 * less than {@link #MIN_THRESHOLD}. So a window has to look more unusual than everything in the baseline
 * to raise an alert. One odd window in the baseline raises the threshold for good; such a window can be
 * deleted from the baseline file. The message lists the values that are above anything in the
 * baseline, which shows what is unusual without any need to read the score.
 *
 * <p>Known limitations: the baseline must come from the network that is monitored, and from a period
 * that had no attack in it; behaviour that never happened in the baseline (a new device, a backup at
 * night) will look unusual; the features are counts per sender, so a slow attack that stays within
 * normal counts is not seen; a window is scored only after it has ended, so the alert comes up to
 * {@link TrafficWindows#WINDOW} late.
 */
public final class AnomalyDetector implements Detector {

    public static final double MIN_THRESHOLD = 0.6;
    public static final double MARGIN = 0.02;
    public static final int MIN_BASELINE_WINDOWS = 20;
    public static final double RANGE_FACTOR = 2;
    public static final double RANGE_MARGIN = 10;

    private static final int TREES = 100;
    private static final int SAMPLE_SIZE = 256;
    private static final long SEED = 42;

    private final AlertManager alerts;
    private final IsolationForest forest;
    private final double threshold;
    private final double[] baselineMax;
    private final double[] rangeLimit;
    private final double[] baselineScores;
    private final TrafficWindows windows;

    /** @param baseline rows of features from normal traffic, at least {@link #MIN_BASELINE_WINDOWS} */
    public AnomalyDetector(AlertManager alerts, double[][] baseline) {
        if (baseline.length < MIN_BASELINE_WINDOWS) {
            throw new IllegalArgumentException("The baseline has %d windows, at least %d are needed"
                    .formatted(baseline.length, MIN_BASELINE_WINDOWS));
        }
        this.alerts = alerts;
        this.forest = IsolationForest.train(baseline, TREES, SAMPLE_SIZE, SEED);

        this.baselineMax = new double[TrafficWindows.FEATURES.size()];
        for (double[] row : baseline) {
            for (int f = 0; f < row.length; f++) {
                baselineMax[f] = Math.max(baselineMax[f], row[f]);
            }
        }
        this.rangeLimit = new double[baselineMax.length];
        for (int f = 0; f < baselineMax.length; f++) {
            rangeLimit[f] = Math.max(baselineMax[f] * RANGE_FACTOR, baselineMax[f] + RANGE_MARGIN);
        }
        this.baselineScores = new double[baseline.length];
        for (int i = 0; i < baseline.length; i++) {
            baselineScores[i] = forest.score(baseline[i]);
        }
        Arrays.sort(baselineScores);
        this.threshold = Math.max(MIN_THRESHOLD, baselineScores[baselineScores.length - 1] + MARGIN);

        this.windows = new TrafficWindows(this::score);
    }

    public double threshold() {
        return threshold;
    }

    /** One line about the baseline, for the console: how many windows and how they score. */
    public String summary() {
        int n = baselineScores.length;
        return "Baseline: %d windows, scores median %.2f, 99th percentile %.2f, maximum %.2f; alert threshold %.2f"
                .formatted(n, baselineScores[n / 2], baselineScores[(int) Math.ceil(0.99 * n) - 1],
                        baselineScores[n - 1], threshold);
    }

    @Override
    public void inspect(Packet packet, Instant timestamp) {
        windows.inspect(packet, timestamp);
    }

    @Override
    public void flush() {
        windows.flush();
    }

    private void score(TrafficWindows.Sample sample) {
        double score = forest.score(sample.features());
        boolean unusual = score > threshold;
        boolean farAbove = false;
        List<String> above = new ArrayList<>();
        for (int f = 0; f < baselineMax.length; f++) {
            double value = sample.features()[f];
            farAbove |= value > rangeLimit[f];
            if (value > baselineMax[f]) {
                above.add("%s %d (most in the baseline: %d)".formatted(TrafficWindows.FEATURES.get(f),
                        (long) value, (long) baselineMax[f]));
            }
        }
        if (!unusual && !farAbove) {
            return;
        }
        String reason = above.isEmpty()
                ? "no single value is above the baseline, but the combination is unusual"
                : "above the baseline: " + String.join(", ", above);
        String what = unusual ? "is unusual" : "has a value far above the baseline";
        alerts.raise(new Alert(sample.windowEnd(), AlertType.ML_ANOMALY, Severity.MEDIUM,
                "Traffic from this sender in the 10 s window ending %s %s (score %.2f, threshold %.2f); %s"
                        .formatted(sample.windowEnd(), what, score, threshold, reason),
                sample.ip(), sample.mac()));
    }
}
