package ro.upb.mitmdetector.ml;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The baseline: one row of traffic features per window of normal traffic, as a CSV file with a header.
 * It is written by {@code --train} and read at startup, where the forest is rebuilt from it. The
 * forest uses a fixed seed, so the same file always gives the same model. The file can be opened
 * in a spreadsheet and edited by hand, for example to remove windows from a period that was not normal.
 */
public final class BaselineFile {

    private BaselineFile() { }

    public static void write(Path path, List<double[]> rows) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add(String.join(",", TrafficWindows.FEATURES));
        for (double[] row : rows) {
            StringBuilder line = new StringBuilder();
            for (int i = 0; i < row.length; i++) {
                if (i > 0) {
                    line.append(',');
                }
                line.append(row[i] == Math.rint(row[i]) ? Long.toString((long) row[i]) : Double.toString(row[i]));
            }
            lines.add(line.toString());
        }
        Files.write(path, lines, StandardCharsets.UTF_8);
    }

    /** @throws IOException if the file cannot be read or does not have the expected header and columns */
    public static double[][] read(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        String expected = String.join(",", TrafficWindows.FEATURES);
        if (lines.isEmpty() || !lines.get(0).trim().equals(expected)) {
            throw new IOException(path + ": the first line must be " + expected);
        }
        List<double[]> rows = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split(",", -1);
            if (parts.length != TrafficWindows.FEATURES.size()) {
                throw new IOException(path + ", line " + (i + 1) + ": expected "
                        + TrafficWindows.FEATURES.size() + " values");
            }
            double[] row = new double[parts.length];
            for (int c = 0; c < parts.length; c++) {
                try {
                    row[c] = Double.parseDouble(parts[c].trim());
                } catch (NumberFormatException e) {
                    throw new IOException(path + ", line " + (i + 1) + ": '" + parts[c] + "' is not a number");
                }
            }
            rows.add(row);
        }
        return rows.toArray(new double[0][]);
    }
}
