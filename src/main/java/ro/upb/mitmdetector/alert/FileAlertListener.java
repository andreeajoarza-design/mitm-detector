package ro.upb.mitmdetector.alert;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** Appends one line per alert to a text file. */
public final class FileAlertListener implements AlertListener {

    private final Path file;

    public FileAlertListener(Path file) {
        this.file = file;
    }

    @Override
    public synchronized void onAlert(Alert alert) {
        try {
            Files.writeString(file, alert + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot write alert to " + file, e);
        }
    }
}
