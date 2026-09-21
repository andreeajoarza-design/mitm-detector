package ro.upb.mitmdetector.ml;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BaselineFileTest {

    private static final String HEADER = String.join(",", TrafficWindows.FEATURES);

    private static Path fileWith(String... lines) throws IOException {
        Path path = Files.createTempFile("baseline", ".csv");
        path.toFile().deleteOnExit();
        Files.write(path, List.of(lines), StandardCharsets.UTF_8);
        return path;
    }

    @Test
    void writtenRowsAreReadBack() throws IOException {
        Path path = Files.createTempFile("baseline", ".csv");
        path.toFile().deleteOnExit();
        List<double[]> rows = List.of(
                new double[]{12, 1, 2, 1, 3, 0, 4, 1},
                new double[]{0, 0, 0, 0, 0, 0, 0, 0.5});
        BaselineFile.write(path, rows);

        assertEquals(HEADER, Files.readAllLines(path).get(0));
        double[][] read = BaselineFile.read(path);
        assertEquals(2, read.length);
        assertArrayEquals(rows.get(0), read[0], 0.0);
        assertArrayEquals(rows.get(1), read[1], 0.0);
    }

    @Test
    void blankLinesAreSkipped() throws IOException {
        double[][] read = BaselineFile.read(fileWith(HEADER, "1,2,3,4,5,6,7,8", "", "8,7,6,5,4,3,2,1", ""));
        assertEquals(2, read.length);
    }

    @Test
    void wrongHeaderIsRejected() throws IOException {
        Path path = fileWith("a,b,c", "1,2,3");
        assertThrows(IOException.class, () -> BaselineFile.read(path));
    }

    @Test
    void wrongNumberOfValuesIsRejected() throws IOException {
        Path path = fileWith(HEADER, "1,2,3");
        assertThrows(IOException.class, () -> BaselineFile.read(path));
    }

    @Test
    void textInsteadOfNumberIsRejected() throws IOException {
        Path path = fileWith(HEADER, "1,2,3,4,5,6,7,x");
        assertThrows(IOException.class, () -> BaselineFile.read(path));
    }
}
