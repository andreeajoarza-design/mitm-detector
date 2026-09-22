package mitmdetector.ml;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IsolationForestTest {

    /** 300 points scattered around (0, 0). */
    private static double[][] cluster() {
        Random random = new Random(1);
        double[][] data = new double[300][];
        for (int i = 0; i < data.length; i++) {
            data[i] = new double[]{random.nextGaussian(), random.nextGaussian()};
        }
        return data;
    }

    @Test
    void pointFarFromTheClusterScoresHigherThanPointInsideIt() {
        IsolationForest forest = IsolationForest.train(cluster(), 100, 256, 7);

        double inside = forest.score(new double[]{0.1, -0.1});
        double outside = forest.score(new double[]{9, 9});

        assertTrue(inside < 0.55, "inside: " + inside);
        assertTrue(outside > 0.7, "outside: " + outside);
        assertTrue(outside > inside + 0.2);
    }

    @Test
    void scoresStayBetweenZeroAndOne() {
        IsolationForest forest = IsolationForest.train(cluster(), 50, 128, 3);
        for (double[] point : new double[][]{{0, 0}, {3, -3}, {1e6, 1e6}, {-1e6, 0}}) {
            double score = forest.score(point);
            assertTrue(score > 0 && score < 1, "score " + score);
        }
    }

    @Test
    void sameSeedGivesSameScores() {
        double[] point = {2.5, -1};
        double first = IsolationForest.train(cluster(), 100, 256, 11).score(point);
        double second = IsolationForest.train(cluster(), 100, 256, 11).score(point);
        assertEquals(first, second, 0.0);
    }

    @Test
    void identicalRowsScoreOneHalf() {
        double[][] data = new double[50][];
        for (int i = 0; i < data.length; i++) {
            data[i] = new double[]{4, 4, 4};
        }
        IsolationForest forest = IsolationForest.train(data, 20, 32, 1);
        assertEquals(0.5, forest.score(new double[]{4, 4, 4}), 1e-9);
    }

    @Test
    void averagePathLengthMatchesTheFormula() {
        assertEquals(0.0, IsolationForest.averagePathLength(1), 0.0);
        assertEquals(1.0, IsolationForest.averagePathLength(2), 0.0);
        assertEquals(10.2448, IsolationForest.averagePathLength(256), 0.001);
    }

    @Test
    void rejectsBadInput() {
        assertThrows(IllegalArgumentException.class, () -> IsolationForest.train(null, 10, 10, 1));
        assertThrows(IllegalArgumentException.class, () -> IsolationForest.train(new double[][]{{1, 2}}, 10, 10, 1));
        assertThrows(IllegalArgumentException.class,
                () -> IsolationForest.train(new double[][]{{1, 2}, {3}}, 10, 10, 1));
        assertThrows(IllegalArgumentException.class, () -> IsolationForest.train(cluster(), 0, 10, 1));

        IsolationForest forest = IsolationForest.train(cluster(), 10, 10, 1);
        assertThrows(IllegalArgumentException.class, () -> forest.score(new double[]{1, 2, 3}));
    }
}
