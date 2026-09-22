package mitmdetector.ml;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Isolation Forest (Liu, Ting and Zhou, 2008) for finding unusual points in numeric data.
 *
 * <p>Each tree is built on a small random sample of the training data. A node picks a random feature
 * and a random split value between the smallest and the largest value of that feature in the node,
 * and sends smaller values to the left and the rest to the right, until every point is alone or the
 * tree is as deep as {@code ceil(log2(sampleSize))}. A point that differs from the rest is cut off
 * after a few splits, a typical point needs many. The score of a point is
 * {@code 2^(-E[h] / c(n))}, where E[h] is its average depth over all trees, corrected for leaves that still
 * hold several points, and c(n) is the average depth of an unsuccessful search in a binary search tree
 * with n nodes. Scores are between 0 and 1: close to 1 means unusual, around 0.5 or below means normal.
 *
 * <p>The random generator is seeded, so the same data and seed always give the same forest.
 * Instances are immutable after training and can be shared between threads.
 */
public final class IsolationForest {

    private static final double EULER_MASCHERONI = 0.5772156649015329;

    /** A leaf has no children; its size is the number of training points that ended there. */
    private record Node(int feature, double split, Node left, Node right, int size) {
        boolean isLeaf() {
            return left == null;
        }
    }

    private final Node[] trees;
    private final int dimensions;
    private final double normalizer;

    private IsolationForest(Node[] trees, int dimensions, int sampleSize) {
        this.trees = trees;
        this.dimensions = dimensions;
        this.normalizer = averagePathLength(sampleSize);
    }

    /**
     * Trains a forest.
     *
     * @param data       one row per observation, all rows with the same number of values; at least two rows
     * @param treeCount  number of trees, 100 is the usual choice
     * @param sampleSize rows sampled for each tree (without repetition), 256 is the usual choice;
     *                   limited to the number of rows
     * @param seed       seed of the random generator
     */
    public static IsolationForest train(double[][] data, int treeCount, int sampleSize, long seed) {
        if (data == null || data.length < 2) {
            throw new IllegalArgumentException("At least two rows are needed to train");
        }
        int dimensions = data[0].length;
        if (dimensions == 0) {
            throw new IllegalArgumentException("Rows must have at least one value");
        }
        for (double[] row : data) {
            if (row.length != dimensions) {
                throw new IllegalArgumentException("All rows must have the same number of values");
            }
        }
        if (treeCount < 1 || sampleSize < 2) {
            throw new IllegalArgumentException("treeCount must be at least 1 and sampleSize at least 2");
        }

        int psi = Math.min(sampleSize, data.length);
        int heightLimit = (int) Math.ceil(Math.log(psi) / Math.log(2));
        Random random = new Random(seed);
        Node[] trees = new Node[treeCount];
        List<Integer> indexes = new ArrayList<>(data.length);
        for (int i = 0; i < data.length; i++) {
            indexes.add(i);
        }
        for (int t = 0; t < treeCount; t++) {
            java.util.Collections.shuffle(indexes, random);
            double[][] sample = new double[psi][];
            for (int i = 0; i < psi; i++) {
                sample[i] = data[indexes.get(i)];
            }
            trees[t] = build(sample, 0, heightLimit, random);
        }
        return new IsolationForest(trees, dimensions, psi);
    }

    /** Anomaly score of one observation, between 0 (very normal) and 1 (very unusual). */
    public double score(double[] point) {
        if (point == null || point.length != dimensions) {
            throw new IllegalArgumentException("Expected " + dimensions + " values");
        }
        double total = 0;
        for (Node tree : trees) {
            total += pathLength(tree, point, 0);
        }
        double average = total / trees.length;
        return Math.pow(2, -average / normalizer);
    }

    private static Node build(double[][] rows, int depth, int heightLimit, Random random) {
        if (depth >= heightLimit || rows.length <= 1) {
            return leaf(rows.length);
        }
        int dimensions = rows[0].length;
        double[] min = rows[0].clone();
        double[] max = rows[0].clone();
        for (double[] row : rows) {
            for (int f = 0; f < dimensions; f++) {
                min[f] = Math.min(min[f], row[f]);
                max[f] = Math.max(max[f], row[f]);
            }
        }
        // Only features that still differ inside this node can split it.
        int[] candidates = new int[dimensions];
        int count = 0;
        for (int f = 0; f < dimensions; f++) {
            if (min[f] < max[f]) {
                candidates[count++] = f;
            }
        }
        if (count == 0) {
            return leaf(rows.length);   // all rows identical
        }

        int feature = candidates[random.nextInt(count)];
        double split = min[feature] + random.nextDouble() * (max[feature] - min[feature]);
        List<double[]> left = new ArrayList<>();
        List<double[]> right = new ArrayList<>();
        for (double[] row : rows) {
            (row[feature] < split ? left : right).add(row);
        }
        if (left.isEmpty() || right.isEmpty()) {
            return leaf(rows.length);   // the split fell exactly on the minimum
        }
        return new Node(feature, split,
                build(left.toArray(new double[0][]), depth + 1, heightLimit, random),
                build(right.toArray(new double[0][]), depth + 1, heightLimit, random),
                rows.length);
    }

    private static Node leaf(int size) {
        return new Node(-1, 0, null, null, size);
    }

    private static double pathLength(Node node, double[] point, int depth) {
        while (!node.isLeaf()) {
            node = point[node.feature()] < node.split() ? node.left() : node.right();
            depth++;
        }
        // A leaf that still holds several points stands for the further splits that were not made.
        return depth + averagePathLength(node.size());
    }

    /** c(n): average depth of an unsuccessful search in a binary search tree with n nodes. */
    static double averagePathLength(int n) {
        if (n <= 1) {
            return 0;
        }
        if (n == 2) {
            return 1;
        }
        return 2 * (Math.log(n - 1) + EULER_MASCHERONI) - 2.0 * (n - 1) / n;
    }
}
