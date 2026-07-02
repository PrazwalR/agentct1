//! Isolation Forest for behavioral anomaly scoring — a native-speed port of the
//! TypeScript scorer. Deterministic via a seedable PRNG; splits only on features
//! that vary in a node so near-constant features don't wash out the signal.

enum Node {
    Leaf { size: usize },
    Internal { f: usize, v: f64, left: Box<Node>, right: Box<Node> },
}

/// mulberry32 — small deterministic PRNG (matches the TS implementation).
struct Mulberry32 {
    state: u32,
}

impl Mulberry32 {
    fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    fn next_f64(&mut self) -> f64 {
        self.state = self.state.wrapping_add(0x6d2b_79f5);
        let mut t = (self.state ^ (self.state >> 15)).wrapping_mul(1 | self.state);
        t = (t.wrapping_add((t ^ (t >> 7)).wrapping_mul(61 | t))) ^ t;
        ((t ^ (t >> 14)) as f64) / 4_294_967_296.0
    }
}

/// Average path length of an unsuccessful BST search over `n` points.
fn c_factor(n: usize) -> f64 {
    if n <= 1 {
        return 0.0;
    }
    let n = n as f64;
    2.0 * ((n - 1.0).ln() + 0.577_215_664_9) - (2.0 * (n - 1.0)) / n
}

fn subsample(data: &[Vec<f64>], k: usize, rng: &mut Mulberry32) -> Vec<Vec<f64>> {
    if data.len() <= k {
        return data.to_vec();
    }
    (0..k)
        .map(|_| {
            let idx = (rng.next_f64() * data.len() as f64) as usize;
            data[idx.min(data.len() - 1)].clone()
        })
        .collect()
}

fn build_tree(data: &[Vec<f64>], depth: usize, max_depth: usize, rng: &mut Mulberry32) -> Node {
    let n = data.len();
    let dims = data.first().map_or(0, |r| r.len());
    if depth >= max_depth || n <= 1 || dims == 0 {
        return Node::Leaf { size: n };
    }

    // Candidate split features = those with a non-zero range in this node.
    let mut ranges: Vec<(usize, f64, f64)> = Vec::new();
    for f in 0..dims {
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        for row in data {
            let x = row.get(f).copied().unwrap_or(0.0); // ragged rows must not panic
            if x < min {
                min = x;
            }
            if x > max {
                max = x;
            }
        }
        if max > min {
            ranges.push((f, min, max));
        }
    }
    if ranges.is_empty() {
        return Node::Leaf { size: n };
    }

    let pick = ranges[(rng.next_f64() * ranges.len() as f64) as usize];
    let (f, min, max) = pick;
    let v = min + rng.next_f64() * (max - min);

    let mut left = Vec::new();
    let mut right = Vec::new();
    for row in data {
        if row.get(f).copied().unwrap_or(0.0) < v {
            left.push(row.clone());
        } else {
            right.push(row.clone());
        }
    }

    Node::Internal {
        f,
        v,
        left: Box::new(build_tree(&left, depth + 1, max_depth, rng)),
        right: Box::new(build_tree(&right, depth + 1, max_depth, rng)),
    }
}

fn path_length(x: &[f64], node: &Node, depth: usize) -> f64 {
    match node {
        Node::Leaf { size } => depth as f64 + c_factor(*size),
        Node::Internal { f, v, left, right } => {
            // A query point shorter than the training dims must not panic (remote DoS
            // via the /score API) — treat a missing feature as 0, matching the TS scorer.
            let xf = x.get(*f).copied().unwrap_or(0.0);
            let next = if xf < *v { left } else { right };
            path_length(x, next, depth + 1)
        }
    }
}

pub struct IsolationForest {
    trees: Vec<Node>,
    sample_size: usize,
}

impl IsolationForest {
    pub fn fit(data: &[Vec<f64>], trees: usize, sample_size: usize, seed: u32) -> Self {
        let mut rng = Mulberry32::new(seed);
        let sample_size = sample_size.min(data.len()).max(1);
        let max_depth = ((sample_size.max(2) as f64).log2().ceil()) as usize;
        let trees = (0..trees)
            .map(|_| {
                let sample = subsample(data, sample_size, &mut rng);
                build_tree(&sample, 0, max_depth, &mut rng)
            })
            .collect();
        Self { trees, sample_size }
    }

    /// Anomaly score in [0,1]; higher = more anomalous.
    pub fn anomaly_score(&self, x: &[f64]) -> f64 {
        if self.trees.is_empty() {
            return 0.0;
        }
        let mean: f64 =
            self.trees.iter().map(|t| path_length(x, t, 0)).sum::<f64>() / self.trees.len() as f64;
        let cn = c_factor(self.sample_size);
        if cn == 0.0 {
            0.0
        } else {
            2f64.powf(-mean / cn)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cluster() -> Vec<Vec<f64>> {
        (0..200)
            .map(|i| {
                let i = i as f64;
                vec![
                    80000.0 + (i * 137.0) % 40000.0,
                    1.0 + (i * 7.0) % 60.0,
                    (i * 5.0) % 24.0,
                    if (i as i64) % 6 == 0 { 1.0 } else { 0.0 },
                ]
            })
            .collect()
    }

    #[test]
    fn scores_outlier_higher_than_inlier() {
        let forest = IsolationForest::fit(&cluster(), 120, 128, 42);
        let inlier = forest.anomaly_score(&[100000.0, 30.0, 12.0, 0.0]);
        let outlier = forest.anomaly_score(&[50_000_000_000.0, 30.0, 12.0, 1.0]);
        assert!(outlier > inlier, "outlier {outlier} should exceed inlier {inlier}");
        assert!(outlier > 0.6, "outlier score {outlier} should be high");
    }

    #[test]
    fn deterministic_for_a_fixed_seed() {
        let a = IsolationForest::fit(&cluster(), 64, 64, 7).anomaly_score(&[1e10, 5.0, 3.0, 1.0]);
        let b = IsolationForest::fit(&cluster(), 64, 64, 7).anomaly_score(&[1e10, 5.0, 3.0, 1.0]);
        assert_eq!(a, b);
    }

    #[test]
    fn short_or_ragged_vectors_do_not_panic() {
        // A query point shorter than the training dims must not panic (remote DoS).
        let forest = IsolationForest::fit(&cluster(), 50, 64, 1);
        let _ = forest.anomaly_score(&[1.0]);
        let _ = forest.anomaly_score(&[]);
        let _ = forest.anomaly_score(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        // Ragged training data (rows of differing lengths) must not panic either.
        let ragged = vec![vec![1.0, 2.0, 3.0], vec![1.0], vec![]];
        let f2 = IsolationForest::fit(&ragged, 10, 8, 2);
        let _ = f2.anomaly_score(&[1.0, 2.0, 3.0]);
    }
}
