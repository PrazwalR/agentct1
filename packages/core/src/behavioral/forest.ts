/**
 * Isolation Forest — unsupervised multivariate anomaly detection.
 *
 * Anomalies are "few and different", so a random binary partitioning isolates
 * them with a shorter expected path length than normal points. The score is
 * 2^(-E[h(x)] / c(n)): near 1 = anomaly, near 0.5 = normal. Scale-invariant per
 * feature (each split is drawn within that feature's own observed range), so the
 * raw [amount, interval, hour, isNew] vectors need no normalization.
 *
 * Deterministic via a seedable RNG so behavioral scoring is reproducible.
 */

export interface ForestOptions {
  trees?: number;
  sampleSize?: number;
  seed?: number;
}

type Node = { leaf: true; size: number } | { leaf: false; f: number; v: number; l: Node; r: Node };

/** mulberry32 — small deterministic PRNG. */
function mulberry32(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Average path length of an unsuccessful BST search over n points. */
function c(n: number): number {
  if (n <= 1) return 0;
  const H = Math.log(n - 1) + 0.5772156649; // Euler–Mascheroni
  return 2 * H - (2 * (n - 1)) / n;
}

function subsample(data: number[][], k: number, rng: () => number): number[][] {
  if (data.length <= k) return data;
  const out: number[][] = [];
  for (let i = 0; i < k; i++) {
    const row = data[Math.floor(rng() * data.length)];
    if (row) out.push(row);
  }
  return out;
}

function buildTree(data: number[][], depth: number, maxDepth: number, rng: () => number): Node {
  const n = data.length;
  const dims = data[0]?.length ?? 0;
  if (depth >= maxDepth || n <= 1 || dims === 0) return { leaf: true, size: n };

  // Only split on features that actually vary in this node — picking a constant
  // feature would waste the split and prematurely terminate the tree, which
  // washes out the anomaly signal when several features are near-constant.
  const ranges: Array<{ f: number; min: number; max: number }> = [];
  for (let f = 0; f < dims; f++) {
    let min = Infinity;
    let max = -Infinity;
    for (const row of data) {
      const x = row[f] ?? 0;
      if (x < min) min = x;
      if (x > max) max = x;
    }
    if (max > min) ranges.push({ f, min, max });
  }
  if (ranges.length === 0) return { leaf: true, size: n };

  const pick = ranges[Math.floor(rng() * ranges.length)]!;
  const v = pick.min + rng() * (pick.max - pick.min);
  const left: number[][] = [];
  const right: number[][] = [];
  for (const row of data) ((row[pick.f] ?? 0) < v ? left : right).push(row);

  return {
    leaf: false,
    f: pick.f,
    v,
    l: buildTree(left, depth + 1, maxDepth, rng),
    r: buildTree(right, depth + 1, maxDepth, rng),
  };
}

function pathLength(x: number[], node: Node, depth: number): number {
  if (node.leaf) return depth + c(node.size);
  return pathLength(x, (x[node.f] ?? 0) < node.v ? node.l : node.r, depth + 1);
}

export class IsolationForest {
  private readonly trees: Node[] = [];
  private readonly sampleSize: number;

  constructor(data: number[][], opts: ForestOptions = {}) {
    const rng = mulberry32(opts.seed ?? 1337);
    const treeCount = opts.trees ?? 100;
    this.sampleSize = Math.max(1, Math.min(opts.sampleSize ?? 256, data.length));
    const maxDepth = Math.ceil(Math.log2(Math.max(2, this.sampleSize)));
    for (let i = 0; i < treeCount; i++) {
      this.trees.push(buildTree(subsample(data, this.sampleSize, rng), 0, maxDepth, rng));
    }
  }

  /** Anomaly score in [0,1]; higher = more anomalous. */
  anomalyScore(x: number[]): number {
    if (this.trees.length === 0) return 0;
    let sum = 0;
    for (const tree of this.trees) sum += pathLength(x, tree, 0);
    const mean = sum / this.trees.length;
    const cn = c(this.sampleSize);
    return cn === 0 ? 0 : 2 ** (-mean / cn);
  }
}
