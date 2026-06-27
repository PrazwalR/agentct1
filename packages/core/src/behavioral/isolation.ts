import type { PaymentRequest, PolicyCheck } from "../types.js";
import { EWMABaseline } from "./baseline.js";
import { extractFeatures } from "./features.js";
import { IsolationForest } from "./forest.js";

export interface BehavioralResult {
  /** Aggregate anomaly score 0-1. */
  score: number;
  anomalyChecks: PolicyCheck[];
}

export interface BehavioralOptions {
  /** Observations before the Isolation Forest activates (default 1000). */
  forestMinObservations?: number;
  /** Retrain the forest every N observations past the minimum (default 500). */
  forestRetrainInterval?: number;
  forestTrees?: number;
  forestSampleSize?: number;
  forestSeed?: number;
}

const DEFAULT_MIN = 1000;
const DEFAULT_INTERVAL = 500;

/**
 * Behavioral anomaly detection for agent spending.
 *
 *   Phase 1 (cold start): EWMA baselines on amount / interval / counterparty
 *     novelty. With little data variance is undefined → z-scores 0 → score 0
 *     (honest cold start).
 *   Phase 2 (enough data): an Isolation Forest over the full feature vector
 *     catches multivariate anomalies a single-feature baseline misses — e.g. a
 *     normal amount, to a new address, at an unusual hour: each feature alone is
 *     fine, the combination is not.
 *
 * Deliberately NOT an LLM — runs inline on every payment in single-digit ms.
 */
export class BehavioralScorer {
  private readonly baseline = new EWMABaseline();
  private observationCount = 0;
  private forest?: IsolationForest;

  constructor(
    private readonly agentId: string,
    private readonly opts: BehavioralOptions = {},
  ) {}

  private get minObservations(): number {
    return this.opts.forestMinObservations ?? DEFAULT_MIN;
  }

  async score(req: PaymentRequest): Promise<BehavioralResult> {
    const f = extractFeatures(req, this.baseline);
    const checks: PolicyCheck[] = [];

    const amountZ = this.baseline.zScore("amount", f.amount);
    const intervalZ = this.baseline.zScore("interval", f.secondsSinceLast);

    if (Math.abs(amountZ) > 3) {
      checks.push({
        id: "behavioral-amount-spike",
        passed: false,
        severity: Math.abs(amountZ) > 5 ? "critical" : "warning",
        message: `payment amount is ${amountZ.toFixed(1)}σ from this agent's norm`,
      });
    }
    if (intervalZ < -3) {
      checks.push({
        id: "behavioral-frequency-spike",
        passed: false,
        severity: "warning",
        message: `paying ${Math.abs(intervalZ).toFixed(1)}σ more frequently than baseline`,
      });
    }
    if (f.isNewCounterparty && this.observationCount > 0) {
      checks.push({
        id: "behavioral-new-counterparty",
        passed: false,
        severity: "warning",
        message: `first payment ever to ${req.recipient.slice(0, 10)}…`,
      });
    }

    let forestScore = 0;
    if (this.forest && this.observationCount >= this.minObservations) {
      forestScore = this.forest.anomalyScore(f.vector);
      if (forestScore > 0.7) {
        checks.push({
          id: "behavioral-multivariate-anomaly",
          passed: false,
          severity: forestScore > 0.85 ? "critical" : "warning",
          message: `multivariate anomaly score ${forestScore.toFixed(2)} — unusual combination of amount, timing, and counterparty`,
        });
      }
    }

    const featureScore = Math.min(1, (Math.abs(amountZ) + Math.abs(Math.min(0, intervalZ))) / 10);
    const score = Math.max(featureScore, forestScore);
    return { score, anomalyChecks: checks };
  }

  /** Record a payment as legitimate, updating the baseline + (re)training the forest. */
  async observe(req: PaymentRequest): Promise<void> {
    const f = extractFeatures(req, this.baseline);
    this.baseline.update("amount", f.amount);
    if (this.observationCount > 0) this.baseline.update("interval", f.secondsSinceLast);
    this.baseline.recordCounterparty(req.recipient);
    this.baseline.recordTimestamp(Date.now());
    this.baseline.recordVector(f.vector);
    this.observationCount++;

    const interval = this.opts.forestRetrainInterval ?? DEFAULT_INTERVAL;
    const min = this.minObservations;
    if (
      this.observationCount >= min &&
      (this.observationCount === min || this.observationCount % interval === 0)
    ) {
      this.forest = new IsolationForest(this.baseline.getHistoricalVectors(), {
        trees: this.opts.forestTrees,
        sampleSize: this.opts.forestSampleSize,
        seed: this.opts.forestSeed,
      });
    }
  }
}
