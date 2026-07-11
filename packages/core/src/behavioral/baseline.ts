/**
 * Exponentially-Weighted Moving Average baselines.
 * Tracks running mean + variance per feature with recency weighting, so the
 * baseline adapts as the agent's legitimate behavior evolves but still flags
 * sudden deviations.
 */
export class EWMABaseline {
  private readonly means = new Map<string, number>();
  private readonly variances = new Map<string, number>();
  private readonly alpha: number;
  private readonly seenCounterparties = new Set<string>();
  private readonly timestamps: number[] = [];
  private readonly historicalVectors: number[][] = [];

  constructor(alpha = 0.1) {
    this.alpha = alpha; // higher = more reactive
  }

  /** Standard deviations `value` is from the running mean (0 until variance exists). */
  zScore(feature: string, value: number): number {
    const mean = this.means.get(feature);
    const variance = this.variances.get(feature);
    // `!(variance > 0)` also rejects NaN (a poisoned variance) and negatives, not just 0.
    if (mean === undefined || variance === undefined || !(variance > 0)) return 0;
    return (value - mean) / Math.sqrt(variance);
  }

  update(feature: string, value: number): void {
    const oldMean = this.means.get(feature) ?? value;
    const newMean = this.alpha * value + (1 - this.alpha) * oldMean;
    const oldVar = this.variances.get(feature) ?? 0;
    const newVar = this.alpha * (value - newMean) ** 2 + (1 - this.alpha) * oldVar;
    this.means.set(feature, newMean);
    this.variances.set(feature, newVar);
  }

  recordCounterparty(addr: string): void {
    this.seenCounterparties.add(addr.toLowerCase());
  }

  isNewCounterparty(addr: string): boolean {
    return !this.seenCounterparties.has(addr.toLowerCase());
  }

  recordTimestamp(ts: number): void {
    this.timestamps.push(ts);
    if (this.timestamps.length > 10000) this.timestamps.shift();
  }

  lastTimestamp(): number | undefined {
    return this.timestamps.at(-1);
  }

  recordVector(vector: number[]): void {
    this.historicalVectors.push(vector);
    if (this.historicalVectors.length > 10000) this.historicalVectors.shift();
  }

  getHistoricalVectors(): number[][] {
    return this.historicalVectors;
  }

}

