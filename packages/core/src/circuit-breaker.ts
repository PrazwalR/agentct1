import type { Verdict } from "./types.js";

export interface CircuitBreakerConfig {
  /** Sliding window (seconds) over which failures are counted. */
  windowSeconds: number;
  /** Trip if this many payments are blocked in the window. */
  maxBlocks?: number;
  /** Trip if this many payments are escalated in the window. */
  maxEscalations?: number;
  /** Trip if this many payments fire a behavioral anomaly in the window. */
  maxAnomalies?: number;
  /** Auto-close after this long open. Omit/0 → stays open until reset() (manual). */
  cooldownSeconds?: number;
}

interface BreakerEvent {
  ts: number;
  verdict: Verdict;
  anomaly: boolean;
}

export type CircuitState = "open" | "closed";

/**
 * Per-agent circuit breaker. A per-payment guard evaluates each request in
 * isolation; this catches the *aggregate* signature of a compromised agent — a
 * burst of blocks, escalations, or anomalies — and freezes ALL of that agent's
 * payments until a human reset() (or an optional cooldown). This is the kill
 * switch for "the agent is behaving badly, stop everything."
 */
export class CircuitBreaker {
  private events: BreakerEvent[] = [];
  private openedAt?: number;

  constructor(private readonly cfg: CircuitBreakerConfig) {}

  /** Whether the agent is currently frozen (auto-closes after cooldown if set). */
  isOpen(now = Date.now()): boolean {
    if (this.openedAt === undefined) return false;
    if (
      this.cfg.cooldownSeconds !== undefined &&
      this.cfg.cooldownSeconds > 0 &&
      now - this.openedAt >= this.cfg.cooldownSeconds * 1000
    ) {
      this.reset();
      return false;
    }
    return true;
  }

  state(now = Date.now()): CircuitState {
    return this.isOpen(now) ? "open" : "closed";
  }

  /** Record a real payment decision; trips the breaker if a threshold is exceeded. */
  record(verdict: Verdict, anomaly: boolean, now = Date.now()): void {
    this.events.push({ ts: now, verdict, anomaly });
    this.prune(now);
    if (this.openedAt === undefined && this.shouldTrip()) {
      this.openedAt = now;
    }
  }

  /** Manually close the breaker and clear its history (human intervention). */
  reset(): void {
    this.openedAt = undefined;
    this.events = [];
  }

  /** Current window counts (for reporting / CLI). */
  counts(now = Date.now()): { blocks: number; escalations: number; anomalies: number } {
    this.prune(now);
    return {
      blocks: this.events.filter((e) => e.verdict === "block").length,
      escalations: this.events.filter((e) => e.verdict === "escalate").length,
      anomalies: this.events.filter((e) => e.anomaly).length,
    };
  }

  private prune(now: number): void {
    const cutoff = now - this.cfg.windowSeconds * 1000;
    this.events = this.events.filter((e) => e.ts > cutoff);
  }

  private shouldTrip(): boolean {
    const c = {
      blocks: this.events.filter((e) => e.verdict === "block").length,
      escalations: this.events.filter((e) => e.verdict === "escalate").length,
      anomalies: this.events.filter((e) => e.anomaly).length,
    };
    return (
      (this.cfg.maxBlocks !== undefined && c.blocks >= this.cfg.maxBlocks) ||
      (this.cfg.maxEscalations !== undefined && c.escalations >= this.cfg.maxEscalations) ||
      (this.cfg.maxAnomalies !== undefined && c.anomalies >= this.cfg.maxAnomalies)
    );
  }
}
