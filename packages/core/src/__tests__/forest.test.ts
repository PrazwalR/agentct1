import { describe, expect, it, vi } from "vitest";
import { parseUnits, type Address } from "viem";
import { IsolationForest } from "../behavioral/forest.js";
import { BehavioralScorer } from "../behavioral/isolation.js";
import type { PaymentRequest } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const known = (i: number): Address => (`0x${(i + 1).toString(16).padStart(40, "0")}`) as Address;
const FRESH = "0x00000000000000000000000000000000deAddEad" as Address;

function req(amount: bigint, recipient: Address): PaymentRequest {
  return { intent: "t", amount, token: USDC, recipient, chain: "eip155:84532", agentId: "a" };
}

describe("isolation forest", () => {
  it("scores an out-of-distribution point higher than an inlier (deterministic)", () => {
    const data: number[][] = [];
    for (let i = 0; i < 200; i++) {
      data.push([80000 + ((i * 137) % 40000), 1 + ((i * 7) % 60), (i * 5) % 24, i % 6 === 0 ? 1 : 0]);
    }
    const forest = new IsolationForest(data, { trees: 120, sampleSize: 128, seed: 42 });
    const inlier = forest.anomalyScore([100000, 30, 12, 0]);
    const outlier = forest.anomalyScore([50_000_000_000, 30, 12, 1]);
    expect(outlier).toBeGreaterThan(inlier);
    expect(outlier).toBeGreaterThan(0.6);
  });
});

describe("behavioral scorer — Isolation Forest phase 2", () => {
  it("flags a multivariate anomaly once the forest is trained", async () => {
    // Pin the clock (deterministic hour/interval; no CI flakes). Time is held
    // constant across observations, so the interval feature has no spurious
    // spread — matching steady operation rather than a tight test loop.
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T12:00:00Z"));
    try {
      const scorer = new BehavioralScorer("a", {
        forestMinObservations: 64,
        forestRetrainInterval: 10000,
        forestSampleSize: 64,
        forestTrees: 150,
        forestSeed: 7,
      });
      // Varied baseline of legitimate small payments to known APIs.
      for (let i = 0; i < 90; i++) {
        const amt = parseUnits((0.05 + (i % 20) * 0.03).toFixed(6), 6);
        await scorer.observe(req(amt, known(i % 4)));
      }
      // A payment wildly out of distribution on amount + counterparty.
      const out = await scorer.score(req(parseUnits("100000", 6), FRESH));
      expect(out.anomalyChecks.some((c) => c.id === "behavioral-multivariate-anomaly")).toBe(true);
      expect(out.score).toBeGreaterThan(0.7);
    } finally {
      vi.useRealTimers();
    }
  });
});
