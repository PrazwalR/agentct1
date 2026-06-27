import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { BehavioralScorer } from "../behavioral/isolation.js";
import type { PaymentRequest } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const A = "0x1111111111111111111111111111111111111111" as Address;
const B = "0x2222222222222222222222222222222222222222" as Address;

function req(amount: string, recipient: Address): PaymentRequest {
  return {
    intent: "t",
    amount: parseUnits(amount, 6),
    token: USDC,
    recipient,
    chain: "eip155:84532",
    agentId: "a",
  };
}

describe("behavioral scorer", () => {
  it("scores 0 on cold start with no checks", async () => {
    const s = new BehavioralScorer("a");
    const r = await s.score(req("0.10", A));
    expect(r.score).toBe(0);
    expect(r.anomalyChecks.length).toBe(0);
  });

  it("flags an amount spike against an established baseline", async () => {
    const s = new BehavioralScorer("a");
    for (const a of ["0.08", "0.12", "0.09", "0.11", "0.10", "0.13", "0.07", "0.10"]) {
      await s.observe(req(a, A));
    }
    const r = await s.score(req("100", A)); // ~1000x the norm
    expect(r.score).toBeGreaterThan(0);
    expect(r.anomalyChecks.some((c) => c.id === "behavioral-amount-spike")).toBe(true);
  });

  it("flags a never-seen counterparty once the agent has history", async () => {
    const s = new BehavioralScorer("a");
    await s.observe(req("0.10", A));
    const r = await s.score(req("0.10", B));
    expect(r.anomalyChecks.some((c) => c.id === "behavioral-new-counterparty")).toBe(true);
  });
});
