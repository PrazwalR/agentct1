import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { simulatePolicy } from "../policy/simulate.js";
import { hashEntry } from "../audit/logger.js";
import type { AuditEntry, PaymentRequest, Policy, Verdict } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const A = "0x1111111111111111111111111111111111111111" as Address;

function entry(i: number, amountUsd: string, verdict: Verdict): AuditEntry {
  const request: PaymentRequest = {
    intent: "x",
    amount: parseUnits(amountUsd, 6),
    token: USDC,
    recipient: A,
    chain: "eip155:84532",
    agentId: "a",
  };
  const decision = { verdict, riskScore: 0, checks: [], reason: "" };
  return {
    id: `e${i}`,
    timestamp: 1_700_000_000_000 + i * 1000,
    agentId: "a",
    request,
    decision,
    settlement: verdict === "allow" ? { success: true } : undefined,
    entryHash: hashEntry(request, decision),
  };
}

const history: AuditEntry[] = [
  entry(0, "0.50", "allow"),
  entry(1, "1", "allow"),
  entry(2, "30", "allow"),
];

const policy = (rules: Policy["rules"]): Policy => ({
  agentId: "a",
  anomalyThreshold: 0.8,
  anomalyAction: "escalate",
  rules,
});

describe("simulatePolicy", () => {
  it("flags a payment a tighter daily cap would newly block", async () => {
    const r = await simulatePolicy(
      history,
      policy([{ type: "spend-cap", window: "day", maxAmount: parseUnits("20", 6), token: USDC }]),
    );
    expect(r.total).toBe(3);
    expect(r.newlyBlocked).toBe(1); // cumulative 31.5 > 20 on the $30 payment
    expect(r.entries.find((e) => e.changed)?.simulatedVerdict).toBe("block");
  });

  it("flags a payment an escalateAbove threshold would newly escalate", async () => {
    const r = await simulatePolicy(
      history,
      policy([
        {
          type: "spend-cap",
          window: "day",
          maxAmount: parseUnits("100", 6),
          escalateAbove: parseUnits("2", 6),
          token: USDC,
        },
      ]),
    );
    expect(r.newlyEscalated).toBe(1); // only the $30 payment exceeds $2
  });

  it("reports no change when the candidate matches recorded allows", async () => {
    const r = await simulatePolicy(history, policy([]));
    expect(r.changed).toBe(0);
  });
});
