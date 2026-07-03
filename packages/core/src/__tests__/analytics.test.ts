import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { report } from "../analytics.js";
import { hashEntry } from "../audit/logger.js";
import type { AuditEntry, PaymentRequest, PolicyCheck, Verdict } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const A = "0x1111111111111111111111111111111111111111" as Address;
const B = "0x2222222222222222222222222222222222222222" as Address;

function mk(
  i: number,
  amountUsd: string,
  recipient: Address,
  verdict: Verdict,
  settled: boolean,
  anomaly = false,
): AuditEntry {
  const request: PaymentRequest = {
    intent: "x",
    amount: parseUnits(amountUsd, 6),
    token: USDC,
    recipient,
    chain: "eip155:84532",
    agentId: "a",
  };
  const checks: PolicyCheck[] = anomaly
    ? [{ id: "behavioral-amount-spike", passed: false, severity: "warning", message: "x" }]
    : [];
  const decision = { verdict, riskScore: 0, checks, reason: "" };
  return {
    id: `e${i}`,
    timestamp: 1000 + i,
    agentId: "a",
    request,
    decision,
    settlement: settled ? { success: true } : undefined,
    entryHash: hashEntry(request, decision),
  };
}

describe("report", () => {
  const entries: AuditEntry[] = [
    mk(0, "0.50", A, "allow", true),
    mk(1, "2", A, "allow", true),
    mk(2, "10", B, "allow", true, true), // anomaly
    mk(3, "15", B, "escalate", false),
    mk(4, "100", B, "block", false),
  ];

  it("aggregates verdicts, settled spend, counterparties, anomalies", () => {
    const r = report(entries, { topN: 5 });
    expect(r.total).toBe(5);
    expect(r.verdicts).toEqual({ allow: 3, block: 1, escalate: 1 });
    expect(r.settled).toBe(3);
    expect(r.anomalies).toBe(1);
    // settled spend: 0.5 + 2 (A) + 10 (B) = 12.5 USDC
    expect(r.totalSpendByToken[USDC.toLowerCase()]).toBe(parseUnits("12.5", 6).toString());
    // top by settled spend: B ($10) over A ($2.5)
    expect(r.topCounterparties[0]?.recipient).toBe(B.toLowerCase());
    expect(r.topCounterparties[0]?.totalSpend).toBe(parseUnits("10", 6).toString());
    expect(r.blockRate).toBeCloseTo(0.2);
    expect(r.escalateRate).toBeCloseTo(0.2);
  });

  it("handles an empty log", () => {
    const r = report([]);
    expect(r.total).toBe(0);
    expect(r.blockRate).toBe(0);
    expect(r.topCounterparties).toEqual([]);
  });
});
