import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { AuditLogger, hashEntry } from "../audit/logger.js";
import { MerkleAuditBatch } from "../audit/merkle.js";
import type { AuditEntry, PaymentRequest, PolicyDecision } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const addr = (i: number): Address =>
  (`0x${(i + 1).toString(16).padStart(40, "0")}`) as Address;

function mkReq(i: number): PaymentRequest {
  return {
    intent: "buy data",
    amount: parseUnits("0.10", 6) + BigInt(i),
    token: USDC,
    recipient: addr(i),
    chain: "eip155:84532",
    agentId: "a",
  };
}

const okDecision: PolicyDecision = {
  verdict: "allow",
  riskScore: 0,
  checks: [],
  reason: "ok",
};

function mkEntry(i: number): AuditEntry {
  const request = mkReq(i);
  return {
    id: `e${i}`,
    timestamp: 1_700_000_000_000 + i,
    agentId: "a",
    request,
    decision: okDecision,
    entryHash: hashEntry(request, okDecision),
  };
}

describe("merkle batch (OZ StandardMerkleTree)", () => {
  it("produces a 32-byte root and verifies every leaf locally", () => {
    const batch = new MerkleAuditBatch();
    for (let i = 0; i < 5; i++) batch.addEntry(mkEntry(i));
    expect(batch.size()).toBe(5);
    expect(batch.root()).toMatch(/^0x[0-9a-fA-F]{64}$/);
    for (let i = 0; i < 5; i++) expect(batch.verify(i)).toBe(true);
  });

  it("verifies a single-entry batch (root == leaf, empty proof)", () => {
    const batch = new MerkleAuditBatch();
    batch.addEntry(mkEntry(0));
    expect(batch.proofAt(0)).toEqual([]);
    expect(batch.verify(0)).toBe(true);
  });
});

describe("audit logger (sqlite :memory:)", () => {
  it("records decisions and round-trips bigint amounts", async () => {
    const log = new AuditLogger(":memory:");
    await log.record(mkReq(0), okDecision);
    await log.record(mkReq(1), { ...okDecision, verdict: "block", reason: "nope" });

    const all = log.list();
    expect(all.length).toBe(2);
    expect(all[0]?.request.amount).toBe(parseUnits("0.10", 6));
    expect(all[1]?.decision.verdict).toBe("block");

    const byAgent = log.list({ agentId: "a" });
    expect(byAgent.length).toBe(2);
    log.close();
  });
});
