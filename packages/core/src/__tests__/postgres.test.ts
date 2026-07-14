import { describe, expect, it } from "vitest";
import { newDb } from "pg-mem";
import { parseUnits, type Address } from "viem";
import type { Pool } from "pg";
import { PostgresAuditStore } from "../audit/postgres-store.js";
import { AuditLogger } from "../audit/logger.js";
import type { PaymentRequest, PolicyDecision } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const okDecision: PolicyDecision = { verdict: "allow", riskScore: 0, checks: [], reason: "ok" };

function mkReq(i: number): PaymentRequest {
  return {
    intent: "buy data",
    amount: parseUnits("0.10", 6) + BigInt(i),
    token: USDC,
    recipient: `0x${(i + 1).toString(16).padStart(40, "0")}` as Address,
    chain: "eip155:84532",
    agentId: "a",
  };
}

function inMemoryPool(): Pool {
  const db = newDb();
  const { Pool } = db.adapters.createPg();
  return new Pool() as unknown as Pool;
}

describe("postgres audit store (pg-mem)", () => {
  it("records, lists in order, round-trips bigint amounts", async () => {
    const log = new AuditLogger(new PostgresAuditStore(inMemoryPool()));
    await log.record(mkReq(0), okDecision);
    await log.record(mkReq(1), { ...okDecision, verdict: "block", reason: "nope" });

    const all = await log.list();
    expect(all.length).toBe(2);
    expect(all[0]?.request.amount).toBe(parseUnits("0.10", 6));
    expect(all[1]?.decision.verdict).toBe("block");

    const byAgent = await log.list({ agentId: "a" });
    expect(byAgent.length).toBe(2);
    await log.close();
  });

  it("supports batch marking + proof lookup over the store", async () => {
    const store = new PostgresAuditStore(inMemoryPool());
    const entry = {
      id: "e1",
      timestamp: Date.now(),
      agentId: "a",
      request: mkReq(0),
      decision: okDecision,
      entryHash: "0x".padEnd(66, "0") as `0x${string}`,
    };
    await store.insert(entry);
    expect((await store.unbatched()).length).toBe(1);
    await store.markBatched(["e1"], 0);
    expect((await store.unbatched()).length).toBe(0);
    expect((await store.entriesInBatch(0)).length).toBe(1);
    expect((await store.getById("e1"))?.batchIndex).toBe(0);
    await store.close();
  });
});
