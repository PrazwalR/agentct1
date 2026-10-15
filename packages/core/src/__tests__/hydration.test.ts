import { afterEach, describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { createGuard } from "../index.js";
import { ViemAdapter } from "../adapters/viem.js";
import { AuditLogger, recomputeEntryHash } from "../audit/logger.js";
import { SqliteAuditStore } from "../audit/store.js";
import { PolicyEvaluator } from "../policy/evaluator.js";
import { BehavioralScorer } from "../behavioral/isolation.js";
import { CircuitBreaker } from "../circuit-breaker.js";
import type { AuditEntry, PaymentRequest, Policy, PolicyCheck, Verdict } from "../types.js";

/**
 * Enforcement state used to live only in memory, so "max $20/day" silently reset on
 * every restart and was never actually enforced. These cover the rebuild-from-audit-log
 * path that closes that.
 */

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const KNOWN = "0x1111111111111111111111111111111111111111" as Address;
const AGENT = "hydration-agent";

const HOUR = 3_600_000;

function req(amountUsd: string, recipient: Address = KNOWN): PaymentRequest {
  return {
    intent: "t",
    amount: parseUnits(amountUsd, 6),
    token: USDC,
    recipient,
    chain: "eip155:84532",
    agentId: AGENT,
  };
}

function entry(
  amountUsd: string,
  agoMs: number,
  opts: { verdict?: Verdict; settled?: boolean; recipient?: Address; checks?: PolicyCheck[] } = {},
): AuditEntry {
  const request = req(amountUsd, opts.recipient);
  const verdict = opts.verdict ?? "allow";
  return {
    id: `${amountUsd}-${agoMs}-${Math.random()}`,
    timestamp: Date.now() - agoMs,
    agentId: AGENT,
    request,
    decision: { verdict, riskScore: 0, checks: opts.checks ?? [], reason: "" },
    settlement: (opts.settled ?? true) ? { success: true } : undefined,
    entryHash: "0x00",
  };
}

const dayCap: Policy = {
  agentId: AGENT,
  anomalyThreshold: 0.8,
  anomalyAction: "escalate",
  rules: [{ type: "spend-cap", window: "day", maxAmount: parseUnits("20", 6), token: USDC }],
};

describe("PolicyEvaluator.hydrate", () => {
  it("rebuilds the daily window so a restart does not reset the cap", async () => {
    const ev = new PolicyEvaluator(dayCap);
    ev.hydrate([entry("18", 2 * HOUR)]);
    // 18 already spent today + 5 more > the 20 cap.
    const check = (await ev.evaluate(req("5"))).checks.find((c) => c.id === "spend-cap-day");
    expect(check?.passed).toBe(false);
    expect(check?.severity).toBe("critical");
  });

  it("ignores spend older than the longest window", async () => {
    const ev = new PolicyEvaluator(dayCap);
    ev.hydrate([entry("18", 30 * HOUR)]); // yesterday — cannot affect a day window
    expect((await ev.evaluate(req("5"))).checks.find((c) => c.id === "spend-cap-day")?.passed).toBe(
      true,
    );
  });

  it("restores counterparty memory from the full history", async () => {
    const policy: Policy = {
      ...dayCap,
      rules: [{ type: "counterparty", flagNewRecipients: true, action: "escalate" }],
    };
    const fresh = new PolicyEvaluator(policy);
    expect((await fresh.evaluate(req("1"))).escalate).toBe(true); // cold: unknown recipient

    const hydrated = new PolicyEvaluator(policy);
    // Deliberately older than the spend window — recognizing a past counterparty
    // must not expire with the rolling cap.
    hydrated.hydrate([entry("1", 60 * 24 * HOUR)]);
    expect((await hydrated.evaluate(req("1"))).escalate).toBe(false);
  });

  it("keeps the `session` window process-scoped, not all-of-history", async () => {
    const sessionCap: Policy = {
      ...dayCap,
      rules: [
        { type: "spend-cap", window: "session", maxAmount: parseUnits("20", 6), token: USDC },
      ],
    };
    const ev = new PolicyEvaluator(sessionCap);
    ev.hydrate([entry("18", 1 * HOUR)]);
    // Replayed spend does not count against this session…
    expect(
      (await ev.evaluate(req("5"))).checks.find((c) => c.id === "spend-cap-session")?.passed,
    ).toBe(true);
    // …but spend observed in this process does.
    ev.observe(req("18"));
    expect(
      (await ev.evaluate(req("5"))).checks.find((c) => c.id === "spend-cap-session")?.passed,
    ).toBe(false);
  });
});

describe("BehavioralScorer.hydrate", () => {
  it("replays history at real timestamps so the baseline is warm on startup", async () => {
    const cold = new BehavioralScorer(AGENT);
    expect((await cold.score(req("100"))).score).toBe(0); // cold start, no signal

    const warm = new BehavioralScorer(AGENT);
    const history = ["0.08", "0.12", "0.09", "0.11", "0.10", "0.13", "0.07", "0.10"].map((a, i) =>
      entry(a, (10 - i) * HOUR),
    );
    await warm.hydrate(history);

    const result = await warm.score(req("100")); // ~1000x the replayed norm
    expect(result.score).toBeGreaterThan(0);
    expect(result.anomalyChecks.some((c) => c.id === "behavioral-amount-spike")).toBe(true);
  });

  it("recognizes a counterparty seen only in replayed history", async () => {
    const s = new BehavioralScorer(AGENT);
    await s.hydrate([entry("0.10", 5 * HOUR)]);
    const seen = await s.score(req("0.10", KNOWN));
    expect(seen.anomalyChecks.some((c) => c.id === "behavioral-new-counterparty")).toBe(false);

    const other = "0x2222222222222222222222222222222222222222" as Address;
    const fresh = await s.score(req("0.10", other));
    expect(fresh.anomalyChecks.some((c) => c.id === "behavioral-new-counterparty")).toBe(true);
  });
});

describe("CircuitBreaker.hydrate", () => {
  const blocked = (agoMs: number) => entry("1", agoMs, { verdict: "block", settled: false });

  it("stays frozen across a restart when the window already tripped", () => {
    const b = new CircuitBreaker({ windowSeconds: 3600, maxBlocks: 2 });
    expect(b.state()).toBe("closed");
    b.hydrate([blocked(10 * 60_000), blocked(5 * 60_000)]);
    expect(b.state()).toBe("open");
    expect(b.counts().blocks).toBe(2);
  });

  it("ignores events that have aged out of the window", () => {
    const b = new CircuitBreaker({ windowSeconds: 600, maxBlocks: 2 });
    b.hydrate([blocked(5 * HOUR), blocked(4 * HOUR)]);
    expect(b.state()).toBe("closed");
  });

  it("counts behavioral anomalies the same way the live path does", () => {
    const anomalous = entry("1", 60_000, {
      verdict: "escalate",
      settled: false,
      checks: [{ id: "behavioral-amount-spike", passed: false, severity: "warning", message: "x" }],
    });
    const b = new CircuitBreaker({ windowSeconds: 3600, maxAnomalies: 1 });
    b.hydrate([anomalous]);
    expect(b.counts().anomalies).toBe(1);
    expect(b.state()).toBe("open");
  });
});

describe("AgentGuard hydration end-to-end", () => {
  const stores: AuditLogger[] = [];
  afterEach(async () => {
    for (const s of stores) await s.close();
    stores.length = 0;
  });

  async function guardOver(store: SqliteAuditStore, hydrate = true) {
    const guard = await createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
      policy: dayCap,
      auditStore: store,
      hydrate,
    });
    return guard;
  }

  it("a second guard over the same store enforces spend the first one recorded", async () => {
    // One shared store stands in for "the process restarted".
    const store = new SqliteAuditStore(":memory:");
    const seed = new AuditLogger(store);
    stores.push(seed);
    await seed.record(
      req("18"),
      { verdict: "allow", riskScore: 0, checks: [], reason: "" },
      {
        success: true,
      },
    );

    const cold = await guardOver(store, false);
    expect((await cold.evaluate(req("5"))).verdict).toBe("allow"); // no history → allowed

    const warm = await guardOver(store, true);
    expect((await warm.evaluate(req("5"))).verdict).toBe("block"); // 18 + 5 > 20
  });

  it("degrades to a cold start rather than throwing when history is unreadable", async () => {
    const broken = {
      listSince: () => Promise.reject(new Error("store offline")),
      close: () => Promise.resolve(),
    } as unknown as SqliteAuditStore;
    const guard = await guardOver(broken, true);
    expect((await guard.evaluate(req("5"))).verdict).toBe("allow");
  });
});

// ── hydration must not trust unverified rows ───────────────────────────────

describe("hydration verifies row integrity before trusting it", () => {
  /**
   * Spend windows are rebuilt from rows claiming `settlement.success`. Before this,
   * an attacker with database write access and no keys could flip today's
   * settlements to false and the daily budget would reset on the next restart,
   * letting the agent spend the cap a second time. Enforcement state has to be as
   * tamper-evident as the audit trail it is derived from.
   */
  async function seedStore(): Promise<{ store: SqliteAuditStore; original: AuditEntry }> {
    const store = new SqliteAuditStore(":memory:");
    const log = new AuditLogger(store);
    const original = await log.record(
      req("18"),
      { verdict: "allow", riskScore: 0, checks: [], reason: "ok" },
      { success: true },
    );
    return { store, original };
  }

  async function guardOn(store: SqliteAuditStore) {
    return createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
      policy: dayCap,
      auditStore: store,
      hydrate: true,
    });
  }

  it("reports a clean log as untampered", async () => {
    const { store } = await seedStore();
    const guard = await guardOn(store);
    expect(guard.hydrationReport?.tampered).toBe(0);
    expect(guard.hydrationReport?.settled).toBe(1);
    await guard.auditLog.close();
  });

  it("still counts a row whose settled flag was flipped, so the budget cannot reset", async () => {
    const { store, original } = await seedStore();
    // The attack: claim it never settled, leaving entry_hash untouched.
    await store.insert({
      ...original,
      id: "flipped",
      settlement: { success: false },
      entryHash: original.entryHash,
    });

    const guard = await guardOn(store);
    expect(guard.hydrationReport?.tampered).toBeGreaterThan(0);
    expect(guard.hydrationReport?.tamperedIds).toContain("flipped");

    // 18 intact + 18 counted conservatively is already past the 20 cap.
    expect((await guard.evaluate(req("5"))).verdict).toBe("block");
    await guard.auditLog.close();
  });

  it("keeps a tampered row out of the baseline and the payee bindings", async () => {
    const { store, original } = await seedStore();
    await store.insert({
      ...original,
      id: "poison",
      request: { ...original.request, amount: parseUnits("999999", 6) },
      entryHash: original.entryHash,
    });
    const guard = await guardOn(store);
    expect(guard.hydrationReport?.tamperedIds).toContain("poison");
    // An edited row must not get to define what "normal" looks like.
    expect(guard.resourceRegistry.size).toBe(0);
    await guard.auditLog.close();
  });

  it("recomputeEntryHash detects an edit the stored column hides", async () => {
    const { original } = await seedStore();
    expect(recomputeEntryHash(original)).toBe(original.entryHash);
    const edited = { ...original, settlement: { success: false } };
    expect(recomputeEntryHash(edited)).not.toBe(edited.entryHash);
  });
});
