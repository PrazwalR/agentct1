import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { ResourceRegistry } from "../intent/registry.js";
import { createGuard } from "../index.js";
import { AuditLogger } from "../audit/logger.js";
import { SqliteAuditStore } from "../audit/store.js";
import type { AuditEntry, PaymentRequest, Policy } from "../types.js";
import { ViemAdapter } from "../adapters/viem.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const PAYEE = "0x1111111111111111111111111111111111111111" as Address;
const IMPOSTOR = "0x00000000000000000000000000000000dEadDEaD" as Address;

function req(over: Partial<PaymentRequest> = {}): PaymentRequest {
  return {
    intent: "weather data",
    amount: parseUnits("0.10", 6), // deliberately BELOW the LLM gate
    token: USDC,
    recipient: PAYEE,
    chain: "eip155:84532",
    agentId: "a",
    resourceUrl: "https://api.weather.example/forecast",
    ...over,
  };
}

describe("ResourceRegistry", () => {
  it("passes a host that has been paid at this address before", () => {
    const r = new ResourceRegistry();
    r.bind("https://api.weather.example/forecast", PAYEE);
    const c = r.check(req());
    expect(c.passed).toBe(true);
    expect(c.severity).toBe("info");
  });

  it("flags a familiar host that suddenly names a different payee", () => {
    // The redirected-payment signature, caught deterministically with no LLM.
    const r = new ResourceRegistry();
    r.bind("https://api.weather.example/forecast", PAYEE);
    const c = r.check(req({ recipient: IMPOSTOR }));
    expect(c.passed).toBe(false);
    expect(c.severity).toBe("critical");
    expect(c.message).toContain("api.weather.example");
  });

  it("treats a never-seen host as trust-on-first-use, not a failure", () => {
    const r = new ResourceRegistry();
    const c = r.check(req());
    expect(c.passed).toBe(true);
    expect(c.severity).toBe("warning");
    expect(c.message).toMatch(/first payment/);
  });

  it("binds per host, so one host's payee says nothing about another's", () => {
    const r = new ResourceRegistry();
    r.bind("https://api.weather.example/x", PAYEE);
    const other = r.check(req({ resourceUrl: "https://api.compute.example/y" }));
    expect(other.severity).toBe("warning"); // unknown host, not a mismatch
    expect(r.size).toBe(1);
  });

  it("matches on host only, so a different path on the same host is fine", () => {
    const r = new ResourceRegistry();
    r.bind("https://api.weather.example/forecast", PAYEE);
    const c = r.check(req({ resourceUrl: "https://api.weather.example/historical" }));
    expect(c.passed).toBe(true);
    expect(c.severity).toBe("info");
  });

  it("does not confuse a lookalike host", () => {
    const r = new ResourceRegistry();
    r.bind("https://api.weather.example/x", PAYEE);
    const c = r.check(req({ resourceUrl: "https://api.weather.example.attacker.net/x" }));
    expect(c.severity).toBe("warning"); // unknown host — must not inherit the binding
  });

  it("allows a host to legitimately have more than one payee", () => {
    const second = "0x2222222222222222222222222222222222222222" as Address;
    const r = new ResourceRegistry();
    r.bind("https://api.weather.example/x", PAYEE);
    r.bind("https://api.weather.example/x", second);
    expect(r.check(req()).passed).toBe(true);
    expect(r.check(req({ recipient: second })).passed).toBe(true);
    expect(r.check(req({ recipient: IMPOSTOR })).passed).toBe(false);
  });

  it("skips cleanly when there is no resource URL or it is unparseable", () => {
    const r = new ResourceRegistry();
    expect(r.check(req({ resourceUrl: undefined })).severity).toBe("info");
    expect(r.check(req({ resourceUrl: "not a url" })).severity).toBe("info");
  });

  it("rebuilds its bindings from settled history", () => {
    const entry = (recipient: Address, url: string): AuditEntry => ({
      id: Math.random().toString(16).slice(2),
      timestamp: Date.now(),
      agentId: "a",
      request: req({ recipient, resourceUrl: url }),
      decision: { verdict: "allow", riskScore: 0, checks: [], reason: "" },
      settlement: { success: true },
      entryHash: "0x00",
    });
    const r = new ResourceRegistry();
    r.hydrate([entry(PAYEE, "https://api.weather.example/a")]);
    expect(r.check(req()).severity).toBe("info");
    expect(r.check(req({ recipient: IMPOSTOR })).passed).toBe(false);
  });
});

describe("the guard runs the binding check at any amount", () => {
  const policy: Policy = {
    agentId: "a",
    anomalyThreshold: 0.99,
    anomalyAction: "escalate",
    rules: [],
  };

  async function guardOver(store: SqliteAuditStore) {
    return createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
      policy,
      auditStore: store,
      hydrate: true,
    });
  }

  it("blocks a redirected sub-$1 payment that the LLM gate would have skipped", async () => {
    // Seed a settled payment so the host is bound, then try to redirect it.
    const store = new SqliteAuditStore(":memory:");
    const seed = new AuditLogger(store);
    await seed.record(
      req(),
      { verdict: "allow", riskScore: 0, checks: [], reason: "ok" },
      { success: true },
    );

    const guard = await guardOver(store);
    const d = await guard.evaluate(req({ recipient: IMPOSTOR }));

    expect(d.verdict).toBe("block");
    const c = d.checks.find((x) => x.id === "intent-resource-binding");
    expect(c?.passed).toBe(false);
    expect(c?.severity).toBe("critical");
    await guard.auditLog.close();
  });

  it("still allows the bound payee", async () => {
    const store = new SqliteAuditStore(":memory:");
    const seed = new AuditLogger(store);
    await seed.record(
      req(),
      { verdict: "allow", riskScore: 0, checks: [], reason: "ok" },
      { success: true },
    );
    const guard = await guardOver(store);
    expect((await guard.evaluate(req())).verdict).toBe("allow");
    await guard.auditLog.close();
  });
});
