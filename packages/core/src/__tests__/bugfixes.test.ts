import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { aggregateVerdict } from "../index.js";
import { PolicyEvaluator } from "../policy/evaluator.js";
import { usdToTokenUnits } from "../constants.js";
import { InFlightNonceTracker } from "../x402/eip3009.js";
import { EWMABaseline } from "../behavioral/baseline.js";
import type { PaymentRequest, Policy, PolicyCheck } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const A = "0x0000000000000000000000000000000000000001" as Address;

const failing = (id: string, severity: PolicyCheck["severity"]): PolicyCheck => ({
  id,
  passed: false,
  severity,
  message: "x",
});

// ─── bug #6: behavioral-critical honors anomalyAction ────────────────────────
describe("aggregateVerdict", () => {
  const base = { anomalyThreshold: 0.8, policyEscalate: false };

  it("routes a behavioral-critical to escalate when anomalyAction=escalate", () => {
    expect(
      aggregateVerdict([failing("behavioral-amount-spike", "critical")], 0, {
        ...base,
        anomalyAction: "escalate",
      }),
    ).toBe("escalate");
  });

  it("routes a behavioral-critical to block when anomalyAction=block", () => {
    expect(
      aggregateVerdict([failing("behavioral-amount-spike", "critical")], 0, {
        ...base,
        anomalyAction: "block",
      }),
    ).toBe("block");
  });

  it("always hard-blocks a policy/intent critical regardless of anomalyAction", () => {
    expect(
      aggregateVerdict([failing("allowlist-recipients", "critical")], 0, {
        ...base,
        anomalyAction: "escalate",
      }),
    ).toBe("block");
    expect(
      aggregateVerdict([failing("intent-reconcile", "critical")], 0, {
        ...base,
        anomalyAction: "escalate",
      }),
    ).toBe("block");
  });

  it("escalates on policyEscalate and allows when nothing fires", () => {
    expect(aggregateVerdict([], 0, { ...base, anomalyAction: "escalate", policyEscalate: true })).toBe(
      "escalate",
    );
    expect(aggregateVerdict([], 0, { ...base, anomalyAction: "escalate" })).toBe("allow");
  });
});

// ─── bug #3: empty allowlist entry must not match every URL ───────────────────
describe("allowlist empty-entry bypass", () => {
  const policy = (entries: string[]): Policy => ({
    agentId: "a",
    anomalyThreshold: 0.8,
    anomalyAction: "escalate",
    rules: [{ type: "allowlist", mode: "resources", entries, enforce: true }],
  });
  const req = (url: string): PaymentRequest => ({
    intent: "x",
    amount: 1n,
    token: USDC,
    recipient: A,
    chain: "eip155:84532",
    agentId: "a",
    resourceUrl: url,
  });

  it("does not let an empty entry allow an arbitrary URL", async () => {
    const ev = new PolicyEvaluator(policy(["api.trusted.com", ""]));
    const r = await ev.evaluate(req("https://attacker.example/drain"));
    expect(r.checks.find((c) => c.id === "allowlist-resources")?.severity).toBe("critical");
  });

  it("still allows a genuinely listed resource", async () => {
    const ev = new PolicyEvaluator(policy(["api.trusted.com"]));
    const r = await ev.evaluate(req("https://api.trusted.com/data"));
    expect(r.checks.find((c) => c.id === "allowlist-resources")?.passed).toBe(true);
  });
});

// ─── bug #5: parseUnits scientific-notation crash ─────────────────────────────
describe("usdToTokenUnits", () => {
  it("handles tiny/huge amounts without throwing and converts normal ones", () => {
    expect(() => usdToTokenUnits(0.0000001)).not.toThrow();
    expect(usdToTokenUnits(0.0000001)).toBe(0n);
    expect(() => usdToTokenUnits(1e21)).not.toThrow();
    expect(usdToTokenUnits(0.1)).toBe(parseUnits("0.1", 6));
    expect(usdToTokenUnits(33.33)).toBe(parseUnits("33.33", 6));
    expect(usdToTokenUnits("50")).toBe(parseUnits("50", 6));
  });
});

// ─── bug #7: in-flight nonce tracking ─────────────────────────────────────────
describe("InFlightNonceTracker", () => {
  it("reserves unique nonces and releases them", () => {
    const t = new InFlightNonceTracker();
    const a = t.reserve();
    const b = t.reserve();
    expect(a).not.toBe(b);
    expect(t.size).toBe(2);
    expect(t.has(a)).toBe(true);
    t.release(a);
    expect(t.has(a)).toBe(false);
    expect(t.size).toBe(1);
  });

  it("regenerates when a supplied nonce is already in flight", () => {
    const t = new InFlightNonceTracker();
    const n = t.reserve();
    expect(t.reserve(n)).not.toBe(n);
  });
});

// ─── bug #9: NaN variance + bug #10: time-window start===end ──────────────────
describe("defensive guards", () => {
  it("zScore returns 0 when variance is NaN (does not poison riskScore)", () => {
    const b = new EWMABaseline();
    b.update("amount", Number.POSITIVE_INFINITY); // variance -> NaN
    b.update("amount", 100);
    expect(Number.isNaN(b.zScore("amount", 100))).toBe(false);
    expect(b.zScore("amount", 100)).toBe(0);
  });

  it("time-window with start===end means 24h allowed, not always-blocked", async () => {
    const ev = new PolicyEvaluator({
      agentId: "a",
      anomalyThreshold: 0.8,
      anomalyAction: "escalate",
      rules: [{ type: "time-window", allowedHours: [12, 12], action: "block" }],
    });
    const r = await ev.evaluate({
      intent: "x",
      amount: 1n,
      token: USDC,
      recipient: A,
      chain: "eip155:84532",
      agentId: "a",
    });
    expect(r.checks.find((c) => c.id === "time-window")?.passed).toBe(true);
  });
});
