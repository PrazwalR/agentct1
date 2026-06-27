import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { PolicyEvaluator } from "../policy/evaluator.js";
import { createGuard } from "../index.js";
import { ViemAdapter } from "../adapters/viem.js";
import type { PaymentRequest, Policy } from "../types.js";

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

function policy(rules: Policy["rules"]): Policy {
  return { agentId: "a", rules, anomalyThreshold: 0.8, anomalyAction: "escalate" };
}

describe("policy evaluator", () => {
  it("blocks over the daily cap", async () => {
    const ev = new PolicyEvaluator(
      policy([{ type: "spend-cap", window: "day", maxAmount: parseUnits("20", 6), token: USDC }]),
    );
    const r = await ev.evaluate(req("25", A));
    expect(r.checks.find((c) => c.id === "spend-cap-day")?.severity).toBe("critical");
  });

  it("escalates above escalateAbove threshold", async () => {
    const ev = new PolicyEvaluator(
      policy([
        {
          type: "spend-cap",
          window: "day",
          maxAmount: parseUnits("20", 6),
          escalateAbove: parseUnits("2", 6),
          token: USDC,
        },
      ]),
    );
    expect((await ev.evaluate(req("15", A))).escalate).toBe(true);
  });

  it("accumulates daily spend across observed payments", async () => {
    const ev = new PolicyEvaluator(
      policy([{ type: "spend-cap", window: "day", maxAmount: parseUnits("20", 6), token: USDC }]),
    );
    ev.observe(req("18", A));
    const r = await ev.evaluate(req("5", A)); // 18 + 5 > 20
    expect(r.checks.find((c) => c.id === "spend-cap-day")?.passed).toBe(false);
  });

  it("flags a new counterparty for escalation, then clears once seen", async () => {
    const ev = new PolicyEvaluator(
      policy([{ type: "counterparty", flagNewRecipients: true, action: "escalate" }]),
    );
    expect((await ev.evaluate(req("1", A))).escalate).toBe(true);
    ev.observe(req("1", A));
    expect((await ev.evaluate(req("1", A))).escalate).toBe(false);
  });

  it("enforced allowlist blocks a non-listed recipient", async () => {
    const ev = new PolicyEvaluator(
      policy([{ type: "allowlist", mode: "recipients", entries: [A.toLowerCase()], enforce: true }]),
    );
    expect(
      (await ev.evaluate(req("1", B))).checks.find((c) => c.id === "allowlist-recipients")?.severity,
    ).toBe("critical");
    expect(
      (await ev.evaluate(req("1", A))).checks.find((c) => c.id === "allowlist-recipients")?.passed,
    ).toBe(true);
  });

  it("rate-limits beyond the configured window", async () => {
    const ev = new PolicyEvaluator(
      policy([{ type: "rate-limit", maxPayments: 2, windowSeconds: 60 }]),
    );
    ev.observe(req("1", A));
    ev.observe(req("1", A));
    expect(
      (await ev.evaluate(req("1", A))).checks.find((c) => c.id === "rate-limit")?.passed,
    ).toBe(false);
  });
});

describe("AgentGuard verdicts", () => {
  it("blocks the prompt-injection demo scenario ($15 → fresh, non-allowlisted address)", async () => {
    const wallet = new ViemAdapter({ privateKey: generatePrivateKey() });
    const guard = await createGuard({
      wallet,
      policy: policy([
        {
          type: "spend-cap",
          window: "day",
          maxAmount: parseUnits("20", 6),
          escalateAbove: parseUnits("2", 6),
          token: USDC,
        },
        { type: "allowlist", mode: "recipients", entries: [A.toLowerCase()], enforce: true },
      ]),
    });
    const decision = await guard.evaluate(req("15", B));
    expect(decision.verdict).toBe("block");
  });

  it("escalates a large payment to a new (allowlisted) counterparty", async () => {
    const wallet = new ViemAdapter({ privateKey: generatePrivateKey() });
    const guard = await createGuard({
      wallet,
      policy: policy([
        {
          type: "spend-cap",
          window: "day",
          maxAmount: parseUnits("20", 6),
          escalateAbove: parseUnits("2", 6),
          token: USDC,
        },
      ]),
    });
    const decision = await guard.evaluate(req("15", A));
    expect(decision.verdict).toBe("escalate");
  });
});
