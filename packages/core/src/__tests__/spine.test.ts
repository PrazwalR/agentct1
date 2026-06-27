import { describe, expect, it } from "vitest";
import { generatePrivateKey } from "viem/accounts";
import { parseUnits, type Address } from "viem";
import { createGuard } from "../index.js";
import { ViemAdapter } from "../adapters/viem.js";
import { inspectAuthorization } from "../x402/eip3009.js";
import type { PaymentRequest, Policy } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const DEAD = "0x000000000000000000000000000000000000dEaD" as Address;

function emptyPolicy(agentId: string): Policy {
  return { agentId, rules: [], anomalyThreshold: 0.8, anomalyAction: "escalate" };
}

describe("agentctl spine", () => {
  it("evaluates a request through the three-layer pipeline (Phase A: allow)", async () => {
    const wallet = new ViemAdapter({ privateKey: generatePrivateKey() });
    const guard = await createGuard({ wallet, policy: emptyPolicy("test-agent") });

    const req: PaymentRequest = {
      intent: "weather data for trip planning",
      amount: parseUnits("0.10", 6),
      token: USDC,
      recipient: DEAD,
      chain: "eip155:84532",
      agentId: "test-agent",
    };

    const decision = await guard.evaluate(req);
    expect(decision.verdict).toBe("allow");
    expect(decision.riskScore).toBe(0);
    expect(decision.checks.some((c) => c.id === "intent-reconcile")).toBe(true);
  });

  it("signs a recipient- and amount-bound EIP-3009 authorization", async () => {
    const wallet = new ViemAdapter({ privateKey: generatePrivateKey() });
    const req: PaymentRequest = {
      intent: "buy compute",
      amount: parseUnits("1.50", 6),
      token: USDC,
      recipient: DEAD,
      chain: "eip155:84532",
      agentId: "test-agent",
    };

    const signed = await wallet.authorizePayment(req);
    const insp = inspectAuthorization(signed);

    expect(insp.recipient.toLowerCase()).toBe(DEAD.toLowerCase());
    expect(insp.amount).toBe(req.amount);
    expect(insp.from.toLowerCase()).toBe((await wallet.getAddress()).toLowerCase());
    // 65-byte signature, 32-byte nonce, future expiry
    expect(signed.signature).toMatch(/^0x[0-9a-fA-F]{130}$/);
    expect(signed.authorization.nonce).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(insp.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("rejects an unsupported chain", async () => {
    const wallet = new ViemAdapter({ privateKey: generatePrivateKey() });
    const req: PaymentRequest = {
      intent: "x",
      amount: 1n,
      token: USDC,
      recipient: DEAD,
      chain: "eip155:1", // Ethereum L1 not configured
      agentId: "a",
    };
    await expect(wallet.authorizePayment(req)).rejects.toThrow(/Unsupported chain/);
  });
});
