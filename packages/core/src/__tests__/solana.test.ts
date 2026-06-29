import { describe, expect, it } from "vitest";
import { generatePrivateKey } from "viem/accounts";
import { PolicyEvaluator } from "../policy/evaluator.js";
import {
  SOLANA_MAINNET_CAIP2,
  SOLANA_USDC_MAINNET,
  getSolanaUsdc,
  isSolanaNetwork,
} from "../solana.js";
import { createGuard } from "../index.js";
import { ViemAdapter } from "../adapters/viem.js";
import type { PaymentRequest, Policy } from "../types.js";

// Solana token amounts/addresses are base58 strings — the policy/behavioral/intent
// layers treat token & recipient as opaque strings, so they are chain-agnostic.
const USDC_MINT = SOLANA_USDC_MAINNET;
const RECIPIENT = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"; // arbitrary base58
const ATTACKER = "11111111111111111111111111111111";

function solReq(amount: bigint, recipient: string): PaymentRequest {
  return {
    intent: "pay a Solana API",
    amount,
    token: USDC_MINT as `0x${string}`, // typed as Address but holds a base58 mint here
    recipient: recipient as `0x${string}`,
    chain: SOLANA_MAINNET_CAIP2,
    agentId: "sol-agent",
  };
}

describe("solana helpers", () => {
  it("identifies Solana networks and resolves USDC", () => {
    expect(isSolanaNetwork(SOLANA_MAINNET_CAIP2)).toBe(true);
    expect(isSolanaNetwork("eip155:8453")).toBe(false);
    expect(getSolanaUsdc(SOLANA_MAINNET_CAIP2)).toBe(SOLANA_USDC_MAINNET);
    expect(SOLANA_MAINNET_CAIP2.startsWith("solana:")).toBe(true);
  });
});

describe("chain-agnostic guard decisions on Solana", () => {
  const policy: Policy = {
    agentId: "sol-agent",
    anomalyThreshold: 0.8,
    anomalyAction: "escalate",
    rules: [
      {
        type: "spend-cap",
        window: "day",
        maxAmount: 20_000_000n, // 20 USDC (6 decimals)
        token: USDC_MINT as `0x${string}`,
      },
      { type: "allowlist", mode: "recipients", entries: [RECIPIENT.toLowerCase()], enforce: true },
    ],
  };

  it("applies spend-cap + allowlist to a Solana payment", async () => {
    const ev = new PolicyEvaluator(policy);
    const overCap = await ev.evaluate(solReq(25_000_000n, RECIPIENT));
    expect(overCap.checks.find((c) => c.id === "spend-cap-day")?.severity).toBe("critical");
  });

  it("blocks a Solana payment to a non-allowlisted recipient end-to-end", async () => {
    const guard = await createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
      policy,
    });
    const decision = await guard.evaluate(solReq(5_000_000n, ATTACKER));
    expect(decision.verdict).toBe("block");
  });
});
