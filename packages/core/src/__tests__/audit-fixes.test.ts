import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { compilePolicyObject } from "../policy/compiler.js";
import { PolicyEvaluator } from "../policy/evaluator.js";
import { getChain } from "../constants.js";
import { ViemAdapter } from "../adapters/viem.js";
import { CdpAdapter } from "../adapters/cdp.js";
import { CircleAdapter } from "../adapters/circle.js";
import { PrivyAdapter } from "../adapters/privy.js";
import type { IWalletAdapter, PaymentRequest, Policy } from "../types.js";

const A = "0x1111111111111111111111111111111111111111" as Address;

const compilerOutput = {
  rules: [{ type: "spend-cap", window: "day", maxAmount: 20 }],
  anomalyThreshold: 0.8,
  anomalyAction: "escalate" as const,
};

describe("compilePolicyObject — chain-aware token resolution", () => {
  it("defaults to Base Sepolia USDC for back-compat", () => {
    const policy = compilePolicyObject(compilerOutput, "a");
    const rule = policy.rules[0];
    expect(rule?.type).toBe("spend-cap");
    if (rule?.type === "spend-cap") {
      expect(rule.token.toLowerCase()).toBe(getChain("eip155:84532").usdc.toLowerCase());
    }
  });

  it("resolves the correct USDC address for a different chain", () => {
    const policy = compilePolicyObject(compilerOutput, "a", undefined, "eip155:8453");
    const rule = policy.rules[0];
    if (rule?.type === "spend-cap") {
      expect(rule.token.toLowerCase()).toBe(getChain("eip155:8453").usdc.toLowerCase());
      expect(rule.token.toLowerCase()).not.toBe(getChain("eip155:84532").usdc.toLowerCase());
    }
  });
});

describe("PolicyEvaluator — spend-cap coverage visibility", () => {
  const sepoliaUsdc = getChain("eip155:84532").usdc;
  const mainnetUsdc = getChain("eip155:8453").usdc;

  const policy: Policy = {
    agentId: "a",
    anomalyThreshold: 0.8,
    anomalyAction: "escalate",
    rules: [
      { type: "spend-cap", window: "day", maxAmount: parseUnits("20", 6), token: sepoliaUsdc },
    ],
  };

  function req(token: Address): PaymentRequest {
    return {
      intent: "x",
      amount: parseUnits("1", 6),
      token,
      recipient: A,
      chain: "eip155:84532",
      agentId: "a",
    };
  }

  it("warns when no spend-cap rule targets the payment's token (the bug this closes)", async () => {
    const ev = new PolicyEvaluator(policy);
    const r = await ev.evaluate(req(mainnetUsdc)); // policy's cap is Sepolia-denominated
    const coverage = r.checks.find((c) => c.id === "spend-cap-coverage");
    expect(coverage).toBeDefined();
    expect(coverage?.passed).toBe(true); // informational only — never itself blocks/escalates
    expect(coverage?.severity).toBe("warning");
  });

  it("does not warn when the token matches", async () => {
    const ev = new PolicyEvaluator(policy);
    const r = await ev.evaluate(req(sepoliaUsdc));
    expect(r.checks.find((c) => c.id === "spend-cap-coverage")).toBeUndefined();
  });

  it("does not warn when the policy has no spend-cap rules at all", async () => {
    const ev = new PolicyEvaluator({ ...policy, rules: [] });
    const r = await ev.evaluate(req(mainnetUsdc));
    expect(r.checks.find((c) => c.id === "spend-cap-coverage")).toBeUndefined();
  });
});

describe("Circle/Privy adapters — fail fast on missing credentials", () => {
  it("CircleAdapter throws a clear error instead of silently using an empty-string key", async () => {
    const adapter = new CircleAdapter({ walletId: "w1", address: A });
    await expect(adapter.getSigner()).rejects.toThrow(/CIRCLE_API_KEY/);
  });

  it("PrivyAdapter throws a clear error instead of silently using an empty-string secret", async () => {
    const adapter = new PrivyAdapter({ walletId: "w1", address: A });
    await expect(adapter.getSigner()).rejects.toThrow(/PRIVY_APP_ID/);
  });
});

describe("releaseNonce — parity across all four wallet adapters", () => {
  const adapters: Array<[string, IWalletAdapter]> = [
    ["viem", new ViemAdapter({ privateKey: generatePrivateKey() })],
    ["cdp", new CdpAdapter({ accountName: "test" })],
    ["circle", new CircleAdapter({ walletId: "w1", address: A })],
    ["privy", new PrivyAdapter({ walletId: "w1", address: A })],
  ];

  it.each(adapters)("%s adapter implements releaseNonce", (_name, adapter) => {
    expect(typeof adapter.releaseNonce).toBe("function");
    // Releasing an unreserved/unknown nonce must not throw.
    expect(() => adapter.releaseNonce?.("0x00" as `0x${string}`)).not.toThrow();
  });
});
