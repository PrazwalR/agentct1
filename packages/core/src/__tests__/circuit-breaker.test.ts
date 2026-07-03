import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { CircuitBreaker } from "../circuit-breaker.js";
import { createGuard } from "../index.js";
import { ViemAdapter } from "../adapters/viem.js";
import type { PaymentRequest, Policy } from "../types.js";

describe("CircuitBreaker", () => {
  it("trips after maxBlocks within the window", () => {
    const b = new CircuitBreaker({ windowSeconds: 60, maxBlocks: 3 });
    b.record("block", false, 1000);
    b.record("block", false, 2000);
    expect(b.isOpen(2000)).toBe(false);
    b.record("block", false, 3000);
    expect(b.isOpen(3000)).toBe(true);
  });

  it("does not trip when failures fall outside the window", () => {
    const b = new CircuitBreaker({ windowSeconds: 10, maxBlocks: 2 });
    b.record("block", false, 0);
    b.record("block", false, 20_000); // 20s later — the first is pruned
    expect(b.isOpen(20_000)).toBe(false);
  });

  it("trips on anomalies", () => {
    const b = new CircuitBreaker({ windowSeconds: 60, maxAnomalies: 2 });
    b.record("allow", true, 0);
    b.record("allow", true, 1000);
    expect(b.isOpen(1000)).toBe(true);
  });

  it("auto-closes after the cooldown", () => {
    const b = new CircuitBreaker({ windowSeconds: 60, maxBlocks: 1, cooldownSeconds: 30 });
    b.record("block", false, 0);
    expect(b.isOpen(0)).toBe(true);
    expect(b.isOpen(29_000)).toBe(true);
    expect(b.isOpen(30_000)).toBe(false);
  });

  it("reset() closes and clears history", () => {
    const b = new CircuitBreaker({ windowSeconds: 60, maxBlocks: 1 });
    b.record("block", false, 0);
    expect(b.state(0)).toBe("open");
    b.reset();
    expect(b.state(0)).toBe("closed");
    expect(b.counts(0).blocks).toBe(0);
  });
});

describe("AgentGuard circuit breaker integration", () => {
  const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
  const A = "0x1111111111111111111111111111111111111111" as Address;
  const policy: Policy = { agentId: "a", anomalyThreshold: 0.8, anomalyAction: "escalate", rules: [] };
  const req: PaymentRequest = {
    intent: "x",
    amount: parseUnits("0.10", 6),
    token: USDC,
    recipient: A,
    chain: "eip155:84532",
    agentId: "a",
  };

  it("freezes the agent once tripped, unfreezes on reset", async () => {
    const guard = await createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
      policy,
      circuitBreaker: { windowSeconds: 60, maxBlocks: 2 },
    });

    expect((await guard.evaluate(req)).verdict).toBe("allow");

    // Simulate two blocked payments tripping the breaker.
    guard.circuitBreaker!.record("block", false);
    guard.circuitBreaker!.record("block", false);

    const frozen = await guard.evaluate(req);
    expect(frozen.verdict).toBe("block");
    expect(frozen.checks.some((c) => c.id === "circuit-breaker")).toBe(true);

    guard.resetCircuitBreaker();
    expect((await guard.evaluate(req)).verdict).toBe("allow");
  });
});
