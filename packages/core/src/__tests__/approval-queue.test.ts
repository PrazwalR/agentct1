import { describe, expect, it, vi } from "vitest";
import { parseUnits, type Address } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { ApprovalQueue } from "../approval-queue.js";
import { createGuard } from "../index.js";
import { ViemAdapter } from "../adapters/viem.js";
import type { PaymentRequest, Policy, PolicyDecision } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const A = "0x1111111111111111111111111111111111111111" as Address;
const req: PaymentRequest = {
  intent: "buy compute",
  amount: parseUnits("15", 6),
  token: USDC,
  recipient: A,
  chain: "eip155:84532",
  agentId: "a",
};
const decision: PolicyDecision = {
  verdict: "escalate",
  riskScore: 0.5,
  checks: [],
  reason: "needs approval",
};

describe("ApprovalQueue", () => {
  it("resolves true when a pending payment is approved", async () => {
    const q = new ApprovalQueue();
    const pending = q.enqueue(req, decision, 60);
    expect(q.size).toBe(1);
    const item = q.list()[0];
    expect(item?.request.amount).toBe(parseUnits("15", 6));
    expect(q.resolve(item!.id, true)).toBe(true);
    await expect(pending).resolves.toBe(true);
    expect(q.size).toBe(0);
  });

  it("resolves false when denied", async () => {
    const q = new ApprovalQueue();
    const pending = q.enqueue(req, decision, 60);
    q.resolve(q.list()[0]!.id, false);
    await expect(pending).resolves.toBe(false);
  });

  it("resolve() returns false for an unknown id", () => {
    expect(new ApprovalQueue().resolve("nope", true)).toBe(false);
  });

  it("auto-denies on timeout", async () => {
    vi.useFakeTimers();
    try {
      const q = new ApprovalQueue({ defaultTimeoutSeconds: 10 });
      const pending = q.enqueue(req, decision);
      expect(q.size).toBe(1);
      vi.advanceTimersByTime(10_000);
      await expect(pending).resolves.toBe(false);
      expect(q.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("AgentGuard approval-queue wiring", () => {
  it("exposes the configured queue as the escalation sink", async () => {
    const queue = new ApprovalQueue();
    const policy: Policy = { agentId: "a", anomalyThreshold: 0.8, anomalyAction: "escalate", rules: [] };
    const guard = await createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
      policy,
      approvalQueue: queue,
    });
    expect(guard.approvalQueue).toBe(queue);
  });
});
