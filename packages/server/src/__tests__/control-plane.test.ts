import { afterEach, describe, expect, it } from "vitest";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { parseUnits, type Address } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { ApprovalQueue, ViemAdapter, createGuard, type Policy } from "@agentctl/core";
import { serveControlPlane, type ServeOptions } from "../index.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const A = "0x1111111111111111111111111111111111111111" as Address;
const B = "0x2222222222222222222222222222222222222222" as Address;

const policy: Policy = {
  agentId: "a",
  anomalyThreshold: 0.8,
  anomalyAction: "escalate",
  rules: [{ type: "allowlist", mode: "recipients", entries: [A.toLowerCase()], enforce: true }],
};

const openServers: Server[] = [];
afterEach(() => {
  for (const s of openServers) s.close();
  openServers.length = 0;
});

async function boot(serveOpts: ServeOptions = {}) {
  const queue = new ApprovalQueue();
  const guard = await createGuard({
    wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
    policy,
    approvalQueue: queue,
    circuitBreaker: { windowSeconds: 60, maxBlocks: 2 },
  });
  const server = await serveControlPlane(guard, { port: 0, ...serveOpts });
  openServers.push(server);
  const { port } = server.address() as AddressInfo;
  return { guard, queue, base: `http://127.0.0.1:${port}` };
}

describe("control plane", () => {
  it("serves /health and evaluates a payment (blocks non-allowlisted)", async () => {
    const { base } = await boot();
    expect(await (await fetch(`${base}/health`)).json()).toEqual({ status: "ok" });

    const res = await fetch(`${base}/evaluate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        request: {
          intent: "x",
          amount: parseUnits("1", 6).toString(),
          token: USDC,
          recipient: B,
          chain: "eip155:84532",
        },
      }),
    });
    const { decision } = (await res.json()) as { decision: { verdict: string } };
    expect(decision.verdict).toBe("block");
  });

  it("lists and resolves pending approvals", async () => {
    const { queue, base } = await boot();
    const pending = queue.enqueue(
      {
        intent: "x",
        amount: parseUnits("15", 6),
        token: USDC,
        recipient: A,
        chain: "eip155:84532",
        agentId: "a",
      },
      { verdict: "escalate", riskScore: 0.5, checks: [], reason: "" },
      60,
    );

    const list = (await (await fetch(`${base}/approvals`)).json()) as {
      pending: Array<{ id: string }>;
    };
    expect(list.pending.length).toBe(1);

    const resolved = (await (
      await fetch(`${base}/approvals/${list.pending[0]!.id}/approve`, { method: "POST" })
    ).json()) as { resolved: boolean };
    expect(resolved.resolved).toBe(true);
    await expect(pending).resolves.toBe(true);
  });

  it("reports and resets the circuit breaker", async () => {
    const { guard, base } = await boot();
    guard.circuitBreaker!.record("block", false);
    guard.circuitBreaker!.record("block", false); // trips (maxBlocks: 2)

    const open = (await (await fetch(`${base}/breaker`)).json()) as { state: string };
    expect(open.state).toBe("open");

    await fetch(`${base}/breaker/reset`, { method: "POST" });
    const closed = (await (await fetch(`${base}/breaker`)).json()) as { state: string };
    expect(closed.state).toBe("closed");
  });

  it("enforces the bearer token on protected routes, but /health stays open", async () => {
    const { base } = await boot({ token: "secret" });

    // /health is exempt by design — orchestrator liveness probes can't send headers.
    expect((await fetch(`${base}/health`)).status).toBe(200);

    expect((await fetch(`${base}/breaker`)).status).toBe(401);
    const ok = await fetch(`${base}/breaker`, { headers: { authorization: "Bearer secret" } });
    expect(ok.status).toBe(200);
  });

  it("rate-limits a client after the configured max, but never /health", async () => {
    const { base } = await boot({ rateLimit: { windowMs: 60_000, max: 3 } });

    for (let i = 0; i < 3; i++) {
      expect((await fetch(`${base}/breaker`)).status).toBe(200);
    }
    expect((await fetch(`${base}/breaker`)).status).toBe(429);

    // /health bypasses the limiter entirely, even once the client is capped.
    expect((await fetch(`${base}/health`)).status).toBe(200);
  });

  it("rateLimit: false disables the limiter", async () => {
    const { base } = await boot({ rateLimit: false });
    for (let i = 0; i < 10; i++) {
      expect((await fetch(`${base}/breaker`)).status).toBe(200);
    }
  });
});
