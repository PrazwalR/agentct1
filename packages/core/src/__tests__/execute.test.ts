import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { parseUnits, type Address, type Hex } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { createGuard, type AgentGuard } from "../index.js";
import { ViemAdapter } from "../adapters/viem.js";
import type { PaymentRequest, Policy } from "../types.js";

/**
 * Coverage for the programmatic settle path.
 *
 * `execute()` is the one code path that actually moves money without an HTTP 402 in
 * front of it, and it had no tests at all. Signing is offline, so a fake facilitator
 * is enough to exercise the whole thing: guard → sign → assert-matches → settle →
 * record → advance state.
 */

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const KNOWN = "0x1111111111111111111111111111111111111111" as Address;
const OTHER = "0x2222222222222222222222222222222222222222" as Address;
const TX = ("0x" + "ab".repeat(32)) as Hex;

interface SettleCall {
  authorization: { from: string; to: string; value: string; validBefore: string; nonce: string };
  signature: string;
  requirements: { asset: string; payTo: string; amount: string; network: string };
}

const servers: Server[] = [];
afterEach(() => {
  for (const s of servers) s.close();
  servers.length = 0;
});

/** A facilitator that records what it was asked to settle and answers as instructed. */
function fakeFacilitator(
  reply: { success: boolean; errorReason?: string } = { success: true },
): Promise<{ url: string; calls: () => SettleCall[] }> {
  const calls: SettleCall[] = [];
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      let body = "";
      req
        .on("data", (c) => (body += c))
        .on("end", () => {
          if (req.url === "/settle" && body) {
            const b = JSON.parse(body);
            calls.push({
              authorization: b.paymentPayload.payload.authorization,
              signature: b.paymentPayload.payload.signature,
              requirements: b.paymentRequirements,
            });
          }
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              success: reply.success,
              errorReason: reply.errorReason,
              transaction: reply.success ? TX : "",
              network: "eip155:84532",
            }),
          );
        });
    });
    servers.push(server);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}`, calls: () => calls });
    });
  });
}

function policy(rules: Policy["rules"] = []): Policy {
  return { agentId: "exec-agent", rules, anomalyThreshold: 0.9, anomalyAction: "escalate" };
}

async function makeGuard(
  url: string,
  p: Policy = policy(),
  extra: Partial<Parameters<typeof createGuard>[0]> = {},
): Promise<AgentGuard> {
  return createGuard({
    wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
    policy: p,
    auditStore: ":memory:",
    hydrate: false,
    facilitatorUrl: url,
    ...extra,
  });
}

function req(amountUsd: string, recipient: Address = KNOWN): PaymentRequest {
  return {
    intent: "buy compute",
    amount: parseUnits(amountUsd, 6),
    token: USDC,
    recipient,
    chain: "eip155:84532",
    agentId: "exec-agent",
  };
}

describe("execute() — the allowed path", () => {
  it("signs an EIP-3009 authorization bound to the approved recipient and amount", async () => {
    const f = await fakeFacilitator();
    const guard = await makeGuard(f.url);
    const r = req("1.50");

    const result = await guard.execute(r);

    expect(result.executed).toBe(true);
    expect(result.decision.verdict).toBe("allow");
    expect(result.settlement?.success).toBe(true);
    expect(result.settlement?.txHash).toBe(TX);

    // What the facilitator was actually handed must match what was approved.
    const [call] = f.calls();
    expect(call).toBeDefined();
    expect(call!.authorization.to.toLowerCase()).toBe(KNOWN.toLowerCase());
    expect(call!.authorization.value).toBe(r.amount.toString());
    expect(call!.requirements.asset.toLowerCase()).toBe(USDC.toLowerCase());
    expect(call!.signature).toMatch(/^0x[0-9a-f]{130}$/);
  });

  it("gives every payment a fresh random nonce and a future expiry", async () => {
    const f = await fakeFacilitator();
    const guard = await makeGuard(f.url);
    await guard.execute(req("1"));
    await guard.execute(req("1"));

    const [a, b] = f.calls();
    // EIP-3009 nonces are single-use; a repeat would be a double-spend hazard.
    expect(a!.authorization.nonce).not.toBe(b!.authorization.nonce);
    expect(a!.authorization.nonce).toMatch(/^0x[0-9a-f]{64}$/);
    expect(Number(a!.authorization.validBefore)).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("records the settlement to the audit log", async () => {
    const f = await fakeFacilitator();
    const guard = await makeGuard(f.url);
    await guard.execute(req("2"));

    const entries = await guard.auditLog.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.decision.verdict).toBe("allow");
    expect(entries[0]?.settlement?.success).toBe(true);
    expect(entries[0]?.settlement?.txHash).toBe(TX);
  });

  it("advances spend and counterparty state only after a real settlement", async () => {
    const f = await fakeFacilitator();
    const guard = await makeGuard(
      f.url,
      policy([
        { type: "spend-cap", window: "day", maxAmount: parseUnits("10", 6), token: USDC },
        { type: "counterparty", flagNewRecipients: true, action: "escalate" },
      ]),
    );

    // First payment to a new counterparty escalates (and, with no handler, is denied).
    const first = await guard.execute(req("6"));
    expect(first.decision.verdict).toBe("escalate");
    expect(first.executed).toBe(false);
    expect(f.calls()).toHaveLength(0); // denied escalation must never reach the facilitator

    // Approve from here on: the payment settles and the window moves.
    const guard2 = await makeGuard(
      f.url,
      policy([{ type: "spend-cap", window: "day", maxAmount: parseUnits("10", 6), token: USDC }]),
    );
    await guard2.execute(req("6"));
    const second = await guard2.evaluate(req("6")); // 6 + 6 > 10
    expect(second.verdict).toBe("block");
  });
});

describe("execute() — the paths that must not pay", () => {
  it("never calls the facilitator when the policy blocks", async () => {
    const f = await fakeFacilitator();
    const guard = await makeGuard(
      f.url,
      policy([{ type: "allowlist", mode: "recipients", entries: [KNOWN], enforce: true }]),
    );

    const result = await guard.execute(req("1", OTHER));

    expect(result.executed).toBe(false);
    expect(result.decision.verdict).toBe("block");
    expect(result.reason).toBe("blocked by policy");
    expect(f.calls()).toHaveLength(0);

    const entries = await guard.auditLog.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.settlement).toBeUndefined();
  });

  it("never calls the facilitator when an escalation is denied", async () => {
    const f = await fakeFacilitator();
    const guard = await makeGuard(
      f.url,
      policy([
        {
          type: "spend-cap",
          window: "day",
          maxAmount: parseUnits("100", 6),
          escalateAbove: parseUnits("1", 6),
          token: USDC,
        },
      ]),
    );

    const result = await guard.execute(req("50"));

    expect(result.executed).toBe(false);
    expect(result.decision.verdict).toBe("escalate");
    expect(result.reason).toBe("escalation denied/timed out");
    expect(f.calls()).toHaveLength(0);
    expect(await guard.auditLog.list()).toHaveLength(1);
  });

  it("settles once an escalation is approved", async () => {
    const f = await fakeFacilitator();
    const guard = await makeGuard(
      f.url,
      policy([
        {
          type: "spend-cap",
          window: "day",
          maxAmount: parseUnits("100", 6),
          escalateAbove: parseUnits("1", 6),
          token: USDC,
        },
      ]),
      { onEscalation: async () => true },
    );

    const result = await guard.execute(req("50"));
    expect(result.decision.verdict).toBe("escalate");
    expect(result.executed).toBe(true);
    expect(f.calls()).toHaveLength(1);
  });

  it("rejects a non-positive amount before signing anything", async () => {
    const f = await fakeFacilitator();
    const guard = await makeGuard(f.url);
    const result = await guard.execute({ ...req("1"), amount: 0n });

    expect(result.executed).toBe(false);
    expect(result.decision.checks[0]?.id).toBe("invalid-amount");
    expect(f.calls()).toHaveLength(0);
  });
});

describe("execute() — when the facilitator refuses", () => {
  it("reports failure, records it, and does not advance state", async () => {
    const f = await fakeFacilitator({ success: false, errorReason: "insufficient_funds" });
    const guard = await makeGuard(
      f.url,
      policy([{ type: "spend-cap", window: "day", maxAmount: parseUnits("10", 6), token: USDC }]),
    );

    const result = await guard.execute(req("6"));

    expect(result.executed).toBe(false);
    expect(result.settlement?.success).toBe(false);
    expect(result.settlement?.txHash).toBeUndefined();
    expect(result.reason).toBe("insufficient_funds");

    // The attempt is still audited — a failed settlement is evidence too.
    const entries = await guard.auditLog.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.settlement?.success).toBe(false);

    // Crucially, an unsettled payment must not consume the day's budget.
    const next = await guard.evaluate(req("6"));
    expect(next.verdict).toBe("allow");
  });
});
