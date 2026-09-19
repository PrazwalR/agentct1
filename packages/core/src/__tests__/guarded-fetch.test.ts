import { afterEach, describe, expect, it } from "vitest";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { parseUnits, type Address } from "viem";
import { generatePrivateKey } from "viem/accounts";
import {
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
  decodePaymentSignatureHeader,
} from "@x402/core/http";
import { createGuard } from "../index.js";
import { ViemAdapter } from "../adapters/viem.js";
import type { Policy } from "../types.js";

/**
 * End-to-end coverage for the x402 interception path — the drop-in `guardedFetch`
 * the README leads with. Until now nothing exercised it, which is exactly how a
 * blocked payment could go unrecorded without a test noticing.
 */

const CHAIN = "eip155:84532";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const KNOWN = "0x1111111111111111111111111111111111111111" as Address;
const ATTACKER = "0x9999999999999999999999999999999999999999" as Address;

const servers: Server[] = [];
const logs: AuditLogger[] = [];
afterEach(async () => {
  for (const s of servers) s.close();
  servers.length = 0;
  for (const l of logs) await l.close();
  logs.length = 0;
});

interface PaidServer {
  url: string;
  /** Payment signature headers seen on the retry (empty if the payment never happened). */
  paid: () => unknown[];
}

/** A resource server that answers 402 with x402 v2 terms, then 200 once paid. */
function startPaidResource(payTo: Address, amount: bigint): Promise<PaidServer> {
  const paid: unknown[] = [];
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const sig = req.headers["payment-signature"] as string | undefined;
      if (sig) {
        paid.push(decodePaymentSignatureHeader(sig));
        res.writeHead(200, {
          "content-type": "application/json",
          "PAYMENT-RESPONSE": encodePaymentResponseHeader({
            success: true,
            transaction: `0x${"ab".repeat(32)}`,
            network: CHAIN,
          } as never),
        });
        res.end(JSON.stringify({ data: "the paid resource" }));
        return;
      }
      res.writeHead(402, {
        "content-type": "application/json",
        "PAYMENT-REQUIRED": encodePaymentRequiredHeader({
          x402Version: 2,
          resource: { url: "http://resource.test/paid" },
          accepts: [
            {
              scheme: "exact",
              network: CHAIN,
              asset: USDC,
              amount: amount.toString(),
              payTo,
              maxTimeoutSeconds: 3600,
              extra: { name: "USDC", version: "2" },
            },
          ],
        }),
      });
      res.end(JSON.stringify({ error: "payment required" }));
    });
    servers.push(server);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}/paid`, paid: () => paid });
    });
  });
}

function policy(rules: Policy["rules"]): Policy {
  return { agentId: "gf-agent", rules, anomalyThreshold: 0.8, anomalyAction: "escalate" };
}

async function makeGuard(p: Policy) {
  const guard = await createGuard({
    wallet: new ViemAdapter({ privateKey: generatePrivateKey(), chain: CHAIN }),
    policy: p,
    auditStore: ":memory:",
    hydrate: false,
  });
  logs.push(guard.auditLog);
  return guard;
}

describe("guardedFetch — x402 interception", () => {
  it("records a BLOCKED payment to the audit log and returns 403", async () => {
    // The regression test for the core gap: aborting at onBeforePaymentCreation makes
    // the x402 client throw, so onPaymentResponse never fires — the blocked attempt
    // (the very event the audit trail exists for) must still be recorded.
    const resource = await startPaidResource(ATTACKER, parseUnits("15", 6));
    const guard = await makeGuard(
      policy([{ type: "allowlist", mode: "recipients", entries: [KNOWN], enforce: true }]),
    );

    const gfetch = await guard.guardedFetch();
    const res = await gfetch(resource.url, { headers: { "x-agent-intent": "weather data" } });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string; decision: { verdict: string } };
    expect(body.error).toBe("Payment blocked by agentctl");
    expect(body.decision.verdict).toBe("block");

    // Nothing was paid…
    expect(resource.paid()).toHaveLength(0);
    // …and exactly one block is in the trail.
    const entries = await guard.auditLog.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.decision.verdict).toBe("block");
    expect(entries[0]?.request.recipient.toLowerCase()).toBe(ATTACKER.toLowerCase());
    expect(entries[0]?.settlement).toBeUndefined();
  });

  it("records an ESCALATION that is denied, without paying", async () => {
    const resource = await startPaidResource(KNOWN, parseUnits("15", 6));
    const guard = await makeGuard(
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

    const gfetch = await guard.guardedFetch();
    const res = await gfetch(resource.url, { headers: { "x-agent-intent": "bulk compute" } });

    expect(res.status).toBe(403);
    expect(resource.paid()).toHaveLength(0);
    const entries = await guard.auditLog.list();
    expect(entries).toHaveLength(1);
    expect(entries[0]?.decision.verdict).toBe("escalate");
  });

  it("threads x-agent-intent into the decision's PaymentRequest", async () => {
    const resource = await startPaidResource(ATTACKER, parseUnits("15", 6));
    const guard = await makeGuard(
      policy([{ type: "allowlist", mode: "recipients", entries: [KNOWN], enforce: true }]),
    );

    const gfetch = await guard.guardedFetch();
    await gfetch(resource.url, { headers: { "x-agent-intent": "tomorrow's forecast" } });

    const entries = await guard.auditLog.list();
    expect(entries[0]?.request.intent).toBe("tomorrow's forecast");
    expect(entries[0]?.request.resourceUrl).toBe(resource.url);
  });

  it("derives the payment request from the 402 terms (amount, token, recipient, chain)", async () => {
    const resource = await startPaidResource(ATTACKER, parseUnits("3.5", 6));
    const guard = await makeGuard(
      policy([{ type: "allowlist", mode: "recipients", entries: [KNOWN], enforce: true }]),
    );

    await (
      await guard.guardedFetch()
    )(resource.url);

    const req = (await guard.auditLog.list())[0]?.request;
    expect(req?.amount).toBe(parseUnits("3.5", 6));
    expect(req?.token.toLowerCase()).toBe(USDC.toLowerCase());
    expect(req?.recipient.toLowerCase()).toBe(ATTACKER.toLowerCase());
    expect(req?.chain).toBe(CHAIN);
  });

  it("passes a non-402 response straight through without touching the audit log", async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ free: true }));
    });
    servers.push(server);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const { port } = server.address() as AddressInfo;

    const guard = await makeGuard(policy([]));
    const res = await (await guard.guardedFetch())(`http://127.0.0.1:${port}/free`);

    expect(res.status).toBe(200);
    expect(await guard.auditLog.list()).toHaveLength(0);
  });
});
