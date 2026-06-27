import { describe, expect, it } from "vitest";
import { type Server, createServer } from "node:http";
import { type AddressInfo } from "node:net";
import { parseUnits, type Address } from "viem";
import {
  SIGNATURE_HEADER,
  createWebhookEscalation,
  signWebhook,
  verifyWebhook,
} from "../escalation/webhook.js";
import type { PaymentRequest, PolicyDecision } from "../types.js";

const req: PaymentRequest = {
  intent: "buy compute",
  amount: parseUnits("5", 6),
  token: "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address,
  recipient: "0x000000000000000000000000000000000000dEaD" as Address,
  chain: "eip155:84532",
  agentId: "a",
};
const decision: PolicyDecision = {
  verdict: "escalate",
  riskScore: 0.5,
  checks: [],
  reason: "needs approval",
};

function startServer(
  handler: (body: string, sig: string) => { status: number; json: unknown },
): Promise<{ server: Server; url: string; last: () => { body: string; sig: string } }> {
  let captured = { body: "", sig: "" };
  return new Promise((resolve) => {
    const server = createServer((rq, rs) => {
      let body = "";
      rq.on("data", (c) => (body += c)).on("end", () => {
        captured = { body, sig: (rq.headers[SIGNATURE_HEADER] as string) ?? "" };
        const { status, json } = handler(body, captured.sig);
        rs.writeHead(status, { "content-type": "application/json" });
        rs.end(JSON.stringify(json));
      });
    });
    server.listen(0, () => {
      const port = (server.address() as AddressInfo).port;
      resolve({ server, url: `http://127.0.0.1:${port}`, last: () => captured });
    });
  });
}

describe("webhook escalation", () => {
  it("signs + verifies (HMAC-SHA256) and detects tampering", () => {
    const sig = signWebhook("secret", "the-body");
    expect(sig.startsWith("sha256=")).toBe(true);
    expect(verifyWebhook("secret", "the-body", sig)).toBe(true);
    expect(verifyWebhook("secret", "tampered", sig)).toBe(false);
    expect(verifyWebhook("wrong-secret", "the-body", sig)).toBe(false);
  });

  it("approves when the endpoint returns { approved: true } with a valid signature", async () => {
    const { server, url, last } = await startServer(() => ({ status: 200, json: { approved: true } }));
    const onEscalation = createWebhookEscalation({ url, secret: "sec", timeoutSeconds: 5 });

    expect(await onEscalation(req, decision)).toBe(true);
    const { body, sig } = last();
    expect(verifyWebhook("sec", body, sig)).toBe(true);
    expect(JSON.parse(body).request.amount).toBe("5000000"); // bigint serialized
    server.close();
  });

  it("denies on { approved: false }, non-200, and is fail-closed", async () => {
    const denied = await startServer(() => ({ status: 200, json: { approved: false } }));
    const onDeny = createWebhookEscalation({ url: denied.url, secret: "sec" });
    expect(await onDeny(req, decision)).toBe(false);
    denied.server.close();

    const errored = await startServer(() => ({ status: 500, json: {} }));
    const onErr = createWebhookEscalation({ url: errored.url, secret: "sec" });
    expect(await onErr(req, decision)).toBe(false);
    errored.server.close();
  });
});
