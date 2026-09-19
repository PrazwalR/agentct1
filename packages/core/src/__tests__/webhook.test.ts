import { afterEach, describe, expect, it } from "vitest";
import { type Server, createServer } from "node:http";
import { type AddressInfo } from "node:net";
import { parseUnits, type Address } from "viem";
import {
  SIGNATURE_HEADER,
  TIMESTAMP_HEADER,
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

interface Captured {
  body: string;
  sig: string;
  ts: number;
}

/** How the approver should answer: given the request event, produce a response. */
type Responder = (event: Record<string, never> & { nonce: string }) => {
  status: number;
  json: unknown;
  /** Sign the response body with this secret (omit to answer unsigned). */
  signWith?: string;
};

const servers: Server[] = [];
afterEach(() => {
  for (const s of servers) s.close();
  servers.length = 0;
});

function startServer(responder: Responder): Promise<{ url: string; last: () => Captured }> {
  let captured: Captured = { body: "", sig: "", ts: 0 };
  return new Promise((resolve) => {
    const server = createServer((rq, rs) => {
      let body = "";
      rq.on("data", (c) => (body += c)).on("end", () => {
        captured = {
          body,
          sig: (rq.headers[SIGNATURE_HEADER] as string) ?? "",
          ts: Number(rq.headers[TIMESTAMP_HEADER]),
        };
        const { status, json, signWith } = responder(JSON.parse(body));
        const payload = JSON.stringify(json);
        const headers: Record<string, string> = { "content-type": "application/json" };
        if (signWith) {
          const ts = Math.floor(Date.now() / 1000);
          headers[SIGNATURE_HEADER] = signWebhook(signWith, payload, ts);
          headers[TIMESTAMP_HEADER] = String(ts);
        }
        rs.writeHead(status, headers);
        rs.end(payload);
      });
    });
    servers.push(server);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}`, last: () => captured });
    });
  });
}

/** An honest approver: echoes the nonce and signs its response. */
const approve = (secret: string): Responder => {
  return (event) => ({
    status: 200,
    json: { approved: true, nonce: event.nonce },
    signWith: secret,
  });
};

describe("signWebhook / verifyWebhook", () => {
  const now = 1_700_000_000;

  it("signs + verifies over `${timestamp}.${body}` and detects tampering", () => {
    const sig = signWebhook("secret", "the-body", now);
    expect(sig.startsWith("sha256=")).toBe(true);
    expect(verifyWebhook("secret", "the-body", sig, now, { now })).toBe(true);
    expect(verifyWebhook("secret", "tampered", sig, now, { now })).toBe(false);
    expect(verifyWebhook("wrong-secret", "the-body", sig, now, { now })).toBe(false);
  });

  it("binds the signature to its timestamp, so a body cannot be re-dated", () => {
    const sig = signWebhook("secret", "the-body", now);
    expect(verifyWebhook("secret", "the-body", sig, now + 1, { now })).toBe(false);
  });

  it("rejects a signature outside the replay window", () => {
    const stale = now - 3600;
    const sig = signWebhook("secret", "the-body", stale);
    // Valid HMAC, but far too old — a captured request must not stay usable.
    expect(verifyWebhook("secret", "the-body", sig, stale, { now })).toBe(false);
    expect(verifyWebhook("secret", "the-body", sig, stale, { now, toleranceSeconds: 7200 })).toBe(
      true,
    );
  });
});

describe("webhook escalation", () => {
  it("approves on a signed 200 that echoes the nonce", async () => {
    const { url, last } = await startServer(approve("sec"));
    const onEscalation = createWebhookEscalation({ url, secret: "sec", timeoutSeconds: 5 });

    expect(await onEscalation(req, decision)).toBe(true);

    const { body, sig, ts } = last();
    expect(verifyWebhook("sec", body, sig, ts)).toBe(true);
    const event = JSON.parse(body);
    expect(event.request.amount).toBe("5000000"); // bigint serialized
    expect(typeof event.nonce).toBe("string");
    expect(event.timestamp).toBe(ts);
  });

  it("denies an UNSIGNED approval — a 200 alone must not authorize a payment", async () => {
    const { url } = await startServer((e) => ({
      status: 200,
      json: { approved: true, nonce: e.nonce },
      // no signWith: anyone who can answer the request would otherwise approve it
    }));
    expect(await createWebhookEscalation({ url, secret: "sec" })(req, decision)).toBe(false);
  });

  it("denies an approval signed with the wrong secret", async () => {
    const { url } = await startServer(approve("not-the-secret"));
    expect(await createWebhookEscalation({ url, secret: "sec" })(req, decision)).toBe(false);
  });

  it("denies when the nonce is missing or belongs to another escalation", async () => {
    const missing = await startServer(() => ({
      status: 200,
      json: { approved: true },
      signWith: "sec",
    }));
    expect(await createWebhookEscalation({ url: missing.url, secret: "sec" })(req, decision)).toBe(
      false,
    );

    const replayed = await startServer(() => ({
      status: 200,
      json: { approved: true, nonce: "a-nonce-from-a-different-payment" },
      signWith: "sec",
    }));
    expect(await createWebhookEscalation({ url: replayed.url, secret: "sec" })(req, decision)).toBe(
      false,
    );
  });

  it("denies on { approved: false } and on a non-200 (fail-closed)", async () => {
    const denied = await startServer((e) => ({
      status: 200,
      json: { approved: false, nonce: e.nonce },
      signWith: "sec",
    }));
    expect(await createWebhookEscalation({ url: denied.url, secret: "sec" })(req, decision)).toBe(
      false,
    );

    const errored = await startServer(() => ({ status: 500, json: {}, signWith: "sec" }));
    expect(await createWebhookEscalation({ url: errored.url, secret: "sec" })(req, decision)).toBe(
      false,
    );
  });

  it("allows opting out of response signing for a trusted transport", async () => {
    const { url } = await startServer((e) => ({
      status: 200,
      json: { approved: true, nonce: e.nonce },
    }));
    const onEscalation = createWebhookEscalation({
      url,
      secret: "sec",
      requireSignedResponse: false,
    });
    expect(await onEscalation(req, decision)).toBe(true);
  });
});
