import { createHmac, timingSafeEqual } from "node:crypto";
import type { PaymentRequest, PolicyDecision } from "../types.js";

/** Header carrying the HMAC-SHA256 signature of the webhook body. */
export const SIGNATURE_HEADER = "x-agentctl-signature";

/** HMAC-SHA256 signature of a body, formatted `sha256=<hex>` (Stripe/CDP style). */
export function signWebhook(secret: string, body: string): string {
  return `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
}

/** Timing-safe verification of a webhook signature. */
export function verifyWebhook(secret: string, body: string, signature: string): boolean {
  const expected = Buffer.from(signWebhook(secret, body));
  const got = Buffer.from(signature);
  return expected.length === got.length && timingSafeEqual(expected, got);
}

export interface WebhookEscalationOptions {
  url: string;
  /** Shared secret used to sign the event so the receiver can verify it. */
  secret: string;
  /** Approval must arrive within this window, else the payment is denied. */
  timeoutSeconds?: number;
}

export interface EscalationEvent {
  type: "payment.escalation";
  request: Omit<PaymentRequest, "amount"> & { amount: string };
  decision: PolicyDecision;
}

/**
 * Build an `onEscalation` handler that POSTs a signed escalation event to a
 * webhook and waits for a human decision. The payment proceeds only if the
 * endpoint responds 200 with `{ "approved": true }` within the timeout; any
 * non-200, malformed body, timeout, or network error denies (fail-closed).
 */
export function createWebhookEscalation(
  opts: WebhookEscalationOptions,
): (req: PaymentRequest, decision: PolicyDecision) => Promise<boolean> {
  return async (req, decision) => {
    const event: EscalationEvent = {
      type: "payment.escalation",
      request: { ...req, amount: req.amount.toString() },
      decision,
    };
    const body = JSON.stringify(event);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), (opts.timeoutSeconds ?? 30) * 1000);
    try {
      const res = await fetch(opts.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          [SIGNATURE_HEADER]: signWebhook(opts.secret, body),
        },
        body,
        signal: controller.signal,
      });
      if (!res.ok) return false;
      const data = (await res.json().catch(() => ({}))) as { approved?: boolean };
      return data.approved === true;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  };
}
