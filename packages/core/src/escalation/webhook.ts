import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { PaymentRequest, PolicyDecision } from "../types.js";

/** Header carrying the HMAC-SHA256 signature of the signed payload. */
export const SIGNATURE_HEADER = "x-agentctl-signature";
/** Header carrying the unix-seconds timestamp that is part of the signed payload. */
export const TIMESTAMP_HEADER = "x-agentctl-timestamp";

/** Default replay window for an escalation signature, in seconds. */
export const DEFAULT_SIGNATURE_TOLERANCE_SECONDS = 300;

/**
 * HMAC-SHA256 over `${timestamp}.${body}`, formatted `sha256=<hex>`.
 *
 * The timestamp is inside the signed payload (Stripe's scheme) so a captured
 * request cannot be replayed indefinitely — signing the body alone leaves every
 * past escalation request valid forever.
 */
export function signWebhook(secret: string, body: string, timestamp: number): string {
  const mac = createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
  return `sha256=${mac}`;
}

export interface VerifyWebhookOptions {
  /** Reject signatures older than this many seconds (default 300). 0 disables the check. */
  toleranceSeconds?: number;
  /** Clock override, in unix seconds (tests). */
  now?: number;
}

/**
 * Timing-safe verification of a webhook signature, including replay-window
 * enforcement on the signed timestamp.
 */
export function verifyWebhook(
  secret: string,
  body: string,
  signature: string,
  timestamp: number,
  opts: VerifyWebhookOptions = {},
): boolean {
  if (!Number.isFinite(timestamp)) return false;
  const tolerance = opts.toleranceSeconds ?? DEFAULT_SIGNATURE_TOLERANCE_SECONDS;
  if (tolerance > 0) {
    const now = opts.now ?? Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > tolerance) return false;
  }
  const expected = Buffer.from(signWebhook(secret, body, timestamp));
  const got = Buffer.from(signature);
  return expected.length === got.length && timingSafeEqual(expected, got);
}

export interface WebhookEscalationOptions {
  url: string;
  /** Shared secret used to sign the event, and to verify the approver's response. */
  secret: string;
  /** Approval must arrive within this window, else the payment is denied. */
  timeoutSeconds?: number;
  /**
   * Require the approver to sign its response (default true). The response must
   * echo the request's `nonce` and carry an `x-agentctl-signature` /
   * `x-agentctl-timestamp` pair over its own body. Set false ONLY for a trusted
   * transport (e.g. a loopback approver) — an unsigned 200 means anyone who can
   * answer the request can approve the payment.
   */
  requireSignedResponse?: boolean;
}

export interface EscalationEvent {
  type: "payment.escalation";
  /** Unix seconds; also part of the signed payload. */
  timestamp: number;
  /** Single-use id the approver must echo back in its response. */
  nonce: string;
  request: Omit<PaymentRequest, "amount"> & { amount: string };
  decision: PolicyDecision;
}

/** What an approver endpoint must return. */
export interface EscalationResponseBody {
  approved: boolean;
  /** Must equal the request event's nonce. */
  nonce?: string;
}

/**
 * Build an `onEscalation` handler that POSTs a signed escalation event to a
 * webhook and waits for a human decision.
 *
 * The payment proceeds only if the endpoint responds 200 with
 * `{ "approved": true, "nonce": "<the request nonce>" }` within the timeout AND
 * (unless `requireSignedResponse: false`) that response is itself HMAC-signed
 * with the shared secret. Any non-200, bad signature, wrong/absent nonce,
 * malformed body, timeout, or network error denies — fail-closed throughout.
 */
export function createWebhookEscalation(
  opts: WebhookEscalationOptions,
): (req: PaymentRequest, decision: PolicyDecision) => Promise<boolean> {
  const requireSignedResponse = opts.requireSignedResponse ?? true;
  return async (req, decision) => {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = randomUUID();
    const event: EscalationEvent = {
      type: "payment.escalation",
      timestamp,
      nonce,
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
          [SIGNATURE_HEADER]: signWebhook(opts.secret, body, timestamp),
          [TIMESTAMP_HEADER]: String(timestamp),
        },
        body,
        signal: controller.signal,
      });
      if (!res.ok) return false;

      const raw = await res.text();
      if (requireSignedResponse && !responseSignatureOk(opts.secret, res, raw)) return false;

      const data = JSON.parse(raw) as EscalationResponseBody;
      // The echoed nonce binds the approval to THIS escalation, so a replayed or
      // misrouted approval for a different payment cannot authorize this one.
      return data.approved === true && data.nonce === nonce;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  };
}

function responseSignatureOk(secret: string, res: Response, body: string): boolean {
  const signature = res.headers.get(SIGNATURE_HEADER);
  const timestamp = Number(res.headers.get(TIMESTAMP_HEADER));
  if (!signature || !Number.isFinite(timestamp)) return false;
  return verifyWebhook(secret, body, signature, timestamp);
}
