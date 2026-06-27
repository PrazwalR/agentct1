import { AsyncLocalStorage } from "node:async_hooks";
import type { Address } from "viem";
import type { PaymentRequirements } from "@x402/fetch";
import type { PaymentRequest, PolicyDecision } from "../types.js";

export interface GuardedFetchOptions {
  /** Underlying fetch to wrap (default: global fetch). */
  fetch?: typeof fetch;
}

export interface IntentStore {
  /** The agent's stated intent for the current request (from x-agent-intent). */
  intent?: string;
  /** Resource URL being requested. */
  resourceUrl?: string;
  /** Decisions made during this request, popped by the response hook for audit. */
  pending: Array<{ req: PaymentRequest; decision: PolicyDecision }>;
}

/**
 * Request-scoped store. The x402 before-payment hook has no access to the
 * original HTTP request, so guardedFetch stashes the intent here and the hook
 * reads it. AsyncLocalStorage keeps this correct under concurrent requests.
 */
export const intentStore = new AsyncLocalStorage<IntentStore>();

/** The headers type the global fetch accepts (HeadersInit | undefined), without naming DOM types. */
type FetchHeaders = NonNullable<Parameters<typeof fetch>[1]>["headers"];

/** Read a header value from any HeadersInit shape. */
export function headerValue(headers: FetchHeaders, name: string): string | undefined {
  if (!headers) return undefined;
  const lname = name.toLowerCase();
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (Array.isArray(headers)) {
    return headers.find((pair) => pair[0]?.toLowerCase() === lname)?.[1];
  }
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lname) return v as string;
  }
  return undefined;
}

/** Map x402 PaymentRequirements (+ request-scoped intent) → agentctl PaymentRequest. */
export function requirementsToPaymentRequest(
  r: PaymentRequirements,
  agentId: string,
  store?: IntentStore,
): PaymentRequest {
  return {
    intent: store?.intent ?? `Pay for resource at ${store?.resourceUrl ?? r.payTo}`,
    amount: BigInt(r.amount),
    token: r.asset as Address,
    recipient: r.payTo as Address,
    chain: r.network,
    agentId,
    resourceUrl: store?.resourceUrl,
  };
}
