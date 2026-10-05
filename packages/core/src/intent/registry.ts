import type { Address } from "viem";
import type { AuditEntry, PaymentRequest, PolicyCheck } from "../types.js";

/**
 * Binds a paid resource's host to the address it has been paid at before.
 *
 * This is the structural half of intent reconciliation, and it exists because the
 * LLM check is gated by an amount threshold — which left the overwhelming majority
 * of x402 traffic (sub-dollar micropayments) with no intent verification at all.
 *
 * The check is deterministic, needs no LLM and costs nothing, so it runs on every
 * payment regardless of size. It catches the signature of a redirected payment:
 * `api.weather.example` has always been paid at `0xAAA`, and this request says to
 * pay `0xBBB` instead. That is trust-on-first-use — the same idea as counterparty
 * novelty, but keyed by the resource rather than the address, which is what makes
 * it catch a *substituted payee for a familiar service*.
 *
 * It cannot help on a first-ever payment to a host; that case is what the
 * counterparty rule and the LLM check are for.
 */
export class ResourceRegistry {
  /** host → the set of addresses that host has been paid at. */
  private readonly bindings = new Map<string, Set<string>>();

  /** Extract the comparable host from a resource URL, or null if unusable. */
  static hostOf(resourceUrl: string | undefined): string | null {
    if (!resourceUrl) return null;
    try {
      const host = new URL(resourceUrl).host.toLowerCase();
      return host.length > 0 ? host : null;
    } catch {
      return null; // not a URL we can reason about
    }
  }

  /** Record that `host` was legitimately paid at `recipient`. */
  bind(resourceUrl: string | undefined, recipient: Address): void {
    const host = ResourceRegistry.hostOf(resourceUrl);
    if (!host) return;
    const set = this.bindings.get(host) ?? new Set<string>();
    set.add(recipient.toLowerCase());
    this.bindings.set(host, set);
  }

  /** Addresses known for a host (empty when the host has never been paid). */
  known(resourceUrl: string | undefined): string[] {
    const host = ResourceRegistry.hostOf(resourceUrl);
    return host ? [...(this.bindings.get(host) ?? [])] : [];
  }

  get size(): number {
    return this.bindings.size;
  }

  /** Seed from settled history so a restart does not forget every binding. */
  hydrate(entries: AuditEntry[]): void {
    for (const e of entries) this.bind(e.request.resourceUrl, e.request.recipient);
  }

  /**
   * Compare the request's recipient against what this host has been paid before.
   *
   * A mismatch is `critical`: a familiar service that suddenly names a different
   * payee is the clearest available signal of a redirected payment, and unlike the
   * LLM check it is deterministic enough to block on.
   */
  check(req: PaymentRequest): PolicyCheck {
    const id = "intent-resource-binding";
    const host = ResourceRegistry.hostOf(req.resourceUrl);
    if (!host) {
      return info(id, "no resource URL to bind against");
    }
    const known = this.bindings.get(host);
    if (!known || known.size === 0) {
      return {
        id,
        passed: true,
        severity: "warning",
        message: `first payment for resource ${host} — binding it to ${short(req.recipient)} on settle`,
      };
    }
    if (known.has(req.recipient.toLowerCase())) {
      return info(id, `${host} previously paid at ${short(req.recipient)}`);
    }
    return {
      id,
      passed: false,
      severity: "critical",
      message:
        `${host} has been paid at ${[...known].map(short).join(", ")} before, but this ` +
        `payment names ${short(req.recipient)}`,
    };
  }
}

const short = (a: string): string => `${a.slice(0, 10)}…`;

function info(id: string, message: string): PolicyCheck {
  return { id, passed: true, severity: "info", message };
}
