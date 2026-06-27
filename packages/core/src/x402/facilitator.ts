import { HTTPFacilitatorClient } from "@x402/core/http";

type Verify = HTTPFacilitatorClient["verify"];
type Settle = HTTPFacilitatorClient["settle"];

/**
 * Tries an ordered list of facilitators, falling over to the next one when a
 * call THROWS (network/HTTP error). It does NOT fail over on a returned
 * `{ success: false }`: that is a definitive settlement result, and retrying a
 * payment the primary may already have settled risks a double-spend. The
 * facilitator is a single point of failure (guide pitfall #2) — this removes it
 * for the programmatic settle path.
 */
export class FailoverFacilitatorClient {
  private readonly clients: HTTPFacilitatorClient[];

  constructor(clients: HTTPFacilitatorClient[]) {
    if (clients.length === 0) throw new Error("FailoverFacilitatorClient needs ≥1 facilitator");
    this.clients = clients;
  }

  /** Build from URLs (primary first). */
  static fromUrls(urls: string[]): FailoverFacilitatorClient {
    return new FailoverFacilitatorClient(urls.map((url) => new HTTPFacilitatorClient({ url })));
  }

  verify(...args: Parameters<Verify>): ReturnType<Verify> {
    return this.tryAll((c) => c.verify(...args)) as ReturnType<Verify>;
  }

  settle(...args: Parameters<Settle>): ReturnType<Settle> {
    return this.tryAll((c) => c.settle(...args)) as ReturnType<Settle>;
  }

  private async tryAll<R>(call: (c: HTTPFacilitatorClient) => Promise<R>): Promise<R> {
    let lastErr: unknown;
    for (const client of this.clients) {
      try {
        return await call(client);
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error("all facilitators failed");
  }
}
