import {
  type IncomingMessage,
  type RequestListener,
  type Server,
  type ServerResponse,
  createServer,
} from "node:http";
import { type AgentGuard, type PaymentRequest, report } from "@agentctl/core";

export interface RateLimitOptions {
  windowMs: number;
  max: number;
}

export interface ControlPlaneOptions {
  /** If set, every route except /health requires `Authorization: Bearer <token>`. */
  token?: string;
  /** Per-client-IP rate limit (default 60 requests / 60s). Pass `false` to disable. */
  rateLimit?: RateLimitOptions | false;
}

export interface ServeOptions extends ControlPlaneOptions {
  port?: number;
  host?: string;
}

const DEFAULT_RATE_LIMIT: RateLimitOptions = { windowMs: 60_000, max: 60 };

function bigintReplacer(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? value.toString() : value;
}

function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body, bigintReplacer));
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  return raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
}

/** Fixed-window per-key request counter (in-process; fine for a single control-plane instance). */
class RateLimiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();

  constructor(private readonly opts: RateLimitOptions) {}

  allow(key: string, now = Date.now()): boolean {
    const entry = this.hits.get(key);
    if (!entry || now >= entry.resetAt) {
      this.hits.set(key, { count: 1, resetAt: now + this.opts.windowMs });
      return true;
    }
    if (entry.count >= this.opts.max) return false;
    entry.count++;
    return true;
  }
}

/**
 * A Node http request handler exposing a guard's control surface. Turns the
 * in-process approval queue + circuit breaker into a remotely-drivable control
 * plane so an operator UI / CLI can list and resolve escalations, check/reset the
 * breaker, dry-run policy, and pull analytics.
 *
 *   GET  /health                         (always open — no auth, no rate limit)
 *   POST /evaluate                     { request: {...} } -> { decision }
 *   GET  /approvals                    -> { pending: [...] }
 *   POST /approvals/:id/approve|deny   -> { resolved }
 *   GET  /breaker                      -> { state, counts }
 *   POST /breaker/reset                -> { state }
 *   GET  /report                       -> { report }
 */
export function createControlPlaneHandler(
  guard: AgentGuard,
  opts: ControlPlaneOptions = {},
): RequestListener {
  const limiter =
    opts.rateLimit === false ? undefined : new RateLimiter(opts.rateLimit ?? DEFAULT_RATE_LIMIT);
  return (req, res) => {
    void handle(guard, opts, limiter, req, res).catch((err) =>
      send(res, 400, { error: err instanceof Error ? err.message : String(err) }),
    );
  };
}

async function handle(
  guard: AgentGuard,
  opts: ControlPlaneOptions,
  limiter: RateLimiter | undefined,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;
  const method = req.method ?? "GET";

  // Unauthenticated and unlimited so orchestrator liveness probes (which
  // typically can't send custom headers) and health monitoring always work.
  if (method === "GET" && path === "/health") return send(res, 200, { status: "ok" });

  if (limiter && !limiter.allow(req.socket.remoteAddress ?? "unknown")) {
    return send(res, 429, { error: "rate limit exceeded" });
  }

  if (opts.token && req.headers.authorization !== `Bearer ${opts.token}`) {
    return send(res, 401, { error: "unauthorized" });
  }

  if (method === "POST" && path === "/evaluate") {
    const body = await readJson(req);
    const r = (body.request ?? body) as Record<string, unknown>;
    const paymentReq: PaymentRequest = {
      intent: (r.intent as string) ?? "",
      amount: BigInt(r.amount as string | number),
      token: r.token as `0x${string}`,
      recipient: r.recipient as `0x${string}`,
      chain: (r.chain as string) ?? "eip155:84532",
      agentId: (r.agentId as string) ?? guard.agentId,
      resourceUrl: r.resourceUrl as string | undefined,
    };
    return send(res, 200, { decision: await guard.evaluate(paymentReq) });
  }

  if (method === "GET" && path === "/approvals") {
    return send(res, 200, { pending: guard.approvalQueue?.list() ?? [] });
  }

  const m = path.match(/^\/approvals\/([^/]+)\/(approve|deny)$/);
  if (method === "POST" && m) {
    const [, id, action] = m;
    const resolved = guard.approvalQueue?.resolve(id!, action === "approve") ?? false;
    return send(res, resolved ? 200 : 404, { resolved });
  }

  if (method === "GET" && path === "/breaker") {
    const b = guard.circuitBreaker;
    return send(res, 200, b ? { state: b.state(), counts: b.counts() } : { state: "disabled" });
  }
  if (method === "POST" && path === "/breaker/reset") {
    guard.resetCircuitBreaker();
    return send(res, 200, { state: guard.circuitBreaker?.state() ?? "disabled" });
  }

  if (method === "GET" && path === "/report") {
    return send(res, 200, { report: report(await guard.auditLog.list()) });
  }

  send(res, 404, { error: "not found" });
}

/** Start the control plane on a port (default 8787). */
export function serveControlPlane(guard: AgentGuard, opts: ServeOptions = {}): Promise<Server> {
  const server = createServer(createControlPlaneHandler(guard, opts));
  return new Promise((resolve) => {
    server.listen(opts.port ?? 8787, opts.host ?? "127.0.0.1", () => resolve(server));
  });
}
