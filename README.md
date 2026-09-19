# agentctl

**A policy & observability layer for autonomous AI agent payments.**

agentctl sits between an AI agent and its wallet: it enforces spending policy and
produces a tamper-evident audit trail for every autonomous x402 payment. It is the
safety + audit layer that agent-wallet providers assume you'll build yourself.

- **Not a wallet** — it never holds keys or custody. It wraps wallets you already use.
- **Not a facilitator** — it decides whether a payment _should_ proceed, then hands
  signing + settlement to the real x402 client / facilitator.
- **Harm reduction, not a guarantee** — it narrows the attack surface; it does not
  eliminate it.

## Status — MVP spine

This repo is the runnable spine from the build plan, targeting **Base Sepolia** with a
**Coinbase CDP** (or raw **viem**) wallet.

**Built & tested**

- Three-layer decision engine: deterministic **policy** rules + **behavioral** anomaly
  scoring (EWMA) + LLM **intent** reconciliation → `allow | escalate | block`.
- Policy rules: spend-cap (tx/session/hour/day, with `escalateAbove`), allowlist,
  rate-limit, counterparty-novelty, time-window.
- Natural-language → policy compiler (Claude Haiku, zod-validated output).
- x402 integration via the official `@x402/fetch` + `@x402/evm`: the guard injects at
  `onBeforePaymentCreation` (block before signing) and records at `onPaymentResponse`.
- Wallet adapters: `viem` (local key), `cdp` (CDP server wallet), `circle` + `privy`
  (MPC, via a viem remote-signer bridge).
- EIP-3009 signing (USDC) + **Permit2** witness path for any ERC-20 incl. USDT, with
  authorization inspection (recipient/amount-bound, random nonce).
- Behavioral: EWMA baselines + a real **Isolation Forest** for multivariate anomalies.
- **HMAC-signed escalation webhook** for human approval; **multi-facilitator failover**
  for the settle path; **OpenTelemetry** spans over evaluate/execute.
- Audit log in SQLite, Merkle-batched with `@openzeppelin/merkle-tree`, root committed
  on-chain via `AuditAnchor.sol`. Sorted-pair hashing matches the contract exactly.
- CLI: `check`, `policy create`, `audit --verify`, `watch`, `demo`.

The `circle` and `privy` adapters are optional peer deps — install the provider's SDK
(`@circle-fin/developer-controlled-wallets` / `@privy-io/server-auth`) to use them.

Also built: durable enforcement state (policy windows, counterparty memory, behavioral
baselines and the circuit breaker are rebuilt from the audit log on startup, so a rolling
cap like "max $20/day" survives a restart), and signed-authorization verification (what
the wallet actually signed is checked against what the policy approved, before settle).

**Not yet built**: framework-specific packages (`@agentctl/langchain` / `openai` /
`vercel` — a framework-agnostic `wrapPaymentTool` covers the TS side today), periodic
auto-anchoring (`anchorAudit()` is manual), `execute()` on Solana (Solana works through
`guardedFetch`), and TypeScript wiring for the Rust sidecar.

## Layout

```
packages/core    @agentctl/core   — engine, adapters, x402, audit, breaker, approvals
packages/server  @agentctl/server — HTTP control plane over a guard
packages/cli     @agentctl/cli    — the agentctl command (check/simulate/report/serve/…)
packages/python  agentctl (PyPI)  — thin Python bindings + LangChain middleware
crates/          agentctl-engine  — optional Rust hot-path sidecar (HTTP)
contracts        Foundry project  — AuditAnchor.sol
```

Beyond the guide, agentctl adds a **circuit breaker** (freeze a compromised agent),
**policy backtesting** (`agentctl simulate`), **spending analytics** (`agentctl report`),
a **human-in-the-loop approval queue**, and an **HTTP control plane** (`agentctl serve`
→ evaluate / approvals / breaker / report) so those are drivable from an operator UI.

The Rust sidecar is a **standalone service** for operators screening high payment volume:
`POST /score` (Isolation Forest) and `POST /inspect/{eip3009,permit2}` (EIP-712 digest +
signer recovery), with its digests cross-checked byte-for-byte against viem's
`hashTypedData`. Note that **the TypeScript engine does not call it yet** — it runs and is
tested on its own, but the hot path is still served by the TS implementations. Wiring it in
(with fallback to the TS path) is planned. Build/test with
`cargo test --manifest-path crates/agentctl-engine/Cargo.toml`.

EVM (Base) + **Solana** are both supported as guarded x402 chains; the audit store is
SQLite or **Postgres**. The Python bindings bridge to the TS engine via `agentctl eval`
(one decision engine, no duplicated logic).

## Install & build

```bash
pnpm install
pnpm -r build
pnpm -r test          # vitest
forge test --root contracts
```

## SDK quickstart

```ts
import { createGuard, ViemAdapter } from "@agentctl/core";
import { createGuardedFetch } from "@agentctl/core/x402";

const guard = await createGuard({
  wallet: new ViemAdapter({ privateKey: process.env.AGENT_PRIVATE_KEY as `0x${string}` }),
  policy: {
    naturalLanguage: "max $20/day, escalate anything over $2, only pay services you've used before",
    agentId: "research-agent-1",
  },
  llmApiKey: process.env.ANTHROPIC_API_KEY,
});

// Drop-in fetch: every x402 402 flows through policy + behavioral + intent checks.
const guardedFetch = await createGuardedFetch(guard);
const res = await guardedFetch("https://api.example/paid", {
  headers: { "x-agent-intent": "tomorrow's forecast for trip planning" },
});
```

`guard.evaluate(req)` returns a decision without executing; `guard.execute(req)` settles
a programmatic payment through the x402 facilitator.

### State & persistence

Rolling policy state is **rebuilt from the audit log** when a guard is created, so limits
hold across restarts rather than silently resetting:

| State                                                               | Rebuilt from                                       | Horizon        |
| ------------------------------------------------------------------- | -------------------------------------------------- | -------------- |
| `hour` / `day` spend windows                                        | settled entries                                    | last 24h       |
| counterparty memory (`counterparty`, `behavioral-new-counterparty`) | settled entries                                    | full lookback  |
| EWMA baselines + Isolation Forest                                   | settled entries, replayed at their real timestamps | last 10 000    |
| circuit breaker                                                     | every recorded decision                            | its own window |

`session` is the deliberate exception: it means _this process run_ and never carries over.
Pass `hydrate: false` for a throwaway or pure dry-run guard, or `hydrateLookbackMs` to
change the 30-day default.

```ts
const guard = await createGuard({ wallet, policy, auditStore: "./agentctl.sqlite" });
// day/hour caps, known counterparties and baselines are already warm here
```

### Escalation webhook contract

`createWebhookEscalation` signs `${timestamp}.${body}` (Stripe-style) and sends
`x-agentctl-signature` + `x-agentctl-timestamp`. The approver must reply `200` with
`{ "approved": true, "nonce": "<the event's nonce>" }` **and sign its own response the
same way** — an unsigned 200 is not enough to move money. Set
`requireSignedResponse: false` only for a trusted transport. Verify inbound requests with
`verifyWebhook(secret, body, signature, timestamp)`, which enforces a 5-minute replay
window by default.

## CLI

```bash
# Dry-run a payment against a policy (built-in demo policy if --policy omitted)
agentctl check --amount 15 --recipient 0x9999…99 --intent "buy compute"

# Compile a natural-language policy to JSON — Anthropic (needs ANTHROPIC_API_KEY),
# or a local Ollama (zero API key: `ollama serve` + `ollama pull llama3.2`)
agentctl policy create --agent research-agent-1 \
  --text "max \$20/day, escalate over \$2, only known APIs"
agentctl policy create --agent research-agent-1 --provider ollama \
  --text "max \$20/day, escalate over \$2, only known APIs"

# The killer demo — allow → escalate → block, recorded to the audit log
agentctl demo
agentctl audit            # show the trail
agentctl audit --verify   # verify each entry against the on-chain Merkle root
```

## On-chain audit anchor (manual)

```bash
# 1. Deploy AuditAnchor to Base Sepolia
forge script script/Deploy.s.sol --root contracts --rpc-url base_sepolia --broadcast
# 2. Set AUDIT_ANCHOR_ADDRESS + ANCHOR_COMMITTER_KEY + RPC_BASE_SEPOLIA in .env
# 3. guard.anchorAudit() batches unanchored entries and commits the root.
#    agentctl audit --verify then proves each entry against it.
```

## Honest limitations

1. **It cannot stop a sufficiently clever prompt injection.** If an injected intent is
   both benign-sounding and points at a plausible recipient, the intent reconciler may
   pass it. agentctl raises the bar; it is not impenetrable.
2. **Behavioral detection has a cold start.** With few observations it is rules-heavy and
   returns a near-zero score; it improves with traffic. Not clairvoyant on day one.
3. **The intent reconciler adds latency + cost.** Each semantic check is an LLM call, so
   it is gated by an amount threshold (default $1) rather than run on every micropayment.
4. **The anchor proves integrity and completeness, not correctness.** It proves an entry
   was recorded, unaltered — request, decision _and_ settlement outcome — at a known point
   in an unforkable per-operator history, and `--verify` cross-checks committed entry counts
   so a deletion shows up. It does _not_ prove the decision was right. It also cannot stop an
   operator from declining to anchor at all, or from anchoring a log that was already false
   when written.
5. **Coupled to x402's trajectory.** The policy/behavioral/audit layers are
   protocol-agnostic; the x402 adapter is the coupling point.
6. **Use _with_ provider-level controls, not instead of them.** Defense in depth: provider
   TEE caps are the hard floor, agentctl is the intelligent layer above.
7. **Intent checking is amount-gated, so most micropayments skip it.** The LLM check only
   runs above a threshold (default $1). Sub-threshold x402 traffic — which is most of it —
   is covered by the policy and behavioral layers only.
8. **Pending approvals do not survive a restart.** The approval queue holds live promises;
   a process that dies mid-escalation loses them (the request awaiting it is gone too). The
   escalation is still recorded to the audit log as denied.
9. **The anchor commits a subset of each entry.** The Merkle leaf covers the request,
   verdict and checks, but not `resourceUrl` or the settlement `txHash` — so those fields
   are logged but not yet tamper-evident.

## Trust model of the audit anchor

Worth being precise about, since "tamper-evident" is doing a lot of work:

- **Each operator has one unforkable history.** `commitBatch` names the head it extends, so
  the contract rejects a second, conflicting chain. An operator cannot quietly rewrite the
  past; they can only stop extending it.
- **The leaf binds chain id, anchor address and operator**, so a Sepolia root is not a
  mainnet root, and a published root cannot be replayed under someone else's address.
- **Verification needs no secrets** — `agentctl audit --verify --operator <address>` works
  for a third party.
- **The committer key is the trust boundary.** It is hot: it signs on every flush. If it
  runs in the same process as the policy engine, one host compromise yields both the log and
  the anchoring authority. Run it out-of-process where you can, and treat key compromise as
  invalidating the guarantee retroactively — the contract is immutable and has no revocation.
- **Timestamps are sequencer-attested, not wall-clock proof.** On Base, `block.timestamp` is
  set by a single sequencer (bounded drift, 2s granularity). The anchor proves ordering and
  integrity, not "this happened at exactly 14:03 UTC".
- **Pending approvals do not survive a restart** — the approval queue holds live promises.
  The escalation is still recorded as denied.

## LLM provider

The policy compiler and intent check work with either:

- **Anthropic** (`ANTHROPIC_API_KEY`) — default if set.
- **Ollama**, local, zero API key — run `ollama serve` + `ollama pull llama3.2`, then either
  set `OLLAMA_BASE_URL` or pass `{ provider: "ollama" }` / `--provider ollama` explicitly.
  Both compilePolicy/IntentReconciler and the CLI accept `{ provider, baseUrl, model }`.
  If neither is configured, both checks degrade gracefully (skip, don't throw) — the guard's
  policy/behavioral layers work with zero LLM configured at all.

## Environment

See [.env.example](.env.example). Variables the code actually reads:

| Variable                                                                        | Read by                                                  |
| ------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `ANTHROPIC_API_KEY`                                                             | policy compiler + intent reconciler (Anthropic provider) |
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL`                                               | policy compiler + intent reconciler (Ollama provider)    |
| `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET`, `CDP_WALLET_SECRET`, `CDP_ACCOUNT_NAME` | `CdpAdapter`                                             |
| `CIRCLE_API_KEY`, `CIRCLE_ENTITY_SECRET`                                        | `CircleAdapter`                                          |
| `PRIVY_APP_ID`, `PRIVY_APP_SECRET`                                              | `PrivyAdapter`                                           |
| `AUDIT_DB_PATH`                                                                 | default SQLite audit store path                          |
| `AUDIT_ANCHOR_ADDRESS`, `ANCHOR_COMMITTER_KEY`, `RPC_BASE_SEPOLIA`              | `agentctl audit --verify`                                |
| `AGENTCTL_ENGINE_HOST`, `AGENTCTL_ENGINE_PORT`, `AGENTCTL_ENGINE_TOKEN`         | the Rust sidecar binary                                  |

Everything else is passed in code: the facilitator URL via `facilitatorUrl`, the wallet key
via `new ViemAdapter({ privateKey })`, the audit store via `auditStore`.

Base Sepolia USDC: `0x036CbD53842c5426634e7929541eC2318f3dCF7e`.
