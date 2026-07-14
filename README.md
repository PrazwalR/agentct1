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

**Deferred** (documented, not yet built): Rust sidecar, Python/PyPI bindings,
Circle/Privy/Crossmint adapters, Permit2/USDT path, Solana, Postgres, OpenTelemetry,
multi-facilitator failover, the Isolation-Forest Phase-2 model (interface stubbed).

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

The Rust sidecar offloads the hot path at native speed: `POST /score` (Isolation
Forest) and `POST /inspect/{eip3009,permit2}` (EIP-712 digest + signer recovery). Its
digests are cross-checked byte-for-byte against viem's `hashTypedData`. Build/test with
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
4. **The anchor proves integrity, not correctness.** It proves a log entry wasn't altered
   after commitment — not that the decision was _correct_.
5. **Coupled to x402's trajectory.** The policy/behavioral/audit layers are
   protocol-agnostic; the x402 adapter is the coupling point.
6. **Use _with_ provider-level controls, not instead of them.** Defense in depth: provider
   TEE caps are the hard floor, agentctl is the intelligent layer above.

## LLM provider

The policy compiler and intent check work with either:

- **Anthropic** (`ANTHROPIC_API_KEY`) — default if set.
- **Ollama**, local, zero API key — run `ollama serve` + `ollama pull llama3.2`, then either
  set `OLLAMA_BASE_URL` or pass `{ provider: "ollama" }` / `--provider ollama` explicitly.
  Both compilePolicy/IntentReconciler and the CLI accept `{ provider, baseUrl, model }`.
  If neither is configured, both checks degrade gracefully (skip, don't throw) — the guard's
  policy/behavioral layers work with zero LLM configured at all.

## Environment

See [.env.example](.env.example). Key vars: `ANTHROPIC_API_KEY` or `OLLAMA_BASE_URL` (compiler + intent),
`CDP_API_KEY_ID`/`CDP_API_KEY_SECRET`/`CDP_WALLET_SECRET` or `AGENT_PRIVATE_KEY` (wallet),
`X402_FACILITATOR_URL`, `RPC_BASE_SEPOLIA`, `AUDIT_ANCHOR_ADDRESS`, `ANCHOR_COMMITTER_KEY`.

Base Sepolia USDC: `0x036CbD53842c5426634e7929541eC2318f3dCF7e`.
