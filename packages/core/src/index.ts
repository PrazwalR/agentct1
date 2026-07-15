import type { Hex } from "viem";
import { wrapFetchWithPayment, x402Client } from "@x402/fetch";
import type { PaymentRequired, PaymentRequirements } from "@x402/fetch";
import { ExactEvmScheme, toClientEvmSigner } from "@x402/evm";
import { HTTPFacilitatorClient } from "@x402/core/http";
import { FailoverFacilitatorClient } from "./x402/facilitator.js";

import type {
  IWalletAdapter,
  PaymentRequest,
  Policy,
  PolicyCheck,
  PolicyDecision,
  Settlement,
  Verdict,
} from "./types.js";
import { DEFAULT_TESTNET_FACILITATOR, getChain } from "./constants.js";
import { makePublicClient as makePublicClientFor } from "./adapters/base.js";
import { PolicyEvaluator } from "./policy/evaluator.js";
import { compilePolicy } from "./policy/compiler.js";
import { BehavioralScorer, type BehavioralOptions } from "./behavioral/isolation.js";
import { IntentReconciler } from "./intent/reconcile.js";
import { AuditLogger, type AnchorConfig } from "./audit/logger.js";
import {
  type GuardedFetchOptions,
  type IntentStore,
  headerValue,
  intentStore,
  requirementsToPaymentRequest,
} from "./x402/interceptor.js";
import { type WebhookEscalationOptions, createWebhookEscalation } from "./escalation/webhook.js";
import { decisionAttrs, paymentAttrs, withSpan } from "./tracing.js";
import { type ClientSvmSigner, registerSvmScheme } from "./x402/svm.js";
import { SOLANA_MAINNET_CAIP2 } from "./solana.js";
import { CircuitBreaker, type CircuitBreakerConfig } from "./circuit-breaker.js";
import type { ApprovalQueue } from "./approval-queue.js";
import type { LLMConfig } from "./llm/client.js";

export interface GuardConfig {
  /** Wallet adapter used for signing + execution. */
  wallet: IWalletAdapter;
  /** Policy — structured, or natural-language to be compiled. */
  policy: Policy | { naturalLanguage: string; agentId: string; chain?: string };
  /** Anthropic API key for NL policy compilation + intent checks. Shortcut for `llm: { apiKey }`. */
  llmApiKey?: string;
  /** LLM config for NL policy compilation + intent checks — pass { provider: "ollama" } for a
   *  local, zero-API-key option (needs `ollama serve` running). Overrides llmApiKey if both set. */
  llm?: LLMConfig;
  /** Audit storage: "sqlite" (default) or a Postgres connection string. */
  auditStore?: string;
  /** On-chain Merkle anchor config. */
  anchor?: AnchorConfig;
  /** x402 facilitator URL (default: Base Sepolia testnet facilitator). */
  facilitatorUrl?: string;
  /** Fallback facilitator URLs, tried in order if the primary throws. */
  facilitatorFallbackUrls?: string[];
  /** RPC override for balance reads / on-chain reads. */
  rpcUrl?: string;
  /** Called on an "escalate" verdict. Return true to approve. Default: deny. */
  onEscalation?: (req: PaymentRequest, decision: PolicyDecision) => Promise<boolean>;
  /** HMAC-signed webhook for human approval on escalate (used if onEscalation unset). */
  escalationWebhook?: WebhookEscalationOptions;
  /** Human-in-the-loop queue: escalated payments park here until resolve()d. */
  approvalQueue?: ApprovalQueue;
  /** Also accept Solana x402 payments: provide an SVM signer (and optional network). */
  solana?: { signer: ClientSvmSigner; network?: string };
  /** Kill-switch: freeze the agent after repeated blocks/anomalies in a window. */
  circuitBreaker?: CircuitBreakerConfig;
  /** Tuning for the behavioral Isolation Forest. */
  behavioral?: BehavioralOptions;
}

export interface ExecuteResult {
  executed: boolean;
  decision: PolicyDecision;
  settlement?: Settlement;
  reason?: string;
}

interface Spine {
  guardedClient: x402Client;
  plainClient: x402Client;
  facilitator: HTTPFacilitatorClient | FailoverFacilitatorClient;
}

export class AgentGuard {
  readonly agentId: string;
  private readonly wallet: IWalletAdapter;
  private readonly evaluator: PolicyEvaluator;
  private readonly behavioral: BehavioralScorer;
  private readonly intent: IntentReconciler;
  private readonly audit: AuditLogger;
  private readonly facilitatorUrl: string;
  private readonly facilitatorFallbackUrls?: string[];
  private readonly rpcUrl?: string;
  private readonly onEscalation?: GuardConfig["onEscalation"];
  private readonly _approvalQueue?: ApprovalQueue;
  private readonly solana?: GuardConfig["solana"];
  private readonly breaker?: CircuitBreaker;
  private spine?: Spine;

  private constructor(policy: Policy, config: GuardConfig) {
    this.agentId = policy.agentId;
    this.wallet = config.wallet;
    this.evaluator = new PolicyEvaluator(policy);
    this.behavioral = new BehavioralScorer(policy.agentId, config.behavioral);
    this.intent = new IntentReconciler(resolveGuardLLMConfig(config));
    this.audit = new AuditLogger(config.auditStore ?? "sqlite", config.anchor);
    this.facilitatorUrl = config.facilitatorUrl ?? DEFAULT_TESTNET_FACILITATOR;
    this.facilitatorFallbackUrls = config.facilitatorFallbackUrls;
    this.rpcUrl = config.rpcUrl;
    this._approvalQueue = config.approvalQueue;
    this.onEscalation =
      config.onEscalation ??
      (config.approvalQueue
        ? (req, decision) => config.approvalQueue!.enqueue(req, decision)
        : config.escalationWebhook
          ? createWebhookEscalation(config.escalationWebhook)
          : undefined);
    this.solana = config.solana;
    this.breaker = config.circuitBreaker ? new CircuitBreaker(config.circuitBreaker) : undefined;
  }

  /** Async factory — compiles NL policy if needed. */
  static async create(config: GuardConfig): Promise<AgentGuard> {
    const policy: Policy =
      "naturalLanguage" in config.policy
        ? await compilePolicy(
            config.policy.naturalLanguage,
            config.policy.agentId,
            resolveGuardLLMConfig(config),
            config.policy.chain ?? config.wallet.chain,
          )
        : config.policy;
    return new AgentGuard(policy, config);
  }

  /** Audit log accessor (CLI / tests). */
  get auditLog(): AuditLogger {
    return this.audit;
  }

  /** Batch unanchored audit entries into a Merkle tree and commit on-chain. */
  async anchorAudit() {
    return this.audit.flush();
  }

  /** The agent's circuit breaker, if configured (state / counts / manual reset). */
  get circuitBreaker(): CircuitBreaker | undefined {
    return this.breaker;
  }

  /** Manually close the circuit breaker after human review. */
  resetCircuitBreaker(): void {
    this.breaker?.reset();
  }

  /** The pending-approval queue, if configured (list / resolve escalated payments). */
  get approvalQueue(): ApprovalQueue | undefined {
    return this._approvalQueue;
  }

  /**
   * Evaluate a payment against all three layers WITHOUT executing.
   * Returns a decision; call execute() (or use guardedFetch) to proceed.
   */
  async evaluate(req: PaymentRequest): Promise<PolicyDecision> {
    return withSpan("agentctl.evaluate", paymentAttrs(req), async (span) => {
      if (this.breaker?.isOpen()) {
        const decision: PolicyDecision = {
          verdict: "block",
          riskScore: 1,
          checks: [
            {
              id: "circuit-breaker",
              passed: false,
              severity: "critical",
              message: "circuit breaker open — agent frozen after repeated failures",
            },
          ],
          reason: "Blocked: circuit breaker open (agent frozen; reset required)",
        };
        span.setAttributes(decisionAttrs(decision));
        return decision;
      }

      // Reject non-positive amounts at the boundary rather than letting them reach
      // signing (where they fail cryptically): a negative amount is below every
      // spend cap and would otherwise aggregate to "allow". Fail closed, auditable.
      if (req.amount <= 0n) {
        const decision: PolicyDecision = {
          verdict: "block",
          riskScore: 1,
          checks: [
            {
              id: "invalid-amount",
              passed: false,
              severity: "critical",
              message: `payment amount must be positive (got ${req.amount})`,
            },
          ],
          reason: `Blocked: payment amount must be positive (got ${req.amount})`,
        };
        span.setAttributes(decisionAttrs(decision));
        return decision;
      }

      const { checks: policyChecks, escalate: policyEscalate } = await this.evaluator.evaluate(req);
      const { score, anomalyChecks } = await this.behavioral.score(req);
      const intentCheck = await this.intent.check(req);
      const checks: PolicyCheck[] = [...policyChecks, ...anomalyChecks, intentCheck];

      const verdict = aggregateVerdict(checks, score, {
        anomalyThreshold: this.evaluator.anomalyThreshold,
        anomalyAction: this.evaluator.anomalyAction,
        policyEscalate,
      });

      const decision: PolicyDecision = {
        verdict,
        riskScore: score,
        checks,
        reason: buildReason(verdict, checks, score),
      };
      span.setAttributes(decisionAttrs(decision));
      return decision;
    });
  }

  /**
   * Evaluate, and if allowed, settle the payment programmatically via the x402
   * facilitator (no HTTP 402 required). Records to the audit log regardless.
   */
  async execute(req: PaymentRequest): Promise<ExecuteResult> {
    return withSpan("agentctl.execute", paymentAttrs(req), async (span) => {
      const { decision, allowed } = await this.runGuard(req);
      span.setAttributes(decisionAttrs(decision));
      if (!allowed) {
        await this.audit.record(req, decision);
        span.setAttribute("agentctl.executed", false);
        return {
          executed: false,
          decision,
          reason:
            decision.verdict === "block" ? "blocked by policy" : "escalation denied/timed out",
        };
      }

      const { plainClient, facilitator } = await this.ensureSpine();
      const paymentRequired = this.toPaymentRequired(req);
      const requirements = paymentRequired.accepts[0];
      if (!requirements) throw new Error("internal: no payment requirements built");

      const payload = await plainClient.createPaymentPayload(paymentRequired);
      const settleResp = await facilitator.settle(payload, requirements);
      const settlement: Settlement = {
        txHash: settleResp.success ? (settleResp.transaction as Hex) : undefined,
        success: settleResp.success,
        facilitator: this.facilitatorUrl,
      };

      if (settlement.success) {
        await this.behavioral.observe(req);
        this.evaluator.observe(req);
      }
      await this.audit.record(req, decision, settlement);
      span.setAttribute("agentctl.executed", settlement.success);
      if (settlement.txHash) span.setAttribute("agentctl.tx_hash", settlement.txHash);
      return { executed: settlement.success, decision, settlement, reason: settleResp.errorReason };
    });
  }

  /**
   * Returns a drop-in `fetch` that routes every x402 payment through the guard.
   * The library handles the 402 → sign → settle → retry loop; agentctl injects
   * the policy decision (before signing) and audit recording (after settle).
   */
  async guardedFetch(opts: GuardedFetchOptions = {}): Promise<typeof fetch> {
    const { guardedClient } = await this.ensureSpine();
    const baseFetch = opts.fetch ?? fetch;
    const wrapped = wrapFetchWithPayment(baseFetch, guardedClient);

    return (async (
      input: Parameters<typeof fetch>[0],
      init?: Parameters<typeof fetch>[1],
    ): Promise<Response> => {
      const intent = headerValue(init?.headers, "x-agent-intent");
      const resourceUrl =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const store: IntentStore = { intent, resourceUrl, pending: [] };

      return intentStore.run(store, async () => {
        try {
          return await wrapped(input, init);
        } catch (err) {
          // A guard abort surfaces as a throw from wrapFetchWithPayment.
          const last = store.pending.at(-1);
          if (last && last.decision.verdict !== "allow") {
            return new Response(
              JSON.stringify({
                error: "Payment blocked by agentctl",
                reason: last.decision.reason,
                decision: last.decision,
              }),
              { status: 403, headers: { "content-type": "application/json" } },
            );
          }
          throw err;
        }
      });
    }) as typeof fetch;
  }

  // ─── internals ─────────────────────────────────────────────────────────────

  private async runGuard(
    req: PaymentRequest,
  ): Promise<{ decision: PolicyDecision; allowed: boolean }> {
    const decision = await this.evaluate(req);
    // Feed real payment attempts to the breaker (dry-run evaluate() does not record).
    if (this.breaker) {
      const anomaly = decision.checks.some((c) => !c.passed && c.id.startsWith("behavioral-"));
      this.breaker.record(decision.verdict, anomaly);
    }
    if (decision.verdict === "block") return { decision, allowed: false };
    if (decision.verdict === "escalate") {
      const ok = this.onEscalation ? await this.onEscalation(req, decision) : false;
      return { decision, allowed: ok };
    }
    return { decision, allowed: true };
  }

  private async ensureSpine(): Promise<Spine> {
    if (this.spine) return this.spine;
    const account = await this.wallet.getSigner();
    const publicClient = makePublicClientFor(this.wallet.chain, this.rpcUrl);
    const signer = toClientEvmSigner(account, publicClient);
    const facilitator =
      this.facilitatorFallbackUrls && this.facilitatorFallbackUrls.length > 0
        ? FailoverFacilitatorClient.fromUrls([this.facilitatorUrl, ...this.facilitatorFallbackUrls])
        : new HTTPFacilitatorClient({ url: this.facilitatorUrl });
    const network = this.wallet.chain as `${string}:${string}`;

    const guardedClient = new x402Client()
      .register(network, new ExactEvmScheme(signer))
      .onBeforePaymentCreation(async (ctx) => {
        const store = intentStore.getStore();
        const req = requirementsToPaymentRequest(ctx.selectedRequirements, this.agentId, store);
        const { decision, allowed } = await this.runGuard(req);
        store?.pending.push({ req, decision });
        if (!allowed) return { abort: true, reason: decision.reason };
        return;
      })
      .onPaymentResponse(async (ctx) => {
        const store = intentStore.getStore();
        const pending = store?.pending.pop();
        if (!pending) return;
        const settlement: Settlement | undefined = ctx.settleResponse
          ? {
              txHash: ctx.settleResponse.success
                ? (ctx.settleResponse.transaction as Hex)
                : undefined,
              success: ctx.settleResponse.success,
              facilitator: this.facilitatorUrl,
            }
          : undefined;
        if (settlement?.success) {
          await this.behavioral.observe(pending.req);
          this.evaluator.observe(pending.req);
        }
        await this.audit.record(pending.req, pending.decision, settlement);
        return;
      });

    const plainClient = new x402Client().register(network, new ExactEvmScheme(signer));

    if (this.solana) {
      const svmNetwork = this.solana.network ?? SOLANA_MAINNET_CAIP2;
      registerSvmScheme(guardedClient, this.solana.signer, svmNetwork);
      registerSvmScheme(plainClient, this.solana.signer, svmNetwork);
    }

    this.spine = { guardedClient, plainClient, facilitator };
    return this.spine;
  }

  private toPaymentRequired(req: PaymentRequest): PaymentRequired {
    const chain = getChain(req.chain);
    const requirements: PaymentRequirements = {
      scheme: "exact",
      network: req.chain as `${string}:${string}`,
      asset: req.token,
      amount: req.amount.toString(),
      payTo: req.recipient,
      maxTimeoutSeconds: 3600,
      extra: { name: chain.usdcDomain.name, version: chain.usdcDomain.version },
    };
    return {
      x402Version: 2,
      resource: { url: req.resourceUrl ?? `agentctl://manual/${req.agentId}` },
      accepts: [requirements],
    };
  }
}

/**
 * Aggregate the three layers into a verdict. Policy/intent criticals (allowlist,
 * spend-cap, intent mismatch) always hard-block; behavioral anomalies — including a
 * critical amount spike — are routed through anomalyAction so an operator who chose
 * "escalate" gets an escalation, not a silent hard block.
 */
export function aggregateVerdict(
  checks: PolicyCheck[],
  score: number,
  opts: { anomalyThreshold: number; anomalyAction: "block" | "escalate"; policyEscalate: boolean },
): Verdict {
  const hardCritical = checks.some(
    (c) => !c.passed && c.severity === "critical" && !c.id.startsWith("behavioral-"),
  );
  const behavioralCritical = checks.some(
    (c) => !c.passed && c.severity === "critical" && c.id.startsWith("behavioral-"),
  );
  const anomalyTriggered = score >= opts.anomalyThreshold || behavioralCritical;

  if (hardCritical || (anomalyTriggered && opts.anomalyAction === "block")) return "block";
  if (opts.policyEscalate || (anomalyTriggered && opts.anomalyAction === "escalate")) {
    return "escalate";
  }
  return "allow";
}

/** `llm` (if set) takes precedence; `llmApiKey` is a back-compat shortcut for Anthropic. */
function resolveGuardLLMConfig(config: GuardConfig): LLMConfig {
  return config.llm ?? (config.llmApiKey ? { apiKey: config.llmApiKey } : {});
}

function buildReason(verdict: Verdict, checks: PolicyCheck[], score: number): string {
  const risk = `risk ${score.toFixed(2)}`;
  if (verdict === "allow") return `Allowed (${risk})`;
  const failed = checks
    .filter((c) => !c.passed)
    .map((c) => c.message)
    .join("; ");
  const verb = verdict === "block" ? "Blocked" : "Escalated";
  return failed ? `${verb} (${risk}): ${failed}` : `${verb} (${risk})`;
}

/** Convenience factory. */
export async function createGuard(config: GuardConfig): Promise<AgentGuard> {
  return AgentGuard.create(config);
}

// ─── Re-exports for SDK + CLI consumers ──────────────────────────────────────
export { ViemAdapter } from "./adapters/viem.js";
export { CdpAdapter } from "./adapters/cdp.js";
export { CircleAdapter } from "./adapters/circle.js";
export { PrivyAdapter } from "./adapters/privy.js";
export { createRemoteSignerAccount, eip712ToJson } from "./adapters/remote-signer.js";
export type { CircleAdapterConfig } from "./adapters/circle.js";
export type { PrivyAdapterConfig } from "./adapters/privy.js";
export { compilePolicy, compilePolicyObject } from "./policy/compiler.js";
export { callLLM, resolveLLMConfig } from "./llm/client.js";
export type { LLMConfig, LLMProvider, LLMCallParams } from "./llm/client.js";
export { PolicyEvaluator } from "./policy/evaluator.js";
export { BehavioralScorer } from "./behavioral/isolation.js";
export type { BehavioralOptions, BehavioralResult } from "./behavioral/isolation.js";
export { IsolationForest } from "./behavioral/forest.js";
export type { ForestOptions } from "./behavioral/forest.js";
export { policyToJSON, policyFromJSON } from "./policy/serde.js";
export { simulatePolicy } from "./policy/simulate.js";
export type { SimulationResult, SimulationEntry } from "./policy/simulate.js";
export { CircuitBreaker } from "./circuit-breaker.js";
export type { CircuitBreakerConfig, CircuitState } from "./circuit-breaker.js";
export { report } from "./analytics.js";
export type { AnalyticsReport, CounterpartyStat } from "./analytics.js";
export { ApprovalQueue } from "./approval-queue.js";
export type { PendingApproval, ApprovalQueueOptions } from "./approval-queue.js";
export { wrapPaymentTool, toPaymentRequest } from "./integrations.js";
export type { PaymentToolInput, BlockedToolResult } from "./integrations.js";
export {
  signWebhook,
  verifyWebhook,
  createWebhookEscalation,
  SIGNATURE_HEADER,
} from "./escalation/webhook.js";
export type { WebhookEscalationOptions, EscalationEvent } from "./escalation/webhook.js";
export { AuditLogger, hashEntry } from "./audit/logger.js";
export type { AnchorConfig, FlushResult, EntryProof } from "./audit/logger.js";
export { SqliteAuditStore } from "./audit/store.js";
export type { AuditStore, StoredEntry } from "./audit/store.js";
export { PostgresAuditStore } from "./audit/postgres-store.js";
export { MerkleAuditBatch, entryToLeaf } from "./audit/merkle.js";
export { AuditAnchorClient, AUDIT_ANCHOR_ABI } from "./audit/anchor.js";
export {
  signEIP3009Authorization,
  inspectAuthorization,
  randomNonce,
  InFlightNonceTracker,
} from "./x402/eip3009.js";
export {
  signPermit2Authorization,
  inspectPermit2Authorization,
  permit2ApprovalNeeded,
  buildPermit2Approval,
} from "./x402/permit2.js";
export { FailoverFacilitatorClient } from "./x402/facilitator.js";
export { registerSvmScheme } from "./x402/svm.js";
export type { ClientSvmSigner } from "./x402/svm.js";
export {
  SOLANA_MAINNET_CAIP2,
  SOLANA_DEVNET_CAIP2,
  SOLANA_TESTNET_CAIP2,
  SOLANA_USDC_MAINNET,
  SOLANA_USDC_DEVNET,
  SOLANA_NETWORKS,
  isSolanaNetwork,
  getSolanaUsdc,
  validateSvmAddress,
} from "./solana.js";
export { getTracer, withSpan, paymentAttrs, decisionAttrs } from "./tracing.js";
export type { SpanAttrs } from "./tracing.js";
export {
  CHAINS,
  DEFAULT_TESTNET_FACILITATOR,
  USDC_DECIMALS,
  EIP3009_TOKENS,
  getChain,
  recommendedAuthMethod,
} from "./constants.js";
export type {
  SignedAuthorization,
  SignedPermit2Authorization,
  Permit2Authorization,
  AuthMethod,
} from "./types.js";

export type {
  PaymentRequest,
  PolicyDecision,
  PolicyCheck,
  Policy,
  PolicyRule,
  IWalletAdapter,
  Settlement,
  AuditEntry,
  Verdict,
} from "./types.js";
