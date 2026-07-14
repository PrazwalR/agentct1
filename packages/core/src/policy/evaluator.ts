import type { PaymentRequest, Policy, PolicyCheck, PolicyRule, SpendWindow } from "../types.js";
import {
  type RuleContext,
  type RuleResult,
  checkAllowlist,
  checkCounterparty,
  checkRateLimit,
  checkSpendCap,
  checkTimeWindow,
} from "./rules.js";

export interface EvaluationResult {
  checks: PolicyCheck[];
  /** At least one rule wants this payment escalated to a human. */
  escalate: boolean;
}

interface SpendRecord {
  ts: number;
  amount: bigint;
  token: string;
}

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

/**
 * Runs the deterministic policy rules against a payment request and tracks
 * per-agent runtime state (rolling spend windows, payment timestamps, seen
 * counterparties). State advances only on observe() — i.e. for payments that
 * actually settled — so dry-run evaluate() calls never mutate it.
 */
export class PolicyEvaluator {
  readonly anomalyThreshold: number;
  readonly anomalyAction: "block" | "escalate";

  private readonly payments: SpendRecord[] = [];
  private readonly seen = new Set<string>();

  constructor(private readonly policy: Policy) {
    this.anomalyThreshold = policy.anomalyThreshold;
    this.anomalyAction = policy.anomalyAction;
  }

  async evaluate(req: PaymentRequest): Promise<EvaluationResult> {
    const now = Date.now();
    const ctx: RuleContext = {
      req,
      now,
      windowedSpend: (window, token) => this.windowedSpend(window, token, now),
      recentPaymentCount: (windowSeconds) =>
        this.payments.filter((p) => p.ts > now - windowSeconds * 1000).length,
      isNewCounterparty: (addr) => !this.seen.has(addr.toLowerCase()),
    };

    const checks: PolicyCheck[] = [];
    let escalate = false;
    let spendCapRules = 0;
    let spendCapApplied = 0;
    for (const rule of this.policy.rules) {
      if (rule.type === "spend-cap") spendCapRules++;
      const res = dispatch(rule, ctx);
      if (res.check) {
        checks.push(res.check);
        if (rule.type === "spend-cap") spendCapApplied++;
      }
      if (res.escalate) escalate = true;
    }
    // A policy that declares spend-cap rules but none of them target this
    // payment's token silently gives it zero cap coverage (checkSpendCap skips
    // a non-matching token with no check entry at all). Surface that instead of
    // letting it pass invisibly — non-blocking (passed: true), purely visibility.
    if (spendCapRules > 0 && spendCapApplied === 0) {
      checks.push({
        id: "spend-cap-coverage",
        passed: true,
        severity: "warning",
        message: `no spend-cap rule targets token ${req.token} — this payment has no cap coverage`,
      });
    }
    return { checks, escalate };
  }

  /** Record a settled payment, advancing spend windows + counterparty memory. */
  observe(req: PaymentRequest): void {
    this.payments.push({ ts: Date.now(), amount: req.amount, token: req.token.toLowerCase() });
    this.seen.add(req.recipient.toLowerCase());
  }

  private windowedSpend(window: SpendWindow, token: string, now: number): bigint {
    const cutoff = window === "hour" ? now - HOUR_MS : window === "day" ? now - DAY_MS : 0; // session = all-time
    const t = token.toLowerCase();
    return this.payments
      .filter((p) => p.token === t && p.ts > cutoff)
      .reduce((sum, p) => sum + p.amount, 0n);
  }
}

function dispatch(rule: PolicyRule, ctx: RuleContext): RuleResult {
  switch (rule.type) {
    case "spend-cap":
      return checkSpendCap(rule, ctx);
    case "allowlist":
      return checkAllowlist(rule, ctx);
    case "rate-limit":
      return checkRateLimit(rule, ctx);
    case "counterparty":
      return checkCounterparty(rule, ctx);
    case "time-window":
      return checkTimeWindow(rule, ctx);
  }
}
