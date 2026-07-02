import { formatUnits } from "viem";
import type {
  AllowlistRule,
  CounterpartyRule,
  PaymentRequest,
  PolicyCheck,
  RateLimitRule,
  SpendCapRule,
  SpendWindow,
  TimeWindowRule,
} from "../types.js";

/** Snapshot of agent state a rule needs, computed by the evaluator. */
export interface RuleContext {
  req: PaymentRequest;
  now: number;
  /** Already-spent total (excluding the current request) in a window, for a token. */
  windowedSpend: (window: SpendWindow, token: string) => bigint;
  /** Count of payments within the last `windowSeconds` (excluding current). */
  recentPaymentCount: (windowSeconds: number) => number;
  isNewCounterparty: (addr: string) => boolean;
}

export interface RuleResult {
  check: PolicyCheck | null;
  /** This rule wants the payment escalated to a human. */
  escalate: boolean;
}

const usdc = (v: bigint): string => `${formatUnits(v, 6)} USDC`;
const pass = (id: string, message: string): RuleResult => ({
  check: { id, passed: true, severity: "info", message },
  escalate: false,
});

export function checkSpendCap(rule: SpendCapRule, ctx: RuleContext): RuleResult {
  if (rule.token.toLowerCase() !== ctx.req.token.toLowerCase()) {
    return { check: null, escalate: false };
  }
  const id = `spend-cap-${rule.window}`;
  const amount = ctx.req.amount;
  const prior = rule.window === "transaction" ? 0n : ctx.windowedSpend(rule.window, rule.token);
  const total = prior + amount;

  if (total > rule.maxAmount) {
    return {
      check: {
        id,
        passed: false,
        severity: "critical",
        message: `${rule.window} spend ${usdc(total)} would exceed cap ${usdc(rule.maxAmount)}`,
      },
      escalate: false,
    };
  }
  if (rule.escalateAbove !== undefined && amount > rule.escalateAbove) {
    return {
      check: {
        id,
        passed: false,
        severity: "warning",
        message: `amount ${usdc(amount)} over escalation threshold ${usdc(rule.escalateAbove)}`,
      },
      escalate: true,
    };
  }
  return pass(id, `within ${rule.window} cap (${usdc(total)} / ${usdc(rule.maxAmount)})`);
}

export function checkAllowlist(rule: AllowlistRule, ctx: RuleContext): RuleResult {
  const id = `allowlist-${rule.mode}`;
  const target =
    rule.mode === "recipients" ? ctx.req.recipient.toLowerCase() : (ctx.req.resourceUrl ?? "");
  // Drop empty entries: for resources mode `target.includes("")` is always true,
  // which would silently turn an enforced allowlist into a no-op.
  const entries = rule.entries.filter((e) => e.length > 0);
  const ok =
    rule.mode === "recipients"
      ? entries.includes(target)
      : target.length > 0 && entries.some((e) => target.includes(e));

  if (ok) return pass(id, `${rule.mode} allowlisted`);
  if (rule.enforce) {
    return {
      check: {
        id,
        passed: false,
        severity: "critical",
        message: `${rule.mode} ${target || "(none)"} not on allowlist`,
      },
      escalate: false,
    };
  }
  return {
    check: {
      id,
      passed: false,
      severity: "warning",
      message: `${rule.mode} ${target || "(none)"} not on allowlist (warn only)`,
    },
    escalate: false,
  };
}

export function checkRateLimit(rule: RateLimitRule, ctx: RuleContext): RuleResult {
  const id = "rate-limit";
  const count = ctx.recentPaymentCount(rule.windowSeconds) + 1; // include current
  if (count > rule.maxPayments) {
    return {
      check: {
        id,
        passed: false,
        severity: "critical",
        message: `${count} payments in ${rule.windowSeconds}s exceeds limit ${rule.maxPayments}`,
      },
      escalate: false,
    };
  }
  return pass(id, `${count}/${rule.maxPayments} payments in ${rule.windowSeconds}s window`);
}

export function checkCounterparty(rule: CounterpartyRule, ctx: RuleContext): RuleResult {
  const id = "counterparty-new";
  if (!rule.flagNewRecipients) return { check: null, escalate: false };
  if (!ctx.isNewCounterparty(ctx.req.recipient)) {
    return pass(id, "known counterparty");
  }
  return {
    check: {
      id,
      passed: false,
      severity: rule.action === "block" ? "critical" : "warning",
      message: `first payment ever to ${ctx.req.recipient.slice(0, 10)}…`,
    },
    escalate: rule.action === "escalate",
  };
}

export function checkTimeWindow(rule: TimeWindowRule, ctx: RuleContext): RuleResult {
  const id = "time-window";
  const hour = new Date(ctx.now).getUTCHours();
  const [start, end] = rule.allowedHours;
  // Support windows that wrap past midnight (e.g. [22, 6]); start === end means
  // "no restriction" (24h) rather than a collapsed, always-blocking window.
  const inWindow =
    start === end ? true : start < end ? hour >= start && hour < end : hour >= start || hour < end;
  if (inWindow) {
    return pass(id, `${hour}:00 UTC within allowed ${start}-${end}`);
  }
  return {
    check: {
      id,
      passed: false,
      severity: rule.action === "block" ? "critical" : "warning",
      message: `${hour}:00 UTC outside allowed window ${start}-${end}`,
    },
    escalate: rule.action === "escalate",
  };
}
