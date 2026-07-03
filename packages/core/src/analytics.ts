import type { AuditEntry } from "./types.js";

export interface CounterpartyStat {
  recipient: string;
  count: number;
  /** Settled spend to this recipient, in token units (as a string). */
  totalSpend: string;
}

export interface AnalyticsReport {
  total: number;
  verdicts: { allow: number; block: number; escalate: number };
  /** Payments that actually settled. */
  settled: number;
  /** Settled spend per token address, in token units (as a string). */
  totalSpendByToken: Record<string, string>;
  /** Top recipients by settled spend. */
  topCounterparties: CounterpartyStat[];
  /** Payments that fired a behavioral anomaly check. */
  anomalies: number;
  blockRate: number;
  escalateRate: number;
  firstTimestamp?: number;
  lastTimestamp?: number;
}

/** Aggregate an audit log into spending + risk analytics for an operator. */
export function report(entries: AuditEntry[], opts: { topN?: number } = {}): AnalyticsReport {
  const topN = opts.topN ?? 5;
  const verdicts = { allow: 0, block: 0, escalate: 0 };
  const spendByToken = new Map<string, bigint>();
  const counterparties = new Map<string, { count: number; spend: bigint }>();
  let settled = 0;
  let anomalies = 0;
  let first: number | undefined;
  let last: number | undefined;

  for (const e of entries) {
    verdicts[e.decision.verdict]++;
    if (e.decision.checks.some((c) => !c.passed && c.id.startsWith("behavioral-"))) anomalies++;
    first = first === undefined ? e.timestamp : Math.min(first, e.timestamp);
    last = last === undefined ? e.timestamp : Math.max(last, e.timestamp);

    if (e.settlement?.success) {
      settled++;
      const token = e.request.token.toLowerCase();
      spendByToken.set(token, (spendByToken.get(token) ?? 0n) + e.request.amount);
      const key = e.request.recipient.toLowerCase();
      const cp = counterparties.get(key) ?? { count: 0, spend: 0n };
      cp.count++;
      cp.spend += e.request.amount;
      counterparties.set(key, cp);
    }
  }

  const topCounterparties = [...counterparties.entries()]
    .map(([recipient, s]) => ({ recipient, count: s.count, totalSpend: s.spend.toString() }))
    .sort((a, b) => {
      const d = BigInt(b.totalSpend) - BigInt(a.totalSpend);
      return d > 0n ? 1 : d < 0n ? -1 : 0;
    })
    .slice(0, topN);

  const total = entries.length;
  return {
    total,
    verdicts,
    settled,
    totalSpendByToken: Object.fromEntries([...spendByToken].map(([k, v]) => [k, v.toString()])),
    topCounterparties,
    anomalies,
    blockRate: total ? verdicts.block / total : 0,
    escalateRate: total ? verdicts.escalate / total : 0,
    firstTimestamp: first,
    lastTimestamp: last,
  };
}
