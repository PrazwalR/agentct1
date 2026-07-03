import type { AuditEntry, PaymentRequest, Policy, PolicyCheck, Verdict } from "../types.js";
import { PolicyEvaluator } from "./evaluator.js";

export interface SimulationEntry {
  request: PaymentRequest;
  recordedVerdict: Verdict;
  simulatedVerdict: Verdict;
  changed: boolean;
}

export interface SimulationResult {
  total: number;
  changed: number;
  /** Would be blocked under the candidate but wasn't originally. */
  newlyBlocked: number;
  /** Would be escalated under the candidate but was originally allowed. */
  newlyEscalated: number;
  /** Would be allowed under the candidate but was originally blocked/escalated. */
  newlyAllowed: number;
  entries: SimulationEntry[];
}

/** Rule-only verdict (behavioral/intent are stochastic and excluded from a backtest). */
function ruleVerdict(checks: PolicyCheck[], escalate: boolean): Verdict {
  if (checks.some((c) => !c.passed && c.severity === "critical")) return "block";
  if (escalate) return "escalate";
  return "allow";
}

/**
 * Backtest a candidate policy against recorded history: replay every past payment
 * (in order, advancing spend windows / counterparty memory for the ones that
 * actually settled) and diff the candidate's rule verdict against what was
 * recorded. Lets an operator see exactly what a policy change would have done
 * before deploying it.
 *
 * Scope: the deterministic policy-rule layer. Behavioral anomaly scoring and the
 * LLM intent check are non-deterministic and are not replayed.
 */
export async function simulatePolicy(
  history: AuditEntry[],
  candidate: Policy,
): Promise<SimulationResult> {
  const evaluator = new PolicyEvaluator(candidate);
  const sorted = [...history].sort((a, b) => a.timestamp - b.timestamp);

  const entries: SimulationEntry[] = [];
  let newlyBlocked = 0;
  let newlyEscalated = 0;
  let newlyAllowed = 0;

  for (const e of sorted) {
    const { checks, escalate } = await evaluator.evaluate(e.request);
    const simulatedVerdict = ruleVerdict(checks, escalate);
    const recordedVerdict = e.decision.verdict;
    const changed = simulatedVerdict !== recordedVerdict;

    if (changed) {
      if (simulatedVerdict === "block") newlyBlocked++;
      else if (simulatedVerdict === "escalate" && recordedVerdict === "allow") newlyEscalated++;
      else if (simulatedVerdict === "allow") newlyAllowed++;
    }

    entries.push({ request: e.request, recordedVerdict, simulatedVerdict, changed });

    // Advance evaluator state with payments that actually happened.
    if (e.settlement?.success || recordedVerdict === "allow") evaluator.observe(e.request);
  }

  return {
    total: sorted.length,
    changed: entries.filter((x) => x.changed).length,
    newlyBlocked,
    newlyEscalated,
    newlyAllowed,
    entries,
  };
}
