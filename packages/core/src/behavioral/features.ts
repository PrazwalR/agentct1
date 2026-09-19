import type { PaymentRequest } from "../types.js";
import type { EWMABaseline } from "./baseline.js";

export interface Features {
  /** Payment amount in smallest token units, as a number for scoring. */
  amount: number;
  /** Seconds since this agent's previous payment (0 if first). */
  secondsSinceLast: number;
  /** UTC hour of day (0-23). */
  hourOfDay: number;
  /** Whether this recipient has never been paid before. */
  isNewCounterparty: boolean;
  /** Numeric feature vector for the Isolation Forest. */
  vector: number[];
}

/**
 * Extract scoring features for a payment relative to the agent's baseline.
 *
 * `now` is injectable so historical entries can be replayed at their real
 * timestamps when rehydrating from the audit log — replaying with Date.now()
 * would collapse every interval to ~0 and poison the frequency baseline.
 */
export function extractFeatures(
  req: PaymentRequest,
  baseline: EWMABaseline,
  now = Date.now(),
): Features {
  const last = baseline.lastTimestamp();
  const secondsSinceLast = last !== undefined ? (now - last) / 1000 : 0;
  const hourOfDay = new Date(now).getUTCHours();
  const amount = Number(req.amount);
  const isNewCounterparty = baseline.isNewCounterparty(req.recipient);

  return {
    amount,
    secondsSinceLast,
    hourOfDay,
    isNewCounterparty,
    vector: [amount, secondsSinceLast, hourOfDay, isNewCounterparty ? 1 : 0],
  };
}
