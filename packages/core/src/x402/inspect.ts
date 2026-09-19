import { isEIP3009Payload, isPermit2Payload, type ExactEvmPayloadV2 } from "@x402/evm";
import type { PaymentRequest } from "../types.js";

/**
 * Thrown when a signed payment payload authorizes something other than what the
 * policy engine approved. Fail-closed: the payment must not reach the facilitator.
 */
export class AuthorizationMismatchError extends Error {
  constructor(readonly mismatches: string[]) {
    super(`signed authorization does not match the approved decision: ${mismatches.join("; ")}`);
    this.name = "AuthorizationMismatchError";
  }
}

const eq = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/**
 * Assert that what was actually SIGNED matches what the guard approved.
 *
 * The policy layers decide on a `PaymentRequest`, but the signing happens inside
 * the x402 client afterwards. Without this check the decision and the signature
 * are only assumed to agree — a scheme bug, a tampered `PaymentRequirements`, or a
 * mismatched selection would settle a payment the guard never approved. This is
 * what makes "recipient-bound and amount-bound" an enforced property rather than
 * a documented one.
 *
 * Throws {@link AuthorizationMismatchError} on any discrepancy. An unrecognized
 * payload shape is NOT an error here — non-EVM schemes (Solana) carry their own
 * payload format and are verified by their own scheme.
 */
export function assertAuthorizationMatches(
  payload: Record<string, unknown>,
  req: PaymentRequest,
): void {
  const p = payload as unknown as ExactEvmPayloadV2;
  const mismatches: string[] = [];

  if (isEIP3009Payload(p)) {
    const { to, value } = p.authorization;
    if (!eq(to, req.recipient)) mismatches.push(`recipient signed=${to} approved=${req.recipient}`);
    if (BigInt(value) !== req.amount) {
      mismatches.push(`amount signed=${value} approved=${req.amount}`);
    }
  } else if (isPermit2Payload(p)) {
    const { permitted, witness } = p.permit2Authorization;
    if (!eq(witness.to, req.recipient)) {
      mismatches.push(`recipient signed=${witness.to} approved=${req.recipient}`);
    }
    if (BigInt(permitted.amount) !== req.amount) {
      mismatches.push(`amount signed=${permitted.amount} approved=${req.amount}`);
    }
    if (!eq(permitted.token, req.token)) {
      mismatches.push(`token signed=${permitted.token} approved=${req.token}`);
    }
  } else {
    return; // not an EVM exact payload — nothing this function can assert
  }

  if (mismatches.length > 0) throw new AuthorizationMismatchError(mismatches);
}
